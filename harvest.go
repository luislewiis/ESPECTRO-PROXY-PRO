package main

// harvest.go — "Auto-Fuentes": recoleccion continua de proxies de fuentes
// publicas + auto-descubrimiento de fuentes nuevas (meta-harvesting).
//
// Reglas de oro:
//   - Escribe SIEMPRE en su propio archivo (default harvested.txt). NUNCA
//     toca proxies.txt ni las listas del usuario.
//   - Solo descarga http/https de hosts publicos (guarda SSRF: loopback,
//     privados y link-local quedan bloqueados).
//   - Deduplica contra el pool existente antes de escribir.
//   - Opcionalmente drena un health-check de los nuevos (check-connect) para
//     que /proxy.txt?alive=1 solo entregue proxies que TUNELIZAN de verdad.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	harvestMaxBytes     = 24 << 20 // tope por descarga (24 MB)
	harvestFetchTO      = 25 * time.Second
	harvestFetchWorkers = 24  // descargas simultaneas
	harvestCheckWorkers = 300 // health-checks simultaneos del drenaje
	harvestCheckBatch   = 3000
	harvestItvMin       = 15  // minutos entre pasadas (default)
	harvestDrainBudget  = 180 // segundos de drenaje por pasada
	harvestOutDefault   = "harvested.txt"
	harvestSrcFile      = "harvest_sources.json"
	harvestMaxSources   = 5000
	harvestMinDiscover  = 5 // lineas minimas para aceptar una fuente descubierta
	// harvestMaxLinesDefault: tope de lineas del archivo recolectado. El pool
	// gratis trae ~480k lineas (x2-3 por protocolo) que cuestan ~600 MB de
	// RAM; con 120k sobran miles de vivos. 0 = sin tope ("millones").
	harvestMaxLinesDefault = 120000
)

var (
	// harvestReIPPort extrae IP:PUERTO de cualquier cuerpo de texto.
	harvestReIPPort = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b`)
	// harvestReURL extrae URLs candidatas de los catalogos de fuentes.
	harvestReURL = regexp.MustCompile(`https?://[^\s"'<>()\[\]{},]+`)
)

// HarvestSource es una fuente remota de proxies (una URL de texto plano).
type HarvestSource struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Proto   string `json:"proto,omitempty"` // "" = inferir por nombre de URL
	Enabled bool   `json:"enabled"`
	Origin  string `json:"origin,omitempty"` // builtin | user | discovered
	AddedAt int64  `json:"added_at,omitempty"`
}

// harvestBuiltin: catalogo curado y verificado en vivo (todas responden 200
// y entregan IP:PUERTO). Cualquier fuente descubierta se suma a estas.
var harvestBuiltin = []HarvestSource{
	{Name: "thespeedx_http", URL: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", Proto: "http"},
	{Name: "thespeedx_socks4", URL: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", Proto: "socks4"},
	{Name: "thespeedx_socks5", URL: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", Proto: "socks5"},
	{Name: "monosans_http", URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", Proto: "http"},
	{Name: "monosans_socks4", URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", Proto: "socks4"},
	{Name: "monosans_socks5", URL: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", Proto: "socks5"},
	{Name: "hookzof_socks5", URL: "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", Proto: "socks5"},
	{Name: "proxifly_http", URL: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", Proto: "http"},
	{Name: "proxifly_socks4", URL: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt", Proto: "socks4"},
	{Name: "proxifly_socks5", URL: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", Proto: "socks5"},
	{Name: "proxifly_all", URL: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt", Proto: ""},
	{Name: "ercin_http", URL: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt", Proto: "http"},
	{Name: "ercin_socks4", URL: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt", Proto: "socks4"},
	{Name: "ercin_socks5", URL: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt", Proto: "socks5"},
	{Name: "murong_http", URL: "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt", Proto: "http"},
	{Name: "murong_socks4", URL: "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt", Proto: "socks4"},
	{Name: "murong_socks5", URL: "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt", Proto: "socks5"},
	{Name: "zevtyardt_http", URL: "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt", Proto: "http"},
	{Name: "zevtyardt_socks4", URL: "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt", Proto: "socks4"},
	{Name: "zevtyardt_socks5", URL: "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt", Proto: "socks5"},
	{Name: "aliilapro_http", URL: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt", Proto: "http"},
	{Name: "aliilapro_socks4", URL: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt", Proto: "socks4"},
	{Name: "aliilapro_socks5", URL: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt", Proto: "socks5"},
	{Name: "rdavydov_http", URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt", Proto: "http"},
	{Name: "rdavydov_socks4", URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt", Proto: "socks4"},
	{Name: "rdavydov_socks5", URL: "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt", Proto: "socks5"},
	{Name: "shiftytr_http", URL: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", Proto: "http"},
	{Name: "shiftytr_socks4", URL: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", Proto: "socks4"},
	{Name: "shiftytr_socks5", URL: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", Proto: "socks5"},
	{Name: "jetkai_http", URL: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", Proto: "http"},
	{Name: "jetkai_socks4", URL: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", Proto: "socks4"},
	{Name: "jetkai_socks5", URL: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", Proto: "socks5"},
	{Name: "mmpx12_http", URL: "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt", Proto: "http"},
	{Name: "mmpx12_socks4", URL: "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt", Proto: "socks4"},
	{Name: "mmpx12_socks5", URL: "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt", Proto: "socks5"},
	{Name: "zloiuser_http", URL: "https://raw.githubusercontent.com/Zloi-User/hideip.me/main/http.txt", Proto: "http"},
	{Name: "zloiuser_socks4", URL: "https://raw.githubusercontent.com/Zloi-User/hideip.me/main/socks4.txt", Proto: "socks4"},
	{Name: "zloiuser_socks5", URL: "https://raw.githubusercontent.com/Zloi-User/hideip.me/main/socks5.txt", Proto: "socks5"},
	{Name: "roosterkid_https", URL: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", Proto: "http"},
	{Name: "roosterkid_socks4", URL: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", Proto: "socks4"},
	{Name: "roosterkid_socks5", URL: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", Proto: "socks5"},
	{Name: "sunny9577_http", URL: "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", Proto: "http"},
	{Name: "clarketm_http", URL: "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", Proto: "http"},
	{Name: "databay_http", URL: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt", Proto: "http"},
	{Name: "databay_socks4", URL: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt", Proto: "socks4"},
	{Name: "databay_socks5", URL: "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt", Proto: "socks5"},
	{Name: "spys_http", URL: "https://spys.me/proxy.txt", Proto: "http"},
	{Name: "spys_socks", URL: "https://spys.me/socks.txt", Proto: "socks5"},
	{Name: "proxyscrape_http", URL: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text", Proto: "http"},
	{Name: "proxyscrape_socks4", URL: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks4&proxy_format=ipport&format=text", Proto: "socks4"},
	{Name: "proxyscrape_socks5", URL: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=ipport&format=text", Proto: "socks5"},
}

// harvestCatalogs: catalogos de OTROS scrapers. No son listas de proxies:
// son listas de FUENTES. De aqui sale el auto-descubrimiento (meta-harvesting).
var harvestCatalogs = []string{
	"https://raw.githubusercontent.com/monosans/proxy-scraper-checker/main/config.toml",
	"https://raw.githubusercontent.com/saschazesiger/Proxy-Grabber-and-Checker/master/Sources.txt",
	"https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/scripts/sources.txt",
	"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/README.md",
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/README.md",
	"https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/README.md",
}

// harvestStats es el informe que consume el panel (/harvest/status).
type harvestStats struct {
	Running      bool   `json:"running"`
	Sources      int    `json:"sources"`
	Enabled      int    `json:"enabled"`
	IntervalMin  int    `json:"interval_min"`
	OutFile      string `json:"out_file"`
	LastRun      int64  `json:"last_run"`
	LastDurMS    int64  `json:"last_dur_ms"`
	Raw          int    `json:"raw"`
	Unique       int    `json:"unique"`
	New          int    `json:"new"`
	Alive        int64  `json:"alive"`
	PoolAlive    int    `json:"pool_alive"`
	PoolTotal    int    `json:"pool_total"`
	GrandRaw     int64  `json:"grand_raw"`
	GrandNew     int64  `json:"grand_new"`
	SourcesOK    int    `json:"sources_ok"`
	SourcesFail  int    `json:"sources_fail"`
	Discovered   int    `json:"discovered"`
	LastDiscover int64  `json:"last_discover"`
	LastError    string `json:"last_error,omitempty"`
	GitHubSearch bool   `json:"github_search"` // GITHUB_TOKEN presente
}

// Harvester orquesta la recoleccion. Un unico dueño por App.
type Harvester struct {
	a      *App
	client *http.Client

	mu    sync.Mutex
	src   []HarvestSource
	out   string
	itv   time.Duration
	run   bool // pasada en curso
	stop  chan struct{}
	once  sync.Once
	stat  harvestStats
	gRaw  int64
	gNew  int64
	alive int64

	// maxLines: tope de lineas del archivo recolectado (0 = sin tope).
	maxLines int
	// deferFirst: no recolectar al arrancar (esperar al primer intervalo).
	deferFirst bool

	// allowLocal solo lo activan los tests (mirror local de una fuente):
	// permite hosts loopback/privados, que en produccion estan bloqueados.
	allowLocal bool

	// discoverCatalogs: catalogos de otros scrapers de donde se extraen
	// fuentes nuevas (default harvestCatalogs; los tests lo sustituyen).
	discoverCatalogs []string
}

func harvestBuiltinList() []HarvestSource {
	out := make([]HarvestSource, len(harvestBuiltin))
	copy(out, harvestBuiltin)
	for i := range out {
		out[i].Enabled = true
		out[i].Origin = "builtin"
	}
	return out
}

// newHarvester crea el recolector y registra su archivo de salida en la lista
// de archivos de la App (para que entre al pool desde el arranque).
func newHarvester(a *App, out string, itvMin int) *Harvester {
	if strings.TrimSpace(out) == "" {
		out = harvestOutDefault
	}
	if abs, err := filepath.Abs(out); err == nil {
		out = abs
	}
	if itvMin <= 0 {
		itvMin = harvestItvMin
	}
	h := &Harvester{
		a:                a,
		client:           &http.Client{Timeout: harvestFetchTO},
		out:              out,
		itv:              time.Duration(itvMin) * time.Minute,
		stop:             make(chan struct{}),
		stat:             harvestStats{OutFile: out, IntervalMin: itvMin},
		discoverCatalogs: append([]string(nil), harvestCatalogs...),
		maxLines:         harvestMaxLinesDefault,
	}
	h.src = h.loadSources()
	h.a.mu.Lock()
	found := false
	for _, f := range h.a.files {
		if f == out {
			found = true
		}
	}
	if !found {
		h.a.files = append(h.a.files, out)
	}
	h.a.mu.Unlock()
	return h
}

// ---------------------------------------------------------------------------
// Persistencia de fuentes
// ---------------------------------------------------------------------------

func (h *Harvester) sourcesPath() string {
	if dir := filepath.Dir(h.out); dir != "" && dir != "." {
		return filepath.Join(dir, harvestSrcFile)
	}
	if cwd, err := os.Getwd(); err == nil {
		return filepath.Join(cwd, harvestSrcFile)
	}
	return harvestSrcFile
}

// loadSources fusiona el catalogo builtin con lo guardado: manda lo guardado
// (enabled/proto), pero un builtin nuevo se agrega solo. Las descubiertas y
// las del usuario se conservan siempre.
func (h *Harvester) loadSources() []HarvestSource {
	saved := []HarvestSource{}
	if data, err := os.ReadFile(h.sourcesPath()); err == nil {
		_ = json.Unmarshal(data, &saved)
	}
	byURL := make(map[string]HarvestSource, len(saved))
	for _, s := range saved {
		if s.URL != "" {
			byURL[s.URL] = s
		}
	}
	out := make([]HarvestSource, 0, len(harvestBuiltin)+len(saved))
	seen := map[string]bool{}
	for _, b := range harvestBuiltinList() {
		if prev, ok := byURL[b.URL]; ok {
			b.Enabled = prev.Enabled
			if prev.Name != "" {
				b.Name = prev.Name
			}
			if prev.Proto != "" {
				b.Proto = prev.Proto
			}
		}
		seen[b.URL] = true
		out = append(out, b)
	}
	for _, s := range saved {
		if s.URL == "" || seen[s.URL] {
			continue
		}
		if s.Origin == "" {
			s.Origin = "user"
		}
		seen[s.URL] = true
		out = append(out, s)
	}
	return out
}

func (h *Harvester) saveSources() {
	h.mu.Lock()
	list := append([]HarvestSource(nil), h.src...)
	h.mu.Unlock()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	path := h.sourcesPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

// SetSource habilita/deshabilita o agrega una fuente del usuario.
func (h *Harvester) SetSource(s HarvestSource) error {
	s.URL = strings.TrimSpace(s.URL)
	if s.URL == "" {
		return fmt.Errorf("la URL es obligatoria")
	}
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("URL invalida (solo http/https)")
	}
	if !h.allowLocal && harvestBlockedHost(u.Hostname()) {
		return fmt.Errorf("host no permitido (privado o local)")
	}
	if s.Name == "" {
		s.Name = u.Host + u.Path
	}
	if s.Proto == "" {
		s.Proto = harvestProtoFromName(s.URL)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.src {
		if h.src[i].URL == s.URL {
			h.src[i].Name = s.Name
			h.src[i].Proto = s.Proto
			h.src[i].Enabled = s.Enabled
			return nil
		}
	}
	if len(h.src) >= harvestMaxSources {
		return fmt.Errorf("limite de fuentes alcanzado (%d)", harvestMaxSources)
	}
	if s.Origin == "" {
		s.Origin = "user"
	}
	s.AddedAt = time.Now().Unix()
	h.src = append(h.src, s)
	return nil
}

// RemoveSource borra una fuente por URL. Devuelve si existia.
func (h *Harvester) RemoveSource(rawurl string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.src {
		if h.src[i].URL == rawurl {
			h.src = append(h.src[:i], h.src[i+1:]...)
			return true
		}
	}
	return false
}

// ListSources devuelve una copia ordenada (builtins primero, luego por nombre).
func (h *Harvester) ListSources() []HarvestSource {
	h.mu.Lock()
	out := append([]HarvestSource(nil), h.src...)
	h.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ---------------------------------------------------------------------------
// Descarga segura (SSRF guard)
// ---------------------------------------------------------------------------

// harvestBlockedHost bloquea hosts privados/loopback/link-local. Si el DNS
// no resuelve, deja pasar: la descarga fallara sola (y no hay nada que
// proteger porque no hay destino).
func harvestBlockedHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return true
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// fetch descarga una URL con tope de tamano y timeout. Solo http/https.
func (h *Harvester) fetch(ctx context.Context, rawurl string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawurl))
	if err != nil {
		return "", fmt.Errorf("URL invalida")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("esquema no permitido (%s)", u.Scheme)
	}
	if !h.allowLocal && harvestBlockedHost(u.Hostname()) {
		return "", fmt.Errorf("host bloqueado (privado o local)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "ESPECTRO-PROXY-PRO/harvest")
	req.Header.Set("Accept", "text/plain, */*")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, harvestMaxBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---------------------------------------------------------------------------
// Extraccion
// ---------------------------------------------------------------------------

// harvestProtoFromName infiere el protocolo por el nombre de la URL.
func harvestProtoFromName(rawurl string) string {
	n := strings.ToLower(rawurl)
	switch {
	case strings.Contains(n, "socks5"):
		return "socks5"
	case strings.Contains(n, "socks4"):
		return "socks4"
	case strings.Contains(n, "socks"):
		return "socks5"
	case strings.Contains(n, "http"):
		return "http"
	}
	return "http"
}

// harvestUsableIP descarta IPs que no son proxies publicos utiles (privadas,
// loopback, link-local, CGNAT, documentacion, reservadas y 0.0.0.0/8).
func harvestUsableIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return true // IPv6 publica: se acepta
	}
	switch {
	case v4[0] == 0: // 0.0.0.0/8 ("this network"): basura tipica de las listas
		return false
	case v4[0] >= 240: // 240.0.0.0/4 reservado
		return false
	case v4[0] == 100 && v4[1]&0xc0 == 0x40: // 100.64.0.0/10 CGNAT
		return false
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
		return false
	case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19): // 198.18.0.0/15
		return false
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 2: // 192.0.2.0/24 (TEST-NET-1)
		return false
	case v4[0] == 198 && v4[1] == 51 && v4[2] == 100: // 198.51.100.0/24
		return false
	case v4[0] == 203 && v4[1] == 0 && v4[2] == 113: // 203.0.113.0/24
		return false
	}
	return true
}

// harvestExtract saca los IP:PUERTO unicos de un cuerpo y los convierte en
// Proxy con el protocolo dado (proto "" -> inferido por la URL).
func harvestExtract(body, proto string) map[string]*Proxy {
	out := make(map[string]*Proxy)
	for _, m := range harvestReIPPort.FindAllString(body, -1) {
		host, portStr, ok := strings.Cut(m, ":")
		if !ok {
			continue
		}
		ip := net.ParseIP(host)
		if !harvestUsableIP(ip) {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		p := &Proxy{Scheme: proto, Host: host, Port: port}
		if p.Scheme == "" {
			p.Scheme = "http"
		}
		out[p.Key()] = p
	}
	return out
}

// ---------------------------------------------------------------------------
// Pasada de recoleccion
// ---------------------------------------------------------------------------

type harvestSrcResult struct {
	name string
	raw  int
	uniq int
	err  error
}

// RunOnce recolecta todas las fuentes habilitadas, agrega solo lo nuevo al
// pool y (opcionalmente) drena un health-check de los recien llegados.
func (h *Harvester) RunOnce(ctx context.Context) error {
	h.mu.Lock()
	if h.run {
		h.mu.Unlock()
		return fmt.Errorf("ya hay una recoleccion en curso")
	}
	h.run = true
	enabled := make([]HarvestSource, 0, len(h.src))
	for _, s := range h.src {
		if s.Enabled {
			enabled = append(enabled, s)
		}
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.run = false
		h.mu.Unlock()
	}()

	start := time.Now()
	var rawTotal, uniqTotal int
	var okN, failN atomic.Int64
	lastErr := ""
	var errMu sync.Mutex

	// Presupuesto de lineas: cuantas caben aun en el archivo propio (tope).
	h.a.mu.Lock()
	tope := h.maxLines
	actuales := 0
	for _, p := range h.a.proxies {
		if p.File == h.out {
			actuales++
		}
	}
	h.a.mu.Unlock()
	presupuesto := -1
	if tope > 0 {
		presupuesto = tope - actuales
		if presupuesto < 0 {
			presupuesto = 0
		}
		if presupuesto == 0 {
			h.a.logf("auto-fuentes: tope alcanzado (%d lineas); se salta la recoleccion (usa --harvest-max-lines 0 para ilimitado, o purga los muertos)", tope)
		}
	}
	var capMu sync.Mutex

	found := make(map[string]*Proxy)
	var foundMu sync.Mutex
	sem := make(chan struct{}, harvestFetchWorkers)
	var wg sync.WaitGroup

	for _, s := range enabled {
		wg.Add(1)
		go func(s HarvestSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body, err := h.fetch(ctx, s.URL)
			if err != nil {
				failN.Add(1)
				errMu.Lock()
				if lastErr == "" {
					lastErr = fmt.Sprintf("%s: %v", s.Name, err)
				}
				errMu.Unlock()
				return
			}
			proto := s.Proto
			if proto == "" {
				proto = harvestProtoFromName(s.URL)
			}
			ps := harvestExtract(body, proto)
			rawN := len(harvestReIPPort.FindAllString(body, -1))
			okN.Add(1)
			foundMu.Lock()
			rawTotal += rawN
			uniqTotal += len(ps)
			for k, p := range ps {
				if presupuesto >= 0 {
					capMu.Lock()
					lleno := len(found) >= presupuesto
					capMu.Unlock()
					if lleno {
						break
					}
				}
				if _, dup := found[k]; !dup {
					found[k] = p
				}
			}
			foundMu.Unlock()
		}(s)
	}
	wg.Wait()

	// Dedupe contra el pool actual (LoadProxies mantiene el estado previo).
	h.a.mu.Lock()
	existing := make(map[string]bool, len(h.a.proxies))
	for _, p := range h.a.proxies {
		existing[p.Key()] = true
	}
	h.a.mu.Unlock()

	var fresh []*Proxy
	for k, p := range found {
		if !existing[k] {
			fresh = append(fresh, p)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Key() < fresh[j].Key() })

	newN := 0
	if len(fresh) > 0 {
		if err := h.appendNew(fresh); err != nil {
			lastErr = "guardando: " + err.Error()
		} else {
			newN = len(fresh)
			h.a.LoadProxies()
			// Politica "solo vivo y filtrado": lo recien recolectado entra al
			// pool como NO vivo y sin verificar. Asi OB nunca recibe basura
			// sin validar (LoadProxies los marca optimistas por diseno) y el
			// drenaje/health-check los promueve solo si TUNELIZAN de verdad.
			h.demoteFresh(fresh)
		}
	}

	// Drenaje: health-check de lo nuevo para que /proxy.txt?alive=1 valga.
	var aliveN int64
	if newN > 0 && h.a.harvestCheck {
		aliveN = h.drainCheck(ctx, time.Duration(harvestDrainBudget)*time.Second)
		h.a.scheduleStateSave()
	}

	dur := time.Since(start)
	h.mu.Lock()
	h.stat.LastRun = time.Now().Unix()
	h.stat.LastDurMS = dur.Milliseconds()
	h.stat.Raw = rawTotal
	h.stat.Unique = uniqTotal
	h.stat.New = newN
	h.stat.Alive = aliveN
	h.stat.SourcesOK = int(okN.Load())
	h.stat.SourcesFail = int(failN.Load())
	h.stat.LastError = lastErr
	h.gRaw += int64(rawTotal)
	h.gNew += int64(newN)
	h.alive += aliveN
	h.stat.GrandRaw = h.gRaw
	h.stat.GrandNew = h.gNew
	h.mu.Unlock()

	pa, pt := h.a.counts()
	h.mu.Lock()
	h.stat.PoolAlive, h.stat.PoolTotal = pa, pt
	h.mu.Unlock()
	h.a.logf("auto-fuentes: %d fuentes OK / %d fallidas, %d crudas -> %d unicas -> %d nuevas (%d vivos) en %s",
		okN.Load(), failN.Load(), rawTotal, uniqTotal, newN, aliveN, dur.Round(time.Millisecond))
	return nil
}

// demoteFresh marca como no-vivos y sin verificar los proxies recien
// agregados al pool (por Key), para que no lleguen a OB antes de validarse.
func (h *Harvester) demoteFresh(fresh []*Proxy) {
	if len(fresh) == 0 {
		return
	}
	keys := make(map[string]bool, len(fresh))
	for _, p := range fresh {
		keys[p.Key()] = true
	}
	h.a.mu.Lock()
	for _, p := range h.a.proxies {
		if keys[p.Key()] {
			p.Alive = false
			p.Checked = false
		}
	}
	h.a.aliveDirty = true
	h.a.mu.Unlock()
}

// appendNew escribe las lineas nuevas al archivo propio del harvester
// (nunca a proxies.txt ni a las listas del usuario).
func (h *Harvester) appendNew(list []*Proxy) error {
	if len(list) == 0 {
		return nil
	}
	if dir := filepath.Dir(h.out); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	f, err := os.OpenFile(h.out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<16)
	for _, p := range list {
		if _, err := w.WriteString(p.LineaCanon() + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// drainCheck valida (CONNECT/GET segun config) los proxies sin verificar,
// en lotes concurrentes, hasta agotar el presupuesto de tiempo.
func (h *Harvester) drainCheck(ctx context.Context, budget time.Duration) int64 {
	deadline := time.Now().Add(budget)
	timeout := h.a.checkTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	connect := h.a.checkConnect
	testURL := h.a.testURL
	var aliveN int64

	for time.Now().Before(deadline) && ctx.Err() == nil {
		h.a.mu.Lock()
		var cand []*Proxy
		for _, p := range h.a.proxies {
			if !p.Checked {
				cand = append(cand, p)
			}
		}
		h.a.mu.Unlock()
		if len(cand) == 0 {
			break
		}
		// Muestreo aleatorio: sin esto el drenaje validaria siempre el mismo
		// prefijo del pool (orden por Key) y el resto quedaria sin medir.
		rand.Shuffle(len(cand), func(i, j int) { cand[i], cand[j] = cand[j], cand[i] })
		batch := harvestCheckBatch
		if len(cand) < batch {
			batch = len(cand)
		}
		cand = cand[:batch]

		sem := make(chan struct{}, harvestCheckWorkers)
		var wg sync.WaitGroup
		var aliveBatch atomic.Int64
		for _, p := range cand {
			wg.Add(1)
			go func(p *Proxy) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				ok, ping := healthCheckFull(p, testURL, timeout, connect)
				h.a.mu.Lock()
				p.Checked = true
				p.LastCheck = time.Now().Unix()
				if ok {
					p.Alive = true
					p.PingMs = ping
					p.Fails = 0
					h.a.aliveDirty = true
					aliveBatch.Add(1)
				} else if p.Alive {
					p.Alive = false
					h.a.aliveDirty = true
				}
				h.a.mu.Unlock()
			}(p)
		}
		wg.Wait()
		aliveN += aliveBatch.Load()
		if len(cand) < harvestCheckBatch {
			break
		}
	}
	return aliveN
}

// Purge borra del archivo recolectado los proxies ya verificados como
// muertos (mantiene vivos y sin verificar). Devuelve cuantos se quitaron.
func (h *Harvester) Purge() (int, error) {
	h.a.mu.Lock()
	drop := make(map[string]bool)
	for _, p := range h.a.proxies {
		if p.File == h.out && p.Checked && !p.Alive {
			drop[p.Key()] = true
		}
	}
	h.a.mu.Unlock()
	if len(drop) == 0 {
		return 0, nil
	}
	data, err := os.ReadFile(h.out)
	if err != nil {
		return 0, err
	}
	removed := 0
	var keep []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimRight(line, "\r")
		if strings.TrimSpace(t) == "" {
			continue
		}
		p := ParseProxyDef(t, "")
		if p != nil && drop[p.Key()] {
			removed++
			continue
		}
		keep = append(keep, t)
	}
	if removed == 0 {
		return 0, nil
	}
	tmp := h.out + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), 0o644); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, h.out); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	h.a.LoadProxies()
	return removed, nil
}

// ---------------------------------------------------------------------------
// Auto-descubrimiento de fuentes (meta-harvesting)
// ---------------------------------------------------------------------------

// harvestLooksLikeList filtra candidatos: solo URLs que parecen listas de
// texto plano (no imagenes, no paginas .md/.toml del catalogo).
func harvestLooksLikeList(rawurl string) bool {
	n := strings.ToLower(rawurl)
	switch {
	case strings.HasSuffix(n, ".png"), strings.HasSuffix(n, ".jpg"), strings.HasSuffix(n, ".jpeg"),
		strings.HasSuffix(n, ".gif"), strings.HasSuffix(n, ".svg"), strings.HasSuffix(n, ".webp"),
		strings.HasSuffix(n, ".md"), strings.HasSuffix(n, ".toml"), strings.HasSuffix(n, ".yml"),
		strings.HasSuffix(n, ".yaml"), strings.HasSuffix(n, ".json"), strings.HasSuffix(n, ".html"):
		return false
	}
	if strings.HasSuffix(n, ".txt") || strings.HasSuffix(n, ".lst") || strings.HasSuffix(n, ".csv") {
		return true
	}
	return strings.Contains(n, "proxy") || strings.Contains(n, "socks") || strings.Contains(n, "/get?")
}

// Discover lee los catalogos de otros scrapers, extrae URLs candidatas, las
// prueba en vivo y agrega como fuente solo las que entregan proxies de verdad.
func (h *Harvester) Discover(ctx context.Context) (int, error) {
	cands := map[string]bool{}
	catalogs := append([]string(nil), h.discoverCatalogs...)
	for _, c := range catalogs {
		body, err := h.fetch(ctx, c)
		if err != nil {
			continue
		}
		for _, m := range harvestReURL.FindAllString(body, -1) {
			u := strings.TrimRight(m, ".,;:'\"")
			if harvestLooksLikeList(u) {
				cands[u] = true
			}
		}
	}
	for _, u := range h.githubCodeSearch(ctx) {
		if harvestLooksLikeList(u) {
			cands[u] = true
		}
	}

	h.mu.Lock()
	known := make(map[string]bool, len(h.src))
	for _, s := range h.src {
		known[s.URL] = true
	}
	h.mu.Unlock()

	var probes []string
	for u := range cands {
		if !known[u] {
			probes = append(probes, u)
		}
	}
	sort.Strings(probes)
	if len(probes) > 150 {
		probes = probes[:150]
	}

	added := 0
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, u := range probes {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body, err := h.fetch(ctx, u)
			if err != nil {
				return
			}
			if len(harvestReIPPort.FindAllString(body, -1)) < harvestMinDiscover {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			h.mu.Lock()
			full := len(h.src) >= harvestMaxSources
			h.mu.Unlock()
			if full {
				return
			}
			if err := h.SetSource(HarvestSource{
				Name:    harvestSourceName(u),
				URL:     u,
				Proto:   harvestProtoFromName(u),
				Enabled: true,
				Origin:  "discovered",
			}); err == nil {
				added++
			}
		}(u)
	}
	wg.Wait()

	if added > 0 {
		h.saveSources()
	}
	h.mu.Lock()
	h.stat.Discovered = added
	h.stat.LastDiscover = time.Now().Unix()
	h.mu.Unlock()
	h.a.logf("auto-fuentes: descubrimiento -> %d fuentes nuevas de %d candidatas", added, len(probes))
	return added, nil
}

func harvestSourceName(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	base := strings.TrimSuffix(filepath.Base(u.Path), filepath.Ext(u.Path))
	if base == "" || base == "/" {
		base = strings.ReplaceAll(u.Host, ".", "_")
	}
	host := strings.Split(u.Host, ":")[0]
	return host + "_" + base
}

// githubCodeSearch usa la API de busqueda de codigo de GitHub (opcional:
// requiere GITHUB_TOKEN/GH_TOKEN) para encontrar listas recien publicadas.
func (h *Harvester) githubCodeSearch(ctx context.Context) []string {
	tok := os.Getenv("GITHUB_TOKEN")
	if tok == "" {
		tok = os.Getenv("GH_TOKEN")
	}
	if tok == "" {
		return nil
	}
	queries := []string{
		"filename:socks5.txt",
		"filename:socks4.txt",
		"filename:http.txt+proxy",
		"filename:proxies.txt",
	}
	var out []string
	for _, q := range queries {
		u := "https://api.github.com/search/code?per_page=30&q=" + url.QueryEscape(q)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "ESPECTRO-PROXY-PRO/harvest")
		resp, err := h.client.Do(req)
		if err != nil {
			continue
		}
		var payload struct {
			Items []struct {
				HTMLURL string `json:"html_url"`
			} `json:"items"`
		}
		dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
		errDec := dec.Decode(&payload)
		resp.Body.Close()
		if errDec != nil {
			continue
		}
		for _, it := range payload.Items {
			if raw := githubBlobToRaw(it.HTMLURL); raw != "" {
				out = append(out, raw)
			}
		}
	}
	return out
}

// githubBlobToRaw convierte .../blob/<ref>/<path> en raw.githubusercontent.com.
func githubBlobToRaw(htmlURL string) string {
	if !strings.Contains(htmlURL, "github.com/") || !strings.Contains(htmlURL, "/blob/") {
		return ""
	}
	out := strings.Replace(htmlURL, "https://github.com/", "https://raw.githubusercontent.com/", 1)
	return strings.Replace(out, "/blob/", "/", 1)
}

// Stats devuelve el informe para el panel.
func (h *Harvester) Stats() harvestStats {
	h.mu.Lock()
	st := h.stat
	st.Sources = len(h.src)
	en := 0
	for _, s := range h.src {
		if s.Enabled {
			en++
		}
	}
	st.Enabled = en
	st.Running = h.run
	h.mu.Unlock()
	st.GitHubSearch = os.Getenv("GITHUB_TOKEN") != "" || os.Getenv("GH_TOKEN") != ""
	alive, total := h.a.counts()
	st.PoolAlive, st.PoolTotal = alive, total
	return st
}

// Loop ejecuta pasadas periodicas hasta Stop().
func (h *Harvester) Loop() {
	h.a.logf("auto-fuentes: activo (cada %s, salida %s)", h.itv, filepath.Base(h.out))
	// Primera pasada al arrancar (salvo --harvest-defer): tener proxies
	// frescos sin esperar al primer intervalo.
	if !h.deferFirst {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			_ = h.RunOnce(ctx)
		}()
	} else {
		h.a.logf("auto-fuentes: primera pasada diferida %s (--harvest-defer)", h.itv)
	}
	t := time.NewTicker(h.itv)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			_ = h.RunOnce(ctx)
			cancel()
		}
	}
}

// Stop detiene el loop periodico.
func (h *Harvester) Stop() {
	h.once.Do(func() { close(h.stop) })
}
