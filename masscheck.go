package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================ Checker Masivo ============================
// Motor de validacion masiva integrado (fusion EspectroProxy -> ESPECTRO
// PROXY PRO): listas o carpetas completas, cascada multi-protocolo con
// auto-deteccion (SOCKS5 -> SOCKS4 -> HTTP para lineas sin esquema), timeout dinamico,
// GeoIP por paises, Discord al terminar y export por protocolo/pais.
// El gateway y su health-check NO se tocan: este job usa su propia lista.

const (
	massMaxHits = 100000 // hits retenidos en memoria (export/panel)
	massMaxText = 20 << 20
	massBodyGeo = 64 << 10
)

type massItem struct {
	host     string
	port     int
	explicit string // "" = cascada; o esquema fijo detectado en la linea
	user     string
	pass     string
	plain    string // forma normal para export/dedup (user:pass@host:puerto)
}

type massHit struct {
	Line    string `json:"line"`
	Proto   string `json:"proto"`
	Ping    int    `json:"ping"`
	Anon    string `json:"anon"`
	Country string `json:"country"`
}

type massJob struct {
	judge     string
	country   string // filtro en minusculas ("" = sin filtro)
	geo       bool
	retries   int
	timeoutMs int
	threads   int
	source    string
	webhook   string // ruta webhook.txt (default)
	outBase   string // "Resultados" (tests lo sustituyen)

	mu          sync.Mutex
	running     bool
	done        bool
	cancelled   bool
	errMsg      string
	start       time.Time
	end         time.Time
	dir         string
	hits        []massHit
	hitsCapped  bool
	dynPing     int
	total       atomic.Int64
	tested      atomic.Int64
	nHTTP       atomic.Int64
	nS4         atomic.Int64
	nS5         atomic.Int64
	bad         atomic.Int64
	usedRetries atomic.Int64
	filtered    atomic.Int64
	removed     atomic.Int64 // vivos borrados a mano desde el panel

	cancelOnce sync.Once
	cancelCh   chan struct{}

	wmu   sync.Mutex
	bw    map[string]*bufio.Writer
	files map[string]*os.File
	cbw   map[string]*bufio.Writer
	cfile map[string]*os.File
}

type massStatusJSON struct {
	Running     bool    `json:"running"`
	Done        bool    `json:"done"`
	Cancelled   bool    `json:"cancelled"`
	Error       string  `json:"error,omitempty"`
	Source      string  `json:"source"`
	Total       int64   `json:"total"`
	Tested      int64   `json:"tested"`
	Pct         float64 `json:"pct"`
	HTTP        int64   `json:"http"`
	Socks4      int64   `json:"socks4"`
	Socks5      int64   `json:"socks5"`
	Alive       int64   `json:"alive"`
	Bad         int64   `json:"bad"`
	Retries     int64   `json:"retries"`
	Filtered    int64   `json:"filtered"`
	CPM         int64   `json:"cpm"`
	ETA         string  `json:"eta"`
	Judge       string  `json:"judge"`
	Country     string  `json:"country"`
	Geo         bool    `json:"geo"`
	RetriesCfg  int     `json:"retries_cfg"`
	TimeoutMs   int     `json:"timeout_ms"`
	DynamicPing int     `json:"dynamic_ping"`
	Threads     int     `json:"threads"`
	Start       string  `json:"start,omitempty"`
	End         string  `json:"end,omitempty"`
	OutDir      string  `json:"out_dir,omitempty"`
	Hits        int     `json:"hits"`
	HitsCapped  bool    `json:"hits_capped"`
	Removed     int64   `json:"removed"`
}

var massCountryRe = regexp.MustCompile(`"country":"([^"]+)"`)

// extractCountry lee el country del cuerpo del juez (ip-api.com u otro
// endpoint que devuelva JSON con "country":"..."). "" si no hay.
func extractCountry(body string) string {
	if m := massCountryRe.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

// normalizeCountryInput: diccionario fuzzy EN->ES estilo Espectro
// (usa "brazil" -> "brasil", ISO cortos -> nombre en espanol).
func normalizeCountryInput(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	dict := map[string]string{
		"brazil": "brasil", "br": "brasil",
		"united states": "estados unidos", "usa": "estados unidos", "us": "estados unidos",
		"spain": "españa", "es": "españa",
		"germany": "alemania", "de": "alemania",
		"france": "francia", "fr": "francia",
		"japan": "japón", "jp": "japón",
		"uk": "reino unido", "united kingdom": "reino unido", "england": "reino unido", "gb": "reino unido",
		"mexico": "méxico", "mx": "méxico",
		"colombia": "colombia", "co": "colombia",
		"argentina": "argentina", "ar": "argentina",
		"peru": "perú", "pe": "perú",
		"chile": "chile", "cl": "chile",
	}
	if v, ok := dict[input]; ok {
		return v
	}
	return input
}

// massJudge: juez efectivo del job. custom tiene prioridad (permite juez
// proprio con GeoIP en tests/usuarios avanzados); geo fuerza ip-api.com
// (mismo comportamiento que Espectro cuando geo/pais esta activo); si no,
// juez ofuscado aleatorio en base64 (evita baneos).
func massJudge(custom string, geo bool) string {
	if c := strings.TrimSpace(custom); c != "" {
		return c
	}
	if geo {
		return "http://ip-api.com/json?lang=es"
	}
	judgesB64 := []string{
		"aHR0cDovL2F6ZW52Lm5ldC8=",     // http://azenv.net/
		"aHR0cDovL2h0dHBiaW4ub3JnL2lw", // http://httpbin.org/ip
		"aHR0cDovL2lmY29uZmlnLm1lL2lw", // http://ifconfig.me/ip
	}
	dec, _ := base64.StdEncoding.DecodeString(judgesB64[rand.Intn(len(judgesB64))])
	return string(dec)
}

// dynamicTimeout: ping al juez y timeout estilo Espectro (2.5s red rapida,
// 4s media, 6s lenta; 5s si el juez no responde).
func dynamicTimeout(judge string) (int, int) {
	start := time.Now()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(judge)
	if err != nil {
		return 999, 5000
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	ping := int(time.Since(start).Milliseconds())
	switch {
	case ping < 150:
		return ping, 2500
	case ping < 400:
		return ping, 4000
	default:
		return ping, 6000
	}
}

// anonLevel clasifica el anonimato leyendo el cuerpo del juez (logica
// azenv/Espectro: REQUEST_METHOD/HTTP_* indican que el juez ve el request).
func anonLevel(scheme, body string) string {
	if strings.Contains(body, "REQUEST_METHOD") || strings.Contains(body, "HTTP_") ||
		strings.Contains(body, "REMOTE_ADDR") {
		if !strings.Contains(body, "HTTP_X_FORWARDED_FOR") && !strings.Contains(body, "HTTP_VIA") {
			return "Elite"
		}
		if !strings.Contains(body, "HTTP_X_FORWARDED_FOR") {
			return "Anonymous"
		}
		return "Transparent"
	}
	if scheme == "http" {
		return "Unknown"
	}
	return "Elite"
}

// parseMassLine convierte una linea en massItem. Lineas con esquema
// explicito (socks5://, 0:tipo:hp, tipo:hp...) respetan ese protocolo;
// las lineas bare (ip:puerto) van en cascada.
func parseMassLine(raw string) *massItem {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "\uFEFF")
	if s == "" || strings.HasPrefix(s, "#") {
		return nil
	}
	mk := func(explicit, host string, port int, user, pass string) *massItem {
		plain := net_JoinHostPortStr(host, port)
		if user != "" {
			if pass != "" {
				plain = user + ":" + pass + "@" + plain
			} else {
				plain = user + "@" + plain
			}
		}
		return &massItem{host: host, port: port, explicit: explicit, user: user, pass: pass, plain: plain}
	}
	// con esquema explicito: url://... o tipo:hp... (OB 0:.. 1:.. 2:..)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil
		}
		scheme, ok := typeMap[strings.ToLower(u.Scheme)]
		if !ok {
			return nil
		}
		host := u.Hostname()
		if host == "" {
			return nil
		}
		port := 0
		if ps := u.Port(); ps != "" {
			port, err = strconv.Atoi(ps)
			if err != nil || port < 1 || port > 65535 {
				return nil
			}
		} else if strings.HasPrefix(scheme, "socks") {
			port = 1080
		} else {
			port = 8080
		}
		user, pass := "", ""
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		return mk(scheme, host, port, user, pass)
	}
	parts := strings.Split(s, ":")
	if len(parts) >= 3 {
		if scheme, ok := typeMap[strings.ToLower(parts[0])]; ok {
			host := parts[1]
			port, err := strconv.Atoi(parts[2])
			if err != nil || host == "" || port < 1 || port > 65535 {
				return nil
			}
			user := ""
			if len(parts) > 3 {
				user = parts[3]
			}
			pass := ""
			if len(parts) > 4 {
				pass = parts[4]
			}
			return mk(scheme, host, port, user, pass)
		}
	}
	// bare: cascada multi-protocolo
	p := ParseProxyDef(s, "")
	if p == nil {
		return nil
	}
	return mk("", p.Host, p.Port, p.User, p.Password)
}

func net_JoinHostPortStr(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// massProbe intenta el proxy contra el juez. Si la linea tenia esquema
// explicito prueba solo ese; si no, cascada SOCKS5 -> SOCKS4 -> HTTP.
// Devuelve protocolo vivo ("" = muerto), ping, pais (si geo) y anonimato.
func massProbe(it *massItem, judge string, timeout time.Duration, geo bool) (string, int, string, string) {
	schemes := []string{"socks5", "socks4", "http"}
	if it.explicit != "" {
		schemes = []string{it.explicit}
	}
	maxBody := 0
	if geo {
		maxBody = massBodyGeo
	}
	for _, s := range schemes {
		tp := &Proxy{Scheme: s, Host: it.host, Port: it.port, User: it.user, Password: it.pass}
		ok, ping, body := healthCheckBody(tp, judge, timeout, maxBody)
		if ok {
			country := ""
			if geo {
				country = extractCountry(body)
			}
			return s, ping, country, anonLevel(s, body)
		}
	}
	return "", 0, "", ""
}

// ============================ ciclo de vida ============================

type massCfg struct {
	path, text, name string
	judge            string
	country          string
	geo              bool
	retries          int
	timeoutMs        int // 0 = timeout dinamico
	threads          int // 0 = autopilot NumCPU*250 (cap 4000)
	skipLocal        bool
}

// massStart valida la fuente, crea el job y lanza el run en background.
// Devuelve error si ya hay un job corriendo o la fuente no es valida.
func (a *App) massStart(cfg massCfg) (*massJob, error) {
	src := ""
	if cfg.path != "" {
		if !importExts[strings.ToLower(filepath.Ext(cfg.path))] {
			if fi, err := os.Stat(cfg.path); err != nil || !fi.IsDir() {
				return nil, fmt.Errorf("ruta invalida: usa un archivo .txt/.lst/.csv o una carpeta")
			}
		}
		if !a.allowAnyPath && !a.rutaPermitida(cfg.path) {
			return nil, fmt.Errorf("acceso denegado: la ruta esta fuera de los directorios permitidos")
		}
		if _, err := os.Stat(cfg.path); err != nil {
			return nil, fmt.Errorf("no se pudo leer la ruta: %v", err)
		}
		src = cfg.path
	} else if strings.TrimSpace(cfg.text) != "" {
		if len(cfg.text) > massMaxText {
			return nil, fmt.Errorf("el texto supera los 20 MB")
		}
		src = "texto pegado"
	} else {
		return nil, fmt.Errorf("envia un archivo/carpeta (path) o listas pegadas (text)")
	}

	// Modo demo (sin espectro.lic Pro): tope de lineas por job. Se cuenta
	// ANTES de lanzar para devolver un error claro (mismas reglas que el
	// feed: sin comentarios/vacias, skipLocal y dedup).
	if !licPro() {
		if n := countCandidates(cfg); n > demoMaxLineas {
			return nil, fmt.Errorf("modo demo: la lista tiene %d proxies y el limite sin licencia es %d por job (con licencia Pro es ilimitado)", n, demoMaxLineas)
		}
	}

	geo := cfg.geo || strings.TrimSpace(cfg.country) != ""
	judge := massJudge(cfg.judge, geo)
	timeoutMs := cfg.timeoutMs
	dynPing := 0
	if timeoutMs <= 0 {
		dynPing, timeoutMs = dynamicTimeout(judge)
	}
	threads := cfg.threads
	if threads <= 0 {
		threads = runtime.NumCPU() * 250
	}
	// cap de hilos: 15000 permitsia un auto-DoS desde el panel (goteo de
	// FDs y CPU); 4000 sigue siendo un techo comodo para listas grandes.
	if threads > 4000 {
		threads = 4000
	}
	if threads < 1 {
		threads = 1
	}
	retries := cfg.retries
	if retries < 0 {
		retries = 0
	}
	if retries > 5 {
		retries = 5
	}

	j := &massJob{
		judge:     judge,
		country:   strings.ToLower(strings.TrimSpace(cfg.country)),
		geo:       geo,
		retries:   retries,
		timeoutMs: timeoutMs,
		threads:   threads,
		source:    src,
		webhook:   "webhook.txt",
		outBase:   a.outBaseDir(),
		start:     time.Now(),
		running:   true,
		cancelCh:  make(chan struct{}),
		dynPing:   dynPing,
	}
	// chequeo y alta en UNA sola seccion critica: con el patron
	// check-then-act dos /checker/start concurrentes pasaban ambos el
	// filtro y creaban 2 jobs (el primero quedaba huérfano e incontrolable)
	a.massMu.Lock()
	if a.mass != nil && a.mass.isRunning() {
		a.massMu.Unlock()
		return nil, fmt.Errorf("ya hay un checker masivo en curso (cancelalo primero)")
	}
	a.mass = j
	a.massMu.Unlock()
	a.logf("checker masivo iniciado: fuente=%s threads=%d timeout=%dms reintentos=%d geo=%v pais=%q",
		src, threads, timeoutMs, retries, geo, cfg.country)
	go a.massRun(j, cfg)
	return j, nil
}

func (j *massJob) isRunning() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.running
}

func (j *massJob) cancel() bool {
	j.mu.Lock()
	if !j.running {
		j.mu.Unlock()
		return false
	}
	j.cancelled = true
	j.mu.Unlock()
	j.cancelOnce.Do(func() { close(j.cancelCh) })
	return true
}

func (j *massJob) isDone() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done
}

// massShutdown: salvavidas de cierre (herencia EspectroProxy "Ctrl+C guarda
// vivos + Report.json"). Cancela el checker en curso y espera a que finish()
// vuelque los buffers, cierre los ficheros y escriba Report.json antes de
// que el proceso salga. Devuelve false si no llego a guardarse en el tiempo.
func (a *App) massShutdown(timeout time.Duration) bool {
	j := a.massCurrent()
	if j == nil || !j.isRunning() {
		return true
	}
	j.cancel()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if j.isDone() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return j.isDone()
}

// massRun: feeder (archivo/carpeta/texto) + workers autopilot + finish.
func (a *App) massRun(j *massJob, cfg massCfg) {
	if err := j.prepareOut(); err != nil {
		j.fail(err)
		return
	}
	ch := make(chan *massItem, j.threads*2)
	go func() {
		a.massFeed(j, cfg, ch)
	}()
	var wg sync.WaitGroup
	for i := 0; i < j.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				if j.isCancelled() {
					return
				}
				a.massCheckOne(j, it)
			}
		}()
	}
	wg.Wait()
	j.finish(a)
}

func (j *massJob) isCancelled() bool {
	select {
	case <-j.cancelCh:
		return true
	default:
		return false
	}
}

// massFeed emite items deduplicados al canal y lo cierra al terminar
// (o al cancelar).
func (a *App) massFeed(j *massJob, cfg massCfg, ch chan<- *massItem) {
	defer close(ch)
	seen := make(map[string]bool)
	emit := func(raw string) bool {
		if j.isCancelled() {
			return false
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			return true
		}
		if cfg.skipLocal && isLocalLine(line) {
			return true
		}
		it := parseMassLine(line)
		if it == nil {
			return true
		}
		if seen[it.plain] {
			return true
		}
		seen[it.plain] = true
		j.total.Add(1)
		select {
		case ch <- it:
			return true
		case <-j.cancelCh:
			return false
		}
	}
	scan := func(path string) bool {
		f, err := os.Open(path)
		if err != nil {
			return true
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
		for sc.Scan() {
			if !emit(sc.Text()) {
				return false
			}
		}
		return true
	}
	if cfg.text != "" {
		for _, line := range strings.Split(strings.ReplaceAll(cfg.text, "\r\n", "\n"), "\n") {
			if !emit(line) {
				return
			}
		}
		return
	}
	fi, err := os.Stat(cfg.path)
	if err != nil {
		return
	}
	if !fi.IsDir() {
		scan(cfg.path)
		return
	}
	filepath.Walk(cfg.path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".txt" && ext != ".lst" && ext != ".csv" {
			return nil
		}
		if !scan(p) {
			return filepath.SkipDir
		}
		return nil
	})
}

// isLocalLine filtra privados/loopback (mismo filtro que Espectro).
func isLocalLine(s string) bool {
	return strings.HasPrefix(s, "127.") || strings.HasPrefix(s, "192.168.") ||
		strings.HasPrefix(s, "10.") || strings.HasPrefix(s, "localhost")
}

// massCheckOne: cascada + reintentos + filtro de pais + guardar hit.
func (a *App) massCheckOne(j *massJob, it *massItem) {
	timeout := time.Duration(j.timeoutMs) * time.Millisecond
	var proto, country, anon string
	ping := 0
	for attempt := 0; attempt <= j.retries; attempt++ {
		proto, ping, country, anon = massProbe(it, j.judge, timeout, j.geo)
		if proto != "" {
			break
		}
		if attempt < j.retries {
			j.usedRetries.Add(1)
		}
	}
	if proto == "" {
		j.bad.Add(1)
		j.tested.Add(1)
		return
	}
	if j.country != "" && !strings.EqualFold(country, j.country) {
		// descarte silencioso estilo Espectro: no suma vivos ni muertos
		j.filtered.Add(1)
		j.tested.Add(1)
		return
	}
	switch proto {
	case "http":
		j.nHTTP.Add(1)
	case "socks4", "socks4a":
		j.nS4.Add(1)
	case "socks5":
		j.nS5.Add(1)
	}
	j.addHit(massHit{Line: it.plain, Proto: proto, Ping: ping, Anon: anon, Country: country})
	j.tested.Add(1)
}

// addHit: guarda en memoria (cap) y escribe en los writers del job.
func (j *massJob) addHit(h massHit) {
	j.mu.Lock()
	if len(j.hits) < massMaxHits {
		j.hits = append(j.hits, h)
	} else {
		j.hitsCapped = true
	}
	j.mu.Unlock()

	full := fmt.Sprintf("%-21s | %-5s | %4dms | %s | %s", h.Line,
		strings.ToUpper(h.Proto), h.Ping, h.Anon, h.Country)
	j.wmu.Lock()
	defer j.wmu.Unlock()
	if bw := j.bw[h.Proto]; bw != nil {
		bw.WriteString(full)
		bw.WriteString("\n")
	}
	if j.geo && h.Country != "" && h.Country != "Desconocido" {
		safe := strings.ReplaceAll(h.Country, "/", "_")
		bw, ok := j.cbw[safe]
		if !ok {
			if j.cfile == nil {
				j.cfile = map[string]*os.File{}
				j.cbw = map[string]*bufio.Writer{}
			}
			paisDir := filepath.Join(j.dir, "Paises Validados")
			os.MkdirAll(paisDir, 0755)
			f, err := os.OpenFile(filepath.Join(paisDir, safe+".txt"),
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				bw = bufio.NewWriter(f)
				j.cbw[safe] = bw
				j.cfile[safe] = f
			}
		}
		if bw != nil {
			bw.WriteString(full)
			bw.WriteString("\n")
		}
	}
}

// prepareOut crea la carpeta de sesion estilo Espectro y abre los
// Live_HTTP/SOCKS4/SOCKS5.txt.
func (j *massJob) prepareOut() error {
	now := j.start
	dir := filepath.Join(j.outBase, fmt.Sprintf("[%02d.%02d.%02d] [%02d.%02d.%02d]",
		now.Day(), now.Month(), now.Year()%100, now.Hour(), now.Minute(), now.Second()))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	j.mu.Lock()
	j.dir = dir
	j.mu.Unlock()
	j.files = map[string]*os.File{}
	j.bw = map[string]*bufio.Writer{}
	for _, proto := range []string{"http", "socks4", "socks5"} {
		f, err := os.OpenFile(filepath.Join(dir, "Live_"+strings.ToUpper(proto)+".txt"),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			// cierra los ya abiertos: si no, fallar a mitad dejaria FDs
			// colgados hasta salir del proceso (el job termina igual)
			for _, of := range j.files {
				of.Close()
			}
			j.files = map[string]*os.File{}
			j.bw = map[string]*bufio.Writer{}
			return err
		}
		j.files[proto] = f
		j.bw[proto] = bufio.NewWriter(f)
	}
	return nil
}

func (j *massJob) fail(err error) {
	j.mu.Lock()
	j.running = false
	j.done = true
	j.end = time.Now()
	j.errMsg = err.Error()
	j.mu.Unlock()
}

// finish: flush, cierre, Report.json, Discord y log de resumen.
func (j *massJob) finish(a *App) {
	j.wmu.Lock()
	for _, bw := range j.bw {
		bw.Flush()
	}
	for _, bw := range j.cbw {
		bw.Flush()
	}
	for _, f := range j.files {
		f.Close()
	}
	for _, f := range j.cfile {
		f.Close()
	}
	j.wmu.Unlock()

	j.writeReport()
	j.notifyDiscord()

	j.mu.Lock()
	j.running = false
	j.done = true
	j.end = time.Now()
	cancelled := j.cancelled
	errMsg := j.errMsg
	j.mu.Unlock()

	if errMsg != "" {
		a.logf("checker masivo con error: %s", errMsg)
		return
	}
	total := j.tested.Load()
	alive := j.nHTTP.Load() + j.nS4.Load() + j.nS5.Load()
	msg := fmt.Sprintf("checker masivo %s: evaluados %d, vivos %d (http %d, socks4 %d, socks5 %d), muertos %d",
		map[bool]string{true: "cancelado", false: "finalizado"}[cancelled],
		total, alive, j.nHTTP.Load(), j.nS4.Load(), j.nS5.Load(), j.bad.Load())
	if n := j.filtered.Load(); n > 0 {
		msg += fmt.Sprintf(", filtrados por pais %d", n)
	}
	a.logf("%s", msg)
}

func (j *massJob) reportBytes() []byte {
	tested := j.tested.Load()
	elapsed := time.Since(j.start).Minutes()
	cpm := int64(0)
	if elapsed > 0 {
		cpm = int64(float64(tested) / elapsed)
	}
	j.mu.Lock()
	report := map[string]interface{}{
		"TotalEvaluados": tested,
		"Vivos": map[string]int64{
			"HTTP": j.nHTTP.Load(), "SOCKS4": j.nS4.Load(), "SOCKS5": j.nS5.Load(),
			"Total": j.nHTTP.Load() + j.nS4.Load() + j.nS5.Load(),
		},
		"Muertos":   j.bad.Load(),
		"CPM":       cpm,
		"Fecha":     time.Now().Format("2006-01-02 15:04:05"),
		"Juez":      j.judge,
		"Filtrados": j.filtered.Load(),
		"Cancelado": j.cancelled,
		"Fuente":    j.source,
	}
	j.mu.Unlock()
	b, _ := json.MarshalIndent(report, "", "  ")
	return b
}

func (j *massJob) writeReport() {
	j.mu.Lock()
	dir := j.dir
	j.mu.Unlock()
	if dir == "" {
		return
	}
	os.WriteFile(filepath.Join(dir, "Report.json"), j.reportBytes(), 0644)
}

// notifyDiscord: webhook.txt en el cwd (herencia Espectro). Silencioso.
// Requiere licencia Pro (notificacion remota = funcion comercial).
func (j *massJob) notifyDiscord() {
	if !licPro() || j.webhook == "" {
		return
	}
	b, err := os.ReadFile(j.webhook)
	if err != nil {
		return
	}
	u := strings.TrimSpace(string(b))
	if u == "" || !strings.HasPrefix(u, "http") {
		return
	}
	alive := j.nHTTP.Load() + j.nS4.Load() + j.nS5.Load()
	msg := fmt.Sprintf("✅ **ESPECTRO PROXY PRO Checker terminado**\nEvaluados: %d\nVivos: %d\nMuertos: %d",
		j.tested.Load(), alive, j.bad.Load())
	sendDiscord(u, msg)
}

func sendDiscord(webhookURL, msg string) error {
	payload, _ := json.Marshal(map[string]string{"content": msg})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ============================ snapshots ============================

func (a *App) massCurrent() *massJob {
	a.massMu.Lock()
	defer a.massMu.Unlock()
	return a.mass
}

func (j *massJob) statusJSON() massStatusJSON {
	st := massStatusJSON{
		Judge:       j.judge,
		Country:     j.country,
		Geo:         j.geo,
		RetriesCfg:  j.retries,
		TimeoutMs:   j.timeoutMs,
		DynamicPing: j.dynPing,
		Threads:     j.threads,
	}
	j.mu.Lock()
	st.Running = j.running
	st.Done = j.done
	st.Cancelled = j.cancelled
	st.Error = j.errMsg
	st.Source = j.source
	st.Start = j.start.Format("2006-01-02 15:04:05")
	if !j.end.IsZero() {
		st.End = j.end.Format("2006-01-02 15:04:05")
	}
	st.OutDir = j.dir
	st.Hits = len(j.hits)
	st.HitsCapped = j.hitsCapped
	st.Removed = j.removed.Load()
	j.mu.Unlock()

	st.Total = j.total.Load()
	st.Tested = j.tested.Load()
	st.HTTP = j.nHTTP.Load()
	st.Socks4 = j.nS4.Load()
	st.Socks5 = j.nS5.Load()
	st.Bad = j.bad.Load()
	st.Retries = j.usedRetries.Load()
	st.Filtered = j.filtered.Load()
	st.Alive = st.HTTP + st.Socks4 + st.Socks5
	if st.Total > 0 {
		st.Pct = float64(st.Tested) / float64(st.Total) * 100
		if st.Pct > 100 {
			st.Pct = 100
		}
	}
	elapsed := time.Since(j.start).Minutes()
	if elapsed > 0 {
		st.CPM = int64(float64(st.Tested) / elapsed)
	}
	if st.CPM > 0 && st.Total > st.Tested {
		st.ETA = fmt.Sprintf("%.1fm", float64(st.Total-st.Tested)/float64(st.CPM))
	} else {
		st.ETA = "0m"
	}
	return st
}

func (a *App) massStatusJSON() massStatusJSON {
	if j := a.massCurrent(); j != nil {
		return j.statusJSON()
	}
	return massStatusJSON{ETA: "0m"}
}

// protoMatch: el filtro 'socks4' incluye tambien 'socks4a'.
func protoMatch(hp, want string) bool {
	return hp == want || (want == "socks4" && hp == "socks4a")
}

// massHits: ultimos hits en memoria ( opcionales por protocolo).
func (a *App) massHits(proto string, limit int) []massHit {
	j := a.massCurrent()
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []massHit
	for i := len(j.hits) - 1; i >= 0 && len(out) < limit; i-- {
		if proto == "" || proto == "all" || protoMatch(j.hits[i].Proto, proto) {
			out = append(out, j.hits[i])
		}
	}
	return out
}

// removeHits borra vivos en memoria: por linea exacta, por protocolo, o
// todos (proto="all"). Devuelve (borrados, restantes). Los contadores vivos
// se ajustan para que status.alive siga cuadrando; los .txt de la sesion en
// Resultados/ NO se reescriben (quedan como registro bruto del run).
func (j *massJob) removeHits(line, proto string) (int, int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	line = strings.TrimSpace(line)
	proto = strings.ToLower(strings.TrimSpace(proto))
	if line == "" && proto != "all" && proto != "http" && proto != "socks4" && proto != "socks5" {
		return 0, len(j.hits)
	}
	kept := j.hits[:0]
	removed := 0
	for _, h := range j.hits {
		del := false
		switch {
		case line != "":
			del = h.Line == line
		case proto == "all":
			del = true
		default:
			del = protoMatch(h.Proto, proto)
		}
		if del {
			removed++
			switch h.Proto {
			case "http":
				j.nHTTP.Add(-1)
			case "socks4", "socks4a":
				j.nS4.Add(-1)
			case "socks5":
				j.nS5.Add(-1)
			}
			continue
		}
		kept = append(kept, h)
	}
	j.hits = kept
	if removed > 0 {
		j.removed.Add(int64(removed))
	}
	return removed, len(j.hits)
}

// massExport: vivos por protocolo. format=full usa la linea estilo
// Espectro (proto | ping | anon | pais); default ip:puerto.
func (a *App) massExport(proto, format string) (string, bool) {
	j := a.massCurrent()
	if j == nil {
		return "", false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var sb strings.Builder
	for _, h := range j.hits {
		if proto != "" && proto != "all" && !protoMatch(h.Proto, proto) {
			continue
		}
		if format == "full" {
			sb.WriteString(fmt.Sprintf("%-21s | %-5s | %4dms | %s | %s", h.Line,
				strings.ToUpper(h.Proto), h.Ping, h.Anon, h.Country))
		} else {
			sb.WriteString(h.Line)
		}
		sb.WriteString("\n")
	}
	return sb.String(), true
}

// massCountries: conteo de vivos por pais (geo activo).
func (a *App) massCountries() map[string]int {
	out := map[string]int{}
	j := a.massCurrent()
	if j == nil {
		return out
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, h := range j.hits {
		if h.Country != "" {
			out[h.Country]++
		}
	}
	return out
}

// ============================ endpoints ============================

// registerChecker monta /checker/* en el mux de la API.
// Mutantes (start/cancel) pasan por allowPanel (POST + X-GW-Panel + token).
func (a *App) registerChecker(mux *http.ServeMux) {
	mux.HandleFunc("/checker/start", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		var req struct {
			Path      string `json:"path"`
			Text      string `json:"text"`
			Name      string `json:"name"`
			Judge     string `json:"judge"`
			Country   string `json:"country"`
			Geo       bool   `json:"geo"`
			Retries   int    `json:"retries"`
			Timeout   int    `json:"timeout"` // ms; 0 = dinamico
			Threads   int    `json:"threads"` // 0 = autopilot
			SkipLocal *bool  `json:"skip_local"`
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, massMaxText))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				jsonOut(w, map[string]interface{}{"ok": false, "error": "JSON invalido"})
				return
			}
		}
		skipLocal := true
		if req.SkipLocal != nil {
			skipLocal = *req.SkipLocal
		}
		cfg := massCfg{
			path:      strings.TrimSpace(req.Path),
			text:      req.Text,
			name:      strings.TrimSpace(req.Name),
			judge:     req.Judge,
			country:   req.Country,
			geo:       req.Geo,
			retries:   req.Retries,
			timeoutMs: req.Timeout,
			threads:   req.Threads,
			skipLocal: skipLocal,
		}
		j, err := a.massStart(cfg)
		if err != nil {
			code := http.StatusBadRequest
			if strings.Contains(err.Error(), "en curso") {
				code = http.StatusConflict
			}
			w.WriteHeader(code)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		jsonOut(w, map[string]interface{}{"ok": true, "started": true, "status": j.statusJSON()})
	})

	mux.HandleFunc("/checker/cancel", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		j := a.massCurrent()
		ok := false
		if j != nil {
			ok = j.cancel()
		}
		jsonOut(w, map[string]interface{}{"ok": true, "cancelled": ok})
	})

	// /checker/remove: borra vivos en memoria (por line, por proto o todos).
	// Solo afecta a hits/reportes/export; los .txt de la sesion no se tocan.
	mux.HandleFunc("/checker/remove", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		var req struct {
			Line  string `json:"line"`
			Proto string `json:"proto"`
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				jsonOut(w, map[string]interface{}{"ok": false, "error": "JSON invalido"})
				return
			}
		}
		req.Proto = strings.ToLower(strings.TrimSpace(req.Proto))
		switch req.Proto {
		case "", "all", "http", "socks4", "socks5":
		default:
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "protocolo desconocido"})
			return
		}
		if strings.TrimSpace(req.Line) == "" && req.Proto == "" {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "indica line o proto"})
			return
		}
		j := a.massCurrent()
		if j == nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "sin datos (ejecuta un checker masivo primero)"})
			return
		}
		n, rest := j.removeHits(req.Line, req.Proto)
		jsonOut(w, map[string]interface{}{"ok": true, "removed": n, "remaining": rest})
	})

	mux.HandleFunc("/checker/status", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, a.massStatusJSON())
	})
	mux.HandleFunc("/checker/hits", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible (vivos del checker): con --api-token exige token.
		if !a.leerOK(w, r) {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 5000 {
			limit = 200
		}
		jsonOut(w, map[string]interface{}{
			"hits": a.massHits(r.URL.Query().Get("proto"), limit),
		})
	})

	mux.HandleFunc("/checker/export", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible (vivos del checker): con --api-token exige token.
		if !a.leerOK(w, r) {
			return
		}
		format := r.URL.Query().Get("format")
		proto := r.URL.Query().Get("proto")
		if proto == "" {
			proto = "all"
		}
		text, ok := a.massExport(proto, format)
		if !ok {
			http.Error(w, "sin datos (ejecuta un checker masivo primero)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(text))
	})

	mux.HandleFunc("/checker/countries", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, map[string]interface{}{"countries": a.massCountries()})
	})

	mux.HandleFunc("/checker/report", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible (incluye la ruta de la fuente y del out_dir):
		// con --api-token exige token.
		if !a.leerOK(w, r) {
			return
		}
		j := a.massCurrent()
		if j == nil {
			http.Error(w, "sin datos (ejecuta un checker masivo primero)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(j.reportBytes())
	})
}

// outBaseDir: carpeta base de salidas ("Resultados" salvo en tests).
func (a *App) outBaseDir() string {
	a.massMu.Lock()
	defer a.massMu.Unlock()
	if a.massBase == "" {
		return "Resultados"
	}
	return a.massBase
}
