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
	"unicode"
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

	// geoCountryURL: pais de RESPALDO cuando no hay base mmdb. Solo se
	// consulta para proxies VIVOS (unos pocos entre miles): el limite de
	// ip-api (~45/min) no ahoga el chequeo, y la validacion no depende de el.
	geoCountryURL = "http://ip-api.com/json?fields=status,country,countryCode,query"
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
	ISO     string `json:"iso,omitempty"`
	IP6     bool   `json:"ip6,omitempty"`
}

type massJob struct {
	site        string // URL de validacion (Site)
	successKey  string // texto exigido en el cuerpo (validacion de contenido)
	siteIsJudge bool   // el site ES el juez: 1 sola peticion por proxy
	judge       string // URL del juez (anonimato / pais de respaldo)
	anonURL     string // juez para anonimato ("" = no clasificar)
	parallel    bool   // cascada en paralelo (mas CPM)
	geoDB       *geoDB // GeoIP offline (nil = se usa el juez)

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

	// Actividad en vivo por protocolo (panel "Thread State" estilo
	// Proxy Checker: HTTP/Socks4/Socks5 - [ n/n/n ]).
	actHTTP atomic.Int64
	actS4   atomic.Int64
	actS5   atomic.Int64

	// Reparto de anonimato y de version de IP de los vivos.
	nElite  atomic.Int64
	nHigh   atomic.Int64
	nTransp atomic.Int64
	nAnonX  atomic.Int64
	nV4     atomic.Int64
	nV6     atomic.Int64

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
	Remaining   int64   `json:"remaining"`
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
	ElapsedS    int     `json:"elapsed_s"`
	Elapsed     string  `json:"elapsed"`
	ActiveHTTP  int64   `json:"active_http"`
	ActiveS4    int64   `json:"active_socks4"`
	ActiveS5    int64   `json:"active_socks5"`
	Elite       int64   `json:"elite"`
	High        int64   `json:"high"`
	Transparent int64   `json:"transparent"`
	AnonUnknown int64   `json:"anon_unknown"`
	V4          int64   `json:"v4"`
	V6          int64   `json:"v6"`
	Site        string  `json:"site"`
	SuccessKey  string  `json:"success_key"`
	Anon        bool    `json:"anon"`
	Parallel    bool    `json:"parallel"`
	GeoMMDB     string  `json:"geo_mmdb,omitempty"`
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

// nombrePaisArchivo normaliza el country devuelto por el juez para usarlo
// como nombre de fichero SEGURO. El valor viene de la respuesta REMOTA del
// juez (ip-api.com via http://, manipulable con MITM, o un juez a medida):
// usarse crudo permitia path traversal ("../../x" creaba .txt fuera de
// Resultados). Se queda solo con letras/digitos Unicode (la enye de
// "españa" se conserva), espacios, guiones y guion bajo: sin separadores
// de ruta ni puntos no sobra ningun "../" ni "..\". Vacio -> "Desconocido".
func nombrePaisArchivo(pais string) string {
	var b strings.Builder
	for _, r := range pais {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s := strings.TrimSpace(b.String())
	if runes := []rune(s); len(runes) > 60 {
		s = strings.TrimSpace(string(runes[:60]))
	}
	if s == "" {
		return "Desconocido"
	}
	return s
}

// countryAlias: equivalencias entre codigo ISO, ingles y espanol -> forma
// canonica en INGLES. Permite que el filtro de pais funcione escriba el
// usuario "brasil", "brazil" o "br".
var countryAlias = map[string]string{
	"brasil": "brazil", "br": "brazil",
	"españa": "spain", "espana": "spain", "es": "spain",
	"estados unidos": "united states", "eeuu": "united states", "ee.uu.": "united states",
	"usa": "united states", "us": "united states", "united states of america": "united states",
	"reino unido": "united kingdom", "uk": "united kingdom", "gb": "united kingdom",
	"england": "united kingdom", "gran bretaña": "united kingdom",
	"alemania": "germany", "de": "germany",
	"francia": "france", "fr": "france",
	"japón": "japan", "japon": "japan", "jp": "japan",
	"méxico": "mexico", "mexico": "mexico", "mx": "mexico",
	"perú": "peru", "peru": "peru", "pe": "peru",
	"chile": "chile", "cl": "chile",
	"argentina": "argentina", "ar": "argentina",
	"colombia": "colombia", "co": "colombia",
	"venezuela": "venezuela", "ve": "venezuela",
	"holanda": "netherlands", "países bajos": "netherlands", "paises bajos": "netherlands", "nl": "netherlands",
	"rusia": "russia", "ru": "russia",
	"china": "china", "cn": "china",
	"corea del sur": "south korea", "kr": "south korea",
	"india": "india", "in": "india",
	"italia": "italy", "it": "italy",
	"canadá": "canada", "canada": "canada", "ca": "canada",
	"suecia": "sweden", "se": "sweden",
	"turquía": "turkey", "turquia": "turkey", "tr": "turkey",
	"indonesia": "indonesia", "id": "indonesia",
	"vietnam": "vietnam", "vn": "vietnam",
	"tailandia": "thailand", "th": "thailand",
}

// canonicalCountry normaliza un pais (nombre o ISO, en espanol o ingles) a
// una forma unica en minusculas para comparar filtros.
func canonicalCountry(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	if s == "" {
		return ""
	}
	if v, ok := countryAlias[s]; ok {
		return v
	}
	return s
}

// countryMatches: filtro de pais tolerante. Acepta ISO ("br"), ingles
// ("brazil") y espanol ("brasil"), y tambien nombres oficiales largos de
// algunas bases ("United Kingdom of Great Britain...") porque compara por
// subcadena.
func countryMatches(want, country, iso string) bool {
	w := canonicalCountry(want)
	if w == "" {
		return true
	}
	if iso != "" && canonicalCountry(iso) == w {
		return true
	}
	have := canonicalCountry(country)
	if have == "" {
		return false
	}
	return have == w || strings.Contains(have, w) || strings.Contains(w, have)
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
// azenv/Proxy Checker): si el juez ve nuesttra cabecera, el proxy no es
// anonimo. Niveles como el checker de referencia:
//
//	Elite       -> el juez no ve NADA (ni XFF ni VIA)
//	High        -> el juez ve que hay un proxy (VIA/FORWARDED) pero no tu IP
//	Transparent -> el juez ve tu IP real (X-Forwarded-For / Client-IP)
//	Unknown     -> el juez no devolvio un eco de cabeceras (pagina normal)
func anonLevel(scheme, body string) string {
	up := strings.ToUpper(body)
	espejo := strings.Contains(up, "REQUEST_METHOD") || strings.Contains(up, "HTTP_") ||
		strings.Contains(up, "REMOTE_ADDR")
	if espejo {
		ipExpuesta := strings.Contains(up, "HTTP_X_FORWARDED_FOR") ||
			strings.Contains(up, "HTTP_CLIENT_IP") || strings.Contains(up, "HTTP_X_REAL_IP") ||
			strings.Contains(up, "HTTP_FORWARDED_FOR") || strings.Contains(up, "HTTP_X_CLIENT_IP")
		if ipExpuesta {
			return "Transparent"
		}
		proxyVisible := strings.Contains(up, "HTTP_VIA") || strings.Contains(up, "PROXY_CONNECTION") ||
			strings.Contains(up, "HTTP_FORWARDED") || strings.Contains(up, "HTTP_X_PROXY_ID") ||
			strings.Contains(up, "HTTP_PROXY_AUTHORIZATION") || strings.Contains(up, "HTTP_X_FORWARDED")
		if proxyVisible {
			return "High"
		}
		return "Elite"
	}
	// sin eco del juez: un SOCKS no anade cabeceras HTTP -> Elite; un HTTP
	// puede estar devolviendo una pagina cacheada/suplantada.
	if scheme == "http" {
		return "Unknown"
	}
	return "Elite"
}

// normalizeAnon: valores heredados (Espectro/versiones previas) -> niveles
// actuales.
func normalizeAnon(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "anonymous":
		return "High"
	case "elite":
		return "Elite"
	case "high":
		return "High"
	case "transparent":
		return "Transparent"
	}
	return s
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

// massProbeRes: resultado de sondear un proxy.
type massProbeRes struct {
	proto   string
	ping    int
	country string
	iso     string
	anon    string
	code    int    // ultimo codigo HTTP visto (diagnostico)
	body    string // cuerpo de la respuesta (anonimato/GeoIP)
}

// schemesFor: protocolos a probar. Un esquema explicito en la linea manda;
// una linea "bare" (ip:puerto) se prueba en cascada SOCKS5 -> SOCKS4 -> HTTP.
func schemesFor(it *massItem) []string {
	if it.explicit != "" {
		return []string{it.explicit}
	}
	return []string{"socks5", "socks4", "http"}
}

func (it *massItem) proxy(scheme string) *Proxy {
	return &Proxy{Scheme: scheme, Host: it.host, Port: it.port, User: it.user, Password: it.pass}
}

// actBegin/actEnd: actividad en vivo por protocolo (panel "Thread State").
func (j *massJob) actBegin(scheme string) {
	switch scheme {
	case "http":
		j.actHTTP.Add(1)
	case "socks4", "socks4a":
		j.actS4.Add(1)
	case "socks5":
		j.actS5.Add(1)
	}
}

func (j *massJob) actEnd(scheme string) {
	switch scheme {
	case "http":
		j.actHTTP.Add(-1)
	case "socks4", "socks4a":
		j.actS4.Add(-1)
	case "socks5":
		j.actS5.Add(-1)
	}
}

// massProbe (compat): cascada secuencial contra un juez, sin Site ni Success
// Key (comportamiento historico: cuerpo solo si se pide GeoIP y anonimato
// siempre clasificado).
func massProbe(it *massItem, judge string, timeout time.Duration, geo bool) (string, int, string, string) {
	j := &massJob{site: judge, judge: judge, siteIsJudge: true, geo: geo}
	r := j.probe(it, timeout, geo)
	if geo {
		r.country = extractCountry(r.body)
	}
	if r.anon == "" {
		r.anon = normalizeAnon(anonLevel(r.proto, r.body))
	}
	return r.proto, r.ping, r.country, r.anon
}

// probe valida el proxy contra el Site del job (con Success Key si la hay)
// probando los protocolos en cascada. Devuelve el primer protocolo vivo.
// wantBody pide el cuerpo de la respuesta (se necesita para clasificar
// anonimato/pais desde el juez en la misma peticion).
func (j *massJob) probe(it *massItem, timeout time.Duration, wantBody bool) massProbeRes {
	schemes := schemesFor(it)
	sp := checkSpec{url: j.site, timeout: timeout, successKey: j.successKey}
	if wantBody && strings.TrimSpace(j.successKey) == "" {
		sp.maxBody = massBodyGeo
	}
	if j.parallel && len(schemes) > 1 {
		return j.probeParallel(it, schemes, sp)
	}
	res := massProbeRes{}
	for _, s := range schemes {
		j.actBegin(s)
		ok, ping, body, code := healthCheckSpec(it.proxy(s), sp)
		j.actEnd(s)
		if ok {
			res.proto, res.ping, res.body, res.code = s, ping, body, code
			return res
		}
		if code != 0 {
			res.code = code
		}
	}
	return res
}

// probeParallel: cascada EN PARALELO (los 3 protocolos a la vez). Un proxy
// muerto cuesta 1 timeout en vez de 3 -> hasta 3x mas CPM, que es como
// trabaja el checker de referencia (un pool por tipo). Gana el vivo con
// menor ping (empate: el orden socks5 > socks4 > http).
func (j *massJob) probeParallel(it *massItem, schemes []string, sp checkSpec) massProbeRes {
	type out struct {
		res massProbeRes
		ok  bool
	}
	ch := make(chan out, len(schemes))
	for _, s := range schemes {
		go func(s string) {
			j.actBegin(s)
			defer j.actEnd(s)
			ok, ping, body, code := healthCheckSpec(it.proxy(s), sp)
			ch <- out{ok: ok, res: massProbeRes{proto: s, ping: ping, body: body, code: code}}
		}(s)
	}
	best := massProbeRes{}
	bestPing := 0
	code := 0
	for range schemes {
		o := <-ch
		if o.res.code != 0 {
			code = o.res.code
		}
		if !o.ok {
			continue
		}
		if best.proto == "" || (o.res.ping > 0 && (bestPing == 0 || o.res.ping < bestPing)) {
			best, bestPing = o.res, o.res.ping
		}
	}
	if best.proto == "" {
		best.code = code
	}
	return best
}

// classify completa pais y anonimato de un VIVO (los muertos no pagan
// peticiones extra): pais desde la base mmdb local (sin red); anonimato
// desde el juez, reutilizando el cuerpo ya leido cuando el juez ES el site
// (caso por defecto: 1 sola peticion por proxy).
func (j *massJob) classify(it *massItem, res *massProbeRes, timeout time.Duration) {
	if j.geoDB != nil {
		rec := j.geoDB.countryRecIP(it.host)
		res.country, res.iso = rec.Name, rec.ISO
	}
	if res.country == "" && j.geoDB == nil && j.siteIsJudge {
		res.country = extractCountry(res.body)
	}
	// Sin base mmdb y sin pais del juez: consulta de respaldo a ip-api, SOLO
	// para este vivo (los muertos no gastan cuota).
	if j.geo && j.geoDB == nil && res.country == "" {
		sp := checkSpec{url: geoCountryURL, timeout: timeout, maxBody: massBodyGeo}
		if ok, _, body, _ := healthCheckSpec(it.proxy(res.proto), sp); ok {
			res.country = extractCountry(body)
		}
	}
	// El anonimato del juez-eco es GRATIS si el cuerpo ya esta leido (el site
	// ES el juez): se clasifica siempre, como el checker de referencia.
	if j.siteIsJudge && res.body != "" {
		res.anon = normalizeAnon(anonLevel(res.proto, res.body))
		return
	}
	if j.anonURL == "" {
		return
	}
	// peticion extra al juez (solo vivos, y solo si el site no era el juez)
	sp := checkSpec{url: j.anonURL, timeout: timeout, maxBody: massBodyGeo}
	ok, _, body, _ := healthCheckSpec(it.proxy(res.proto), sp)
	if !ok {
		// El juez no respondio: no se pudo clasificar. Se marca Unknown para
		// que el panel muestre un valor (y no un hueco) como el checker de
		// referencia; el contador lo cuenta igual como no clasificado.
		res.anon = "Unknown"
		return
	}
	res.anon = normalizeAnon(anonLevel(res.proto, body))
	if res.country == "" && j.geoDB == nil {
		res.country = extractCountry(body)
	}
}

// ============================ ciclo de vida ============================

type massCfg struct {
	path, text, name string
	site             string // URL de validacion (Site); "" = el juez
	successKey       string // texto exigido en el cuerpo de la respuesta
	judge            string // URL del juez (anonimato); "" = azenv.net
	anon             bool   // clasificar anonimato (Elite/High/Transparent)
	parallel         bool   // cascada en paralelo (mas CPM)
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
	// Juez de anonimato: el indicado o azenv.net (el unico tipo de juez que
	// devuelve el eco de cabeceras necesario para clasificar).
	anonURL := ""
	if cfg.anon {
		anonURL = strings.TrimSpace(cfg.judge)
		if anonURL == "" {
			anonURL = "http://azenv.net/"
		}
	}
	// Site de validacion: el indicado (con Success Key si la hay) o el juez.
	// Validar contra el juez permite 1 sola peticion por proxy. El site NO se
	// elige por GeoIP: validar contra ip-api agotaba su limite de tasa.
	site := strings.TrimSpace(cfg.site)
	siteIsJudge := site == "" // sin Site explicito se valida contra un juez
	var judgeEff string
	switch {
	case anonURL != "":
		judgeEff = anonURL
		if site == "" {
			site = anonURL
		}
	case site != "":
		judgeEff = site
	default:
		site = massJudge(cfg.judge, false)
		judgeEff = site
	}
	timeoutMs := cfg.timeoutMs
	dynPing := 0
	if timeoutMs <= 0 {
		dynPing, timeoutMs = dynamicTimeout(site)
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
		site:        site,
		successKey:  strings.TrimSpace(cfg.successKey),
		siteIsJudge: siteIsJudge,
		judge:       judgeEff,
		anonURL:     anonURL,
		parallel:    cfg.parallel,
		geoDB:       a.geoDB,
		country:     strings.ToLower(strings.TrimSpace(cfg.country)),
		geo:         geo,
		retries:     retries,
		timeoutMs:   timeoutMs,
		threads:     threads,
		source:      src,
		webhook:     "webhook.txt",
		outBase:     a.outBaseDir(),
		start:       time.Now(),
		running:     true,
		cancelCh:    make(chan struct{}),
		dynPing:     dynPing,
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
	a.logf("checker masivo iniciado: fuente=%s threads=%d timeout=%dms reintentos=%d geo=%v pais=%q site=%s key=%q anon=%v paralelo=%v",
		src, threads, timeoutMs, retries, geo, cfg.country, site, cfg.successKey, anonURL != "", cfg.parallel)
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

// massCheckOne: cascada + reintentos + clasificacion + filtro de pais + hit.
func (a *App) massCheckOne(j *massJob, it *massItem) {
	timeout := time.Duration(j.timeoutMs) * time.Millisecond
	// El cuerpo solo hace falta si vamos a clasificar con el juez en la
	// misma peticion (juez == site): anonimato, o pais cuando no hay base
	// mmdb. Si no, la validacion va sin leer cuerpo (mas rapida).
	wantBody := j.siteIsJudge && (j.anonURL != "" || (j.geo && j.geoDB == nil))
	var res massProbeRes
	for attempt := 0; attempt <= j.retries; attempt++ {
		res = j.probe(it, timeout, wantBody)
		if res.proto != "" {
			break
		}
		if attempt < j.retries {
			j.usedRetries.Add(1)
		}
	}
	if res.proto == "" {
		j.bad.Add(1)
		j.tested.Add(1)
		return
	}
	j.classify(it, &res, timeout)
	if j.country != "" && !countryMatches(j.country, res.country, res.iso) {
		// descarte silencioso estilo Espectro: no suma vivos ni muertos
		j.filtered.Add(1)
		j.tested.Add(1)
		return
	}
	switch res.proto {
	case "http":
		j.nHTTP.Add(1)
	case "socks4", "socks4a":
		j.nS4.Add(1)
	case "socks5":
		j.nS5.Add(1)
	}
	switch res.anon {
	case "Elite":
		j.nElite.Add(1)
	case "High":
		j.nHigh.Add(1)
	case "Transparent":
		j.nTransp.Add(1)
	default:
		j.nAnonX.Add(1)
	}
	if strings.Contains(it.host, ":") {
		j.nV6.Add(1)
	} else {
		j.nV4.Add(1)
	}
	j.addHit(massHit{Line: it.plain, Proto: res.proto, Ping: res.ping,
		Anon: res.anon, Country: res.country, ISO: res.iso,
		IP6: strings.Contains(it.host, ":")})
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
		// nombre de fichero saneado (ver nombrePaisArchivo): country crudo
		// del juez remoto = path traversal potencial, jamas.
		safe := nombrePaisArchivo(h.Country)
		if safe != "Desconocido" {
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
	j.mu.Lock()
	start, end := j.start, j.end
	j.mu.Unlock()
	elapsed := time.Since(start)
	if !end.IsZero() {
		elapsed = end.Sub(start)
	}
	cpm := int64(0)
	if m := elapsed.Minutes(); m > 0 {
		cpm = int64(float64(tested) / m)
	}
	j.mu.Lock()
	report := map[string]interface{}{
		"TotalEvaluados": tested,
		"Restantes":      j.total.Load() - tested,
		"Vivos": map[string]int64{
			"HTTP": j.nHTTP.Load(), "SOCKS4": j.nS4.Load(), "SOCKS5": j.nS5.Load(),
			"Total": j.nHTTP.Load() + j.nS4.Load() + j.nS5.Load(),
		},
		"Anonimato": map[string]int64{
			"Elite": j.nElite.Load(), "High": j.nHigh.Load(),
			"Transparent": j.nTransp.Load(), "Desconocido": j.nAnonX.Load(),
		},
		"IP":         map[string]int64{"IPv4": j.nV4.Load(), "IPv6": j.nV6.Load()},
		"Muertos":    j.bad.Load(),
		"Reintentos": j.usedRetries.Load(),
		"CPM":        cpm,
		"Tiempo":     formatDuracion(elapsed),
		"Fecha":      time.Now().Format("2006-01-02 15:04:05"),
		"Site":       j.site,
		"SuccessKey": j.successKey,
		"Juez":       j.judge,
		"GeoMMDB":    geoInfo(j.geoDB),
		"Filtrados":  j.filtered.Load(),
		"Cancelado":  j.cancelled,
		"Fuente":     j.source,
	}
	j.mu.Unlock()
	b, _ := json.MarshalIndent(report, "", "  ")
	return b
}

func geoInfo(g *geoDB) string {
	if g == nil {
		return ""
	}
	return g.info()
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
		Site:        j.site,
		SuccessKey:  j.successKey,
		Anon:        j.anonURL != "",
		Parallel:    j.parallel,
		Country:     j.country,
		Geo:         j.geo,
		RetriesCfg:  j.retries,
		TimeoutMs:   j.timeoutMs,
		DynamicPing: j.dynPing,
		Threads:     j.threads,
	}
	if j.geoDB != nil {
		st.GeoMMDB = j.geoDB.info()
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
	st.ActiveHTTP = j.actHTTP.Load()
	st.ActiveS4 = j.actS4.Load()
	st.ActiveS5 = j.actS5.Load()
	st.Elite = j.nElite.Load()
	st.High = j.nHigh.Load()
	st.Transparent = j.nTransp.Load()
	st.AnonUnknown = j.nAnonX.Load()
	st.V4 = j.nV4.Load()
	st.V6 = j.nV6.Load()
	st.Alive = st.HTTP + st.Socks4 + st.Socks5
	if st.Total > st.Tested {
		st.Remaining = st.Total - st.Tested
	}
	if st.Total > 0 {
		st.Pct = float64(st.Tested) / float64(st.Total) * 100
		if st.Pct > 100 {
			st.Pct = 100
		}
	}
	// Reloj estilo Proxy Checker: tiempo transcurrido desde el arranque del
	// job (se congela al terminar). El CPM se calcula sobre ese mismo tiempo.
	elapsed := time.Since(j.start)
	if st.Done && !j.end.IsZero() {
		elapsed = j.end.Sub(j.start)
	}
	if elapsed < 0 {
		elapsed = 0
	}
	st.ElapsedS = int(elapsed.Seconds())
	st.Elapsed = formatDuracion(elapsed)
	minutes := elapsed.Minutes()
	if minutes > 0 {
		st.CPM = int64(float64(st.Tested) / minutes)
	}
	if st.CPM > 0 && st.Total > st.Tested {
		st.ETA = formatDuracion(time.Duration(float64(st.Total-st.Tested) / float64(st.CPM) * float64(time.Minute)))
	} else {
		st.ETA = "0s"
	}
	return st
}

// formatDuracion: "1h02m03s" / "2m03s" / "7s" (estilo panel del checker).
func formatDuracion(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	h, m, sec := s/3600, (s%3600)/60, s%60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm%02ds", h, m, sec)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, sec)
	default:
		return fmt.Sprintf("%ds", sec)
	}
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
			Path       string `json:"path"`
			Text       string `json:"text"`
			Name       string `json:"name"`
			Site       string `json:"site"`
			SuccessKey string `json:"success_key"`
			Judge      string `json:"judge"`
			Country    string `json:"country"`
			Geo        bool   `json:"geo"`
			Anon       *bool  `json:"anon"`
			Parallel   *bool  `json:"parallel"`
			Retries    int    `json:"retries"`
			Timeout    int    `json:"timeout"` // ms; 0 = dinamico
			Threads    int    `json:"threads"` // 0 = autopilot
			SkipLocal  *bool  `json:"skip_local"`
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
		anon := true
		if req.Anon != nil {
			anon = *req.Anon
		}
		parallel := true
		if req.Parallel != nil {
			parallel = *req.Parallel
		}
		cfg := massCfg{
			path:       strings.TrimSpace(req.Path),
			text:       req.Text,
			name:       strings.TrimSpace(req.Name),
			site:       req.Site,
			successKey: req.SuccessKey,
			judge:      req.Judge,
			anon:       anon,
			parallel:   parallel,
			country:    req.Country,
			geo:        req.Geo,
			retries:    req.Retries,
			timeoutMs:  req.Timeout,
			threads:    req.Threads,
			skipLocal:  skipLocal,
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
		// Lectura sensible (incluye source y out_dir, igual que
		// /checker/report): con --api-token exige token. El panel siempre
		// manda X-API-Token en jget, asi que la UI no se ve afectada.
		if !a.leerOK(w, r) {
			return
		}
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
		// countries=all (default) o lista tolerante ("BR,US,brasil").
		countries := parseCountries(r.URL.Query().Get("countries"))
		text, ok := a.massExportSel(proto, format, countries)
		if !ok {
			http.Error(w, "sin datos (ejecuta un checker masivo primero)", http.StatusNotFound)
			return
		}
		switch strings.ToLower(strings.TrimSpace(format)) {
		case "json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		case "csv":
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Write([]byte(text))
	})

	mux.HandleFunc("/checker/countries", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible minima (conteos por pais): misma proteccion
		// que el resto de /checker/* con --api-token (antes era el unico
		// endpoint sin leerOK — exposicion inconsistente).
		if !a.leerOK(w, r) {
			return
		}
		jsonOut(w, map[string]interface{}{
			"countries": a.massCountries(),
			"list":      a.massCountryList(),
		})
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
