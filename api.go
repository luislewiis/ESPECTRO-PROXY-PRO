package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed panel.html
var panelHTML string

// maxProxyTxtLines es el techo duro de lineas que /proxy.txt entrega aunque
// pidan ?max= mas grande: evita que una fuente remota mal configurada vuelque
// el pool completo (100k+) en el ProxyManager de OB y lo congele.
const maxProxyTxtLines = 200000

type proxyJSON struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Alive  bool   `json:"alive"`
	Fails  int    `json:"fails"`
	Tag    string `json:"tag"`
	// Key = identificador estable (scheme|host:port|user): lo usan el panel
	// para borrar/editar proxies exactos via /proxy-remove y /proxy-edit.
	Key string `json:"key"`
	// Estado de analisis (persistido entre reinicios):
	Checked   bool  `json:"checked"`
	PingMs    int   `json:"ping_ms"`
	LastCheck int64 `json:"last_check"`
	// Alt: protocolo REAL detectado (el declarado no respondia).
	Alt string `json:"alt,omitempty"`
	// Effective: esquema con el que realmente se usa el proxy.
	Effective string `json:"effective,omitempty"`
	// Country: pais (GeoIP) del proxy.
	Country string `json:"country,omitempty"`
	// ConnOK/ConnKnown: si se ha MEDIDO que el proxy sabe tunelizar.
	ConnOK    bool `json:"conn_ok"`
	ConnKnown bool `json:"conn_known"`
	// CooldownS: segundos que le quedan de enfriamiento (0 = ninguno).
	CooldownS int `json:"cooldown_s"`
	// Anon: nivel de anonimato si lo midio el checker masivo ("" = sin dato).
	Anon string `json:"anon,omitempty"`
	// Capacidad medida: TLS 1.3, HTTP/2 y resolucion DNS remota.
	TLS13     bool   `json:"tls13"`
	H2        bool   `json:"h2"`
	DNSRemote bool   `json:"dns_remote"`
	DNSMode   string `json:"dns_mode,omitempty"`
	CapsKnown bool   `json:"caps_known"`
	// User/Password: credenciales del proxy (para la linea OB de la ficha).
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

type statsJSON struct {
	Requests  int64    `json:"requests"`
	Errors    int64    `json:"errors"`
	BytesUp   int64    `json:"bytes_up"`
	BytesDown int64    `json:"bytes_down"`
	Alive     int      `json:"alive"`
	Dead      int      `json:"dead"`
	Unchecked int      `json:"unchecked"` // vivos sin verificar (nunca chequeados)
	Total     int      `json:"total"`
	Sessions  int      `json:"sessions"`
	Strategy  string   `json:"strategy"`
	Files     []string `json:"files"`
	Gateway   string   `json:"gateway"`
	CheckItv  int      `json:"check_itv"`  // health-check en s (0 = desactivado)
	StateFile string   `json:"state_file"` // base del archivo de estado ("" = off)
	Version   string   `json:"version"`    // inyectada por ldflags en release
	Lic       string   `json:"lic"`        // "Pro — ACME, perpetua" | "Demo (checker hasta 2000...)"
	// Modo del auto-check: "alive" (solo vivos + sin verificar) | "full"
	// (chequeo completo de la lista en cada ciclo).
	CheckMode string `json:"check_mode"`
	// Reintentos por proxy (cada uno con un protocolo distinto).
	CheckRetries int `json:"check_retries"`
	// Modo de validacion: "GET" o "CONNECT" (tunel, el que necesita OB).
	CheckMode2 string `json:"check_kind"`
	// Metricas del rail lateral (todas medidas, nunca inventadas).
	LatP50       int        `json:"lat_p50"`
	LatP90       int        `json:"lat_p90"`
	AliveHTTP    int        `json:"alive_http"`
	AliveSocks4  int        `json:"alive_socks4"`
	AliveSocks5  int        `json:"alive_socks5"`
	ThreadsNow   int64      `json:"threads_active"`
	ThreadsTotal int        `json:"threads_total"`
	RetriesUsed  int64      `json:"retries_used"`
	SuccessRate  float64    `json:"success_rate"`
	GeoTop       []geoCount `json:"geo_top"`
	LastCheck    int64      `json:"last_check_ts"`
	AliveChecked int        `json:"alive_checked"`
	// Capacidades medidas de los vivos (caps.go).
	TLS13       int `json:"tls13"`
	H2          int `json:"h2"`
	DNSRemote   int `json:"dns_remote"`
	Elite       int `json:"anon_elite"`
	High        int `json:"anon_high"`
	Transparent int `json:"anon_transparent"`
}

// geoCount: paises con mas proxies vivos (geolocalizacion top).
type geoCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

func (a *App) statsSnapshot() statsJSON {
	alive, total := a.counts()
	a.mu.Lock()
	sessions := len(a.sessions)
	strategy := a.strategy
	files := append([]string(nil), a.files...)
	gateway := a.gateway
	unchecked := 0
	for _, p := range a.proxies {
		if !p.Checked {
			unchecked++
		}
	}
	a.mu.Unlock()
	stateFile := ""
	if p := a.statePathFor(); p != "" {
		stateFile = filepath.Base(p)
	}
	// Metricas del rail: percentiles de latencia, reparto por protocolo y
	// geolocalizacion top. Todo se mide sobre los proxies VIVOS.
	p50, p90 := 0, 0
	var byProto map[string]int
	geo := map[string]int{}
	lastCheck := int64(0)
	tls13, h2n, dnsRemote, elite, high, transpar := 0, 0, 0, 0, 0, 0
	a.mu.Lock()
	for _, p := range a.proxies {
		if p.LastCheck > lastCheck {
			lastCheck = p.LastCheck
		}
		if !p.Alive {
			continue
		}
		if byProto == nil {
			byProto = map[string]int{}
		}
		byProto[p.EffScheme()]++
		if p.Country != "" {
			geo[strings.ToUpper(p.Country)]++
		}
		if p.TLS13 {
			tls13++
		}
		if p.H2 {
			h2n++
		}
		if p.DNSRemote {
			dnsRemote++
		}
		switch p.Anon {
		case "Elite":
			elite++
		case "High":
			high++
		case "Transparent":
			transpar++
		}
	}
	pinges := make([]int, 0, len(a.proxies))
	for _, p := range a.proxies {
		if p.Alive && p.PingMs > 0 {
			pinges = append(pinges, p.PingMs)
		}
	}
	a.mu.Unlock()
	if len(pinges) > 0 {
		sort.Ints(pinges)
		// Percentil por rango mas cercano (nearest-rank): p50 = mediana,
		// p90 = el valor por debajo del cual esta el 90% de las muestras.
		p50 = pinges[(len(pinges)*50+99)/100-1]
		p90 = pinges[(len(pinges)*90+99)/100-1]
	}
	geoTop := make([]geoCount, 0, len(geo))
	for c, n := range geo {
		geoTop = append(geoTop, geoCount{Country: c, Count: n})
	}
	sort.Slice(geoTop, func(i, j int) bool {
		if geoTop[i].Count != geoTop[j].Count {
			return geoTop[i].Count > geoTop[j].Count
		}
		return geoTop[i].Country < geoTop[j].Country
	})
	if len(geoTop) > 8 {
		geoTop = geoTop[:8]
	}
	req := a.stats.Requests.Load()
	errs := a.stats.Errors.Load()
	rate := 0.0
	if req > 0 {
		rate = float64(req-errs) / float64(req) * 100
	}
	return statsJSON{
		Requests:     a.stats.Requests.Load(),
		Errors:       a.stats.Errors.Load(),
		BytesUp:      a.stats.BytesUp.Load(),
		BytesDown:    a.stats.BytesDown.Load(),
		Alive:        alive,
		Dead:         total - alive,
		Unchecked:    unchecked,
		Total:        total,
		Sessions:     sessions,
		Strategy:     strategy,
		Files:        files,
		Gateway:      gateway,
		CheckItv:     a.checkItv,
		StateFile:    stateFile,
		Version:      version,
		Lic:          licDesc(),
		CheckMode:    a.checkScopeName(),
		CheckRetries: a.checkRetries,
		CheckMode2:   map[bool]string{true: "CONNECT", false: "GET"}[a.checkConnect],
		LatP50:       p50,
		LatP90:       p90,
		AliveHTTP:    byProto["http"],
		AliveSocks4:  byProto["socks4"] + byProto["socks4a"],
		AliveSocks5:  byProto["socks5"],
		ThreadsNow:   a.checkActive.Load(),
		ThreadsTotal: checkThreads,
		RetriesUsed:  a.checkRetriesUsed.Load(),
		SuccessRate:  rate,
		GeoTop:       geoTop,
		LastCheck:    lastCheck,
		TLS13:        tls13,
		H2:           h2n,
		DNSRemote:    dnsRemote,
		Elite:        elite,
		High:         high,
		Transparent:  transpar,
	}
}

// checkScopeName: modo efectivo del auto-check ("alive" | "full").
func (a *App) checkScopeName() string {
	if a.checkAll {
		return "full"
	}
	if a.checkScope == "full" || a.checkScope == "all" {
		return "full"
	}
	return "alive"
}

func (a *App) proxiesSnapshot() []proxyJSON {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().Unix()
	out := make([]proxyJSON, 0, len(a.proxies))
	for _, p := range a.proxies {
		cd := 0
		if exp, ok := a.enfriar[p.Key()]; ok {
			if r := int(exp - now); r > 0 {
				cd = r
			}
		}
		out = append(out, proxyJSON{
			Scheme: p.Scheme, Host: p.Host, Port: p.Port,
			Alive: p.Alive, Fails: p.Fails, Tag: p.Tag(),
			Key:     p.Key(),
			Checked: p.Checked, PingMs: p.PingMs, LastCheck: p.LastCheck,
			Alt: p.AltScheme, Effective: p.EffScheme(),
			Country: p.Country, ConnOK: p.ConnOK, ConnKnown: p.ConnKnown,
			CooldownS: cd,
			User:      p.User, Password: p.Password,
			Anon:  p.Anon,
			TLS13: p.TLS13, H2: p.H2, DNSRemote: p.DNSRemote,
			DNSMode: p.DNSMode, CapsKnown: p.CapsKnown,
		})
	}
	return out
}

func randomToken() string {
	b := make([]byte, 8)
	// crypto/rand.Read nunca devuelve error (doc: "It never returns an error,
	// and always fills b entirely"): se ignora de forma explicita.
	_, _ = rand.Read(b)
	return "s" + hex.EncodeToString(b)
}

// ---------------- rate-limit de autenticacion ----------------
// Tras authFailsMax fallos de token desde la misma IP dentro de
// authFailWindow, esa IP queda bloqueada (429) durante authBlockDur.
// Frena la fuerza bruta contra --api-token aunque la API este en LAN.
const (
	authFailsMax   = 10
	authFailWindow = 10 * time.Minute
	authBlockDur   = 2 * time.Minute
)

// authLimiter cuenta fallos de token por IP. now es inyectable para tests.
type authLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
	block map[string]time.Time
	now   func() time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{
		fails: make(map[string][]time.Time),
		block: make(map[string]time.Time),
		now:   time.Now,
	}
}

func (l *authLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if until, ok := l.block[ip]; ok {
		if now.Before(until) {
			return // ya bloqueado: no contar ni extender
		}
		delete(l.block, ip)
	}
	cut := now.Add(-authFailWindow)
	kept := make([]time.Time, 0, len(l.fails[ip])+1)
	for _, t := range l.fails[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) >= authFailsMax {
		l.block[ip] = now.Add(authBlockDur)
		delete(l.fails, ip)
		return
	}
	l.fails[ip] = kept
	// poda de IPs con la ventana vencida: el mapa no debe crecer sin limite
	for k, v := range l.fails {
		if len(v) == 0 || !v[len(v)-1].After(cut) {
			delete(l.fails, k)
		}
	}
	for k, until := range l.block {
		if !until.After(now) {
			delete(l.block, k)
		}
	}
}

func (l *authLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.block[ip]
	if !ok {
		return false
	}
	if l.now().After(until) {
		delete(l.block, ip)
		return false
	}
	return true
}

// clear resetea los fallos de una IP (un acierto valido borra el historial).
func (l *authLimiter) clear(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

func ipDe(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

// resultado de la autenticacion de un request
type authResult int

const (
	authOK authResult = iota
	authSinToken
	authBloqueado
)

// auth valida --api-token aplicando rate-limit por IP (fuerza bruta).
// Sin token configurado, todo pasa (modo local por defecto).
func (a *App) auth(r *http.Request) authResult {
	if a.apiToken == "" {
		return authOK
	}
	ip := ipDe(r)
	if a.authLim.blocked(ip) {
		return authBloqueado
	}
	// ConstantTimeCompare: la comparacion de tokens no debe filtrar
	// prefijos por timing (el rate-limit ya frena la fuerza bruta).
	okH := subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Token")), []byte(a.apiToken))
	okQ := subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(a.apiToken))
	if okH == 1 || okQ == 1 {
		a.authLim.clear(ip)
		return authOK
	}
	a.authLim.fail(ip)
	return authSinToken
}

// writeAuth responde 429 (bloqueado) o 401 (token invalido); true = autorizado.
func writeAuth(w http.ResponseWriter, res authResult) bool {
	switch res {
	case authOK:
		return true
	case authBloqueado:
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"ok":false,"error":"demasiados intentos, espera un poco"}`)
	default:
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"ok":false,"error":"token invalido"}`)
	}
	return false
}

// leerOK protege lecturas sensibles (credenciales, listas, hits): exige el
// token SOLO si --api-token esta configurado; sin el, no cambia nada.
func (a *App) leerOK(w http.ResponseWriter, r *http.Request) bool {
	return writeAuth(w, a.auth(r))
}

// setCSP aplica las cabeceras de seguridad de las paginas HTML (indice y
// panel): frame-ancestors/X-Frame-Options cierran el clickjacking, CSP
// limita recursos a este origen y base-uri impide reescribir los enlaces
// relativos. 'unsafe-inline' en script/style se mantiene porque el panel
// usa atributos onclick/estilos inline (sin ellos se romperia toda la UI).
func setCSP(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// allowPanel protege los endpoints que cambian estado (/reload, /set-strategy,
// /check): requieren POST + cabecera X-GW-Panel (solo el panel la envia) y,
// si hay --api-token, tambien ese token. Bloquea CSRF desde paginas web.
func (a *App) allowPanel(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, `{"ok":false,"error":"usa POST"}`)
		return false
	}
	if r.Header.Get("X-GW-Panel") != "1" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"ok":false,"error":"falta cabecera X-GW-Panel"}`)
		return false
	}
	return writeAuth(w, a.auth(r))
}

func (a *App) APIMux(httpPort int, bind string) *http.ServeMux {
	gatewayBase := "http://" + net.JoinHostPort(bind, strconv.Itoa(httpPort))
	a.mu.Lock()
	a.gateway = gatewayBase
	a.mu.Unlock()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Si alguien usa este puerto (API/panel) como proxy, no devolver el
		// indice: avisar con el endpoint correcto del gateway.
		if r.Method == http.MethodConnect || r.Header.Get("Proxy-Authorization") != "" || r.URL.IsAbs() {
			http.Error(w, "Este es el puerto de la API/panel, no un proxy. Endpoint del gateway: "+gatewayBase, http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		alive, total := a.counts()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setCSP(w)
		// Pagina de referencia de la API: tema oscuro del panel (antes salia
		// como texto crudo en blanco al pulsar "API" desde la ventana).
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="15"><title>ESPECTRO PROXY PRO</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0f1a;color:#cfe3ff;font:15px/1.65 Consolas,Menlo,monospace;padding:28px}
.card{max-width:820px;margin:0 auto;background:#111827;border:1px solid #1f2b40;border-radius:12px;padding:24px 30px 28px;box-shadow:0 12px 34px rgba(0,0,0,.45)}
a{color:#48e0c0}
a:hover{color:#7ff3db}
.back{display:inline-block;margin-bottom:14px;color:#8fb3ff;text-decoration:none}
.back:hover{text-decoration:underline}
h1{font-size:19px;margin:0 0 6px;color:#e8f3ff;letter-spacing:.6px;font-weight:600}
h1 span{color:#48e0c0}
.stat{background:#0d1524;border:1px solid #1f2b40;border-radius:8px;padding:9px 14px;display:inline-block;margin:8px 0 14px;color:#9fb8dd}
.stat b{color:#48e0c0}
ul{list-style:none;padding:0;margin:0}
li{margin:7px 0;border-bottom:1px dashed #172238;padding-bottom:7px}
li:last-child{border-bottom:0}
code{background:#0d1524;border:1px solid #1f2b40;border-radius:6px;padding:1px 7px;color:#9fe8ff}
.k{color:#6f8bb0}
.note{color:#6f8bb0;font-size:13px;margin-top:16px}
</style>
<div class="card">
<a class="back" href="/panel">&#8592; Volver al panel</a>
<h1>ESPECTRO PROXY PRO <span>&mdash; API</span></h1>
<div class="stat"><b>%d/%d</b> proxies vivos <span class="k">|</span> estrategia: %s</div>
<ul>
<li><span class="k">Panel:</span> <a href="/panel">/panel</a></li>
<li><span class="k">Endpoint rotativo:</span> <code>%s</code></li>
<li><span class="k">Sesion sticky:</span> <code>http://MI_SESION:clave@%s:%d</code></li>
<li><a href="/get?session=MI_SESION">/get?session=MI_SESION</a> <span class="k">(enlace magico JSON)</span></li>
<li><a href="/stats">/stats</a></li>
<li><a href="/proxies">/proxies</a></li>
<li><a href="/proxy.txt">/proxy.txt</a> <span class="k">(lista viva, para OB M2)</span></li>
<li><code>POST /reload</code> <span class="k">(cabecera X-GW-Panel: 1)</span></li>
<li><code>POST /proxy-remove</code>, <code>POST /proxy-edit</code> <span class="k">(gestor de la lista: keys/dead/alive persisten en disco; scope "all" solo memoria)</span></li>
</ul>
<p class="note">Los endpoints marcados con POST exigen la cabecera <code>X-GW-Panel: 1</code>
	y, si hay <code>--api-token</code>, tambien <code>X-API-Token</code>. Con <code>--api-token</code>,
	las lecturas <code>/proxies</code>, <code>/logs</code>, <code>/proxy.txt</code>,
	<code>/checker/status</code>, <code>/checker/hits</code>, <code>/checker/export</code>
	y <code>/checker/report</code>
	exigen el token; tras 10 fallos la IP recibe 429 durante un rato.</p>
	</div>`, alive, total, a.statsSnapshot().Strategy, html.EscapeString(gatewayBase), html.EscapeString(bind), httpPort)
	})

	mux.HandleFunc("/panel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		setCSP(w)
		// inyecta el token en la meta del panel para que api()/jpost() lo envien
		// (html.EscapeString: un --api-token con < o " no rompe/inyecta HTML).
		// Replace n=1: solo la meta (linea 6); el literal '__GW_TOKEN__' del
		// JS (guard de gwToken) NO se toca, o la comparacion quedaria
		// `!== '<token>'` y el panel dejaria de mandar el token siempre.
		page := strings.Replace(panelHTML, "__GW_TOKEN__", html.EscapeString(a.apiToken), 1)
		w.Write([]byte(page))
	})

	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		session := r.URL.Query().Get("session")
		if session == "" {
			session = randomToken()
		}
		// cap de 64: el session es clave del mapa de sesiones (DoS de memoria)
		if len(session) > 64 {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"error": "sesion demasiado larga (max 64)"})
			return
		}
		p := a.pick(session, nil)
		if p == nil {
			jsonOut(w, map[string]interface{}{"error": "sin proxies vivos"})
			return
		}
		alive, total := a.counts()
		jsonOut(w, map[string]interface{}{
			"session":   session,
			"gateway":   gatewayBase,
			"proxy":     "http://" + session + ":clave@" + net.JoinHostPort(bind, strconv.Itoa(httpPort)),
			"sticky_on": p.Tag(),
			"strategy":  a.statsSnapshot().Strategy,
			"alive":     alive,
			"total":     total,
		})
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, a.statsSnapshot())
	})

	mux.HandleFunc("/proxies", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible (lista completa): con --api-token exige token.
		if !a.leerOK(w, r) {
			return
		}
		// Paginacion: con listas grandes (24k) el JSON completo son varios MB
		// y el panel se congela renderizando. ?limit=200&offset=0 devuelve
		// {proxies,total,offset,limit}; sin ?limit devuelve el array completo.
		// ?sort=ping ordena por latencia (vivos con ping primero, estilo
		// xRisky "TimeOut/latencia"); el orden NO afecta a la rotacion interna.
		all := a.proxiesSnapshot()
		if r.URL.Query().Get("sort") == "ping" {
			sort.SliceStable(all, func(i, j int) bool {
				rank := func(p proxyJSON) int {
					switch {
					case p.Alive && p.Checked && p.PingMs > 0:
						return 0
					case p.Alive:
						return 1
					}
					return 2
				}
				ri, rj := rank(all[i]), rank(all[j])
				if ri != rj {
					return ri < rj
				}
				return all[i].PingMs < all[j].PingMs
			})
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 {
			jsonOut(w, all)
			return
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}
		if offset > len(all) {
			offset = len(all)
		}
		end := len(all)
		// Sin overflow: solo sumar cuando limit < resto (offset+len nunca
		// puede desbordar; ?limit=MaxInt64 antes rompia con panic de slice
		// porque offset+limit daba negativo y all[offset:end] petaba).
		if limit < len(all)-offset {
			end = offset + limit
		}
		jsonOut(w, map[string]interface{}{
			"proxies": all[offset:end],
			"total":   len(all),
			"offset":  offset,
			"limit":   limit,
		})
	})

	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible (los logs imprimen p.Tag() = host:puerto de los
		// proxies): con --api-token exige token, como /proxies.
		if !a.leerOK(w, r) {
			return
		}
		jsonOut(w, map[string]interface{}{"lines": a.logTail(100)})
	})

	mux.HandleFunc("/proxy.txt", func(w http.ResponseWriter, r *http.Request) {
		// Lectura sensible (format=ob incluye user:pass): con --api-token exige token.
		if !a.leerOK(w, r) {
			return
		}
		format := r.URL.Query().Get("format")
		// scheme / proto: filtra por protocolo (http|socks4|socks4a|socks5).
		scheme := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scheme")))
		if scheme == "" {
			scheme = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("proto")))
		}
		aliveOnly := r.URL.Query().Get("alive") == "1"
		// Politica "solo vivo y filtrado" (README): ?alive=1 NUNCA entrega un
		// proxy sin verificar. El modo optimista historico (servir tu propia
		// lista recien cargada antes del primer chequeo) hay que pedirlo:
		//   /proxy.txt?alive=1&include_unchecked=1
		// Sin esto, tras un arranque limpio OB recibia 12k+ proxies sin
		// validar, justo lo que la politica dice evitar (auditoria 17/10/2026).
		includeUnchecked := r.URL.Query().Get("include_unchecked") == "1"
		maxPing := 0
		if mp := r.URL.Query().Get("max_ping"); mp != "" {
			maxPing, _ = strconv.Atoi(mp)
		}
		// Acepta varios paises ("BR,US,brasil") y nombres en ingles/espanol.
		countries := parseCountries(r.URL.Query().Get("country"))
		// Tope de lineas entregadas (?max=N). OB M2 y SilverBullet meten la
		// lista entera en su ProxyManager y la re-chequean proxy a proxy: con
		// 12k+ lineas la UI se congela y el runner parece "caerse" antes de
		// arrancar. Recomendado para fuentes remotas:
		//   /proxy.txt?alive=1&sort=ping&max=500
		// 0 = sin tope (comportamiento historico). Se aplica DESPUES de
		// ordenar, para que el tope se quede con los de menor ping.
		maxOut := 0
		if v := r.URL.Query().Get("max"); v != "" {
			maxOut, _ = strconv.Atoi(v)
		} else if v := r.URL.Query().Get("limit"); v != "" {
			maxOut, _ = strconv.Atoi(v)
		}
		if maxOut < 0 {
			maxOut = 0
		}
		if maxOut > maxProxyTxtLines {
			maxOut = maxProxyTxtLines
		}

		// Filtrado con a.mu TOMADO: Alive/Checked/PingMs/Country los escribe el
		// health-check en caliente; leerlos sin lock era una carrera real
		// (benigna hasta hoy, pero real) que el filtro estricto de 'checked'
		// habria ampliado. La serializacion de abajo solo toca campos
		// inmutables tras publicar el proxy (Scheme/Host/Port/User/Password),
		// asi que sigue fuera del lock (una lista de 130k no bloquea la
		// rotacion).
		a.mu.Lock()
		a.refreshIdxLocked()
		src := a.aliveIdx
		if len(src) == 0 && !aliveOnly {
			src = a.proxies
		}
		list := make([]*Proxy, 0, len(src))
		for _, p := range src {
			if aliveOnly && !includeUnchecked && !p.Checked {
				continue
			}
			// protoMatch: "socks4" incluye "socks4a", igual que el checker y
			// que el export OB (OB no distingue 4a). "socks4a" sigue exacto.
			if scheme != "" && !protoMatch(p.Scheme, scheme) {
				continue
			}
			if maxPing > 0 && (p.PingMs <= 0 || p.PingMs > maxPing) {
				continue
			}
			if len(countries) > 0 && !proxyCountryMatch(p, countries) {
				continue
			}
			list = append(list, p)
		}
		if r.URL.Query().Get("sort") == "ping" {
			// Exporta el vivo mas rapido primero (estilo xRisky: latencia
			// por proxy); los sin medir (0) van al final.
			sort.SliceStable(list, func(i, j int) bool {
				pi, pj := list[i].PingMs, list[j].PingMs
				if (pi > 0) != (pj > 0) {
					return pi > 0
				}
				return pi < pj
			})
		}
		a.mu.Unlock()
		// El tope se aplica sobre la lista ya ordenada: O(1) y fuera del lock.
		if maxOut > 0 && len(list) > maxOut {
			list = list[:maxOut]
		}
		var sb strings.Builder
		for _, p := range list {
			switch format {
			case "ob":
				sb.WriteString(p.OB())
			case "full":
				sb.WriteString(p.Tag())
			default:
				sb.WriteString(p.Plain())
			}
			sb.WriteString("\n")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// OB1/SilverBullet re-descargan la fuente al recargar; que ningun
		// intermediario sirva una copia vieja de la lista.
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(sb.String()))
	})

	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		// Refresca el estado desde disco: asi, tras un "vaciar todo"
		// (solo memoria) el /reload no solo recarga los .txt sino que
		// recupera tambien el analisis persistido en state.json.
		a.loadState()
		a.LoadProxies()
		_, total := a.counts()
		jsonOut(w, map[string]interface{}{"ok": true, "total": total})
	})

	// Gestor de la lista del panel: borrado y edicion de proxies.
	// keys/dead/alive reescriben los .txt de origen (sobreviven a
	// /reload y reinicios); scope "all" (vaciar todo) SOLO vacia la
	// memoria sin tocar ningun .txt ni el state.json.
	mux.HandleFunc("/proxy-remove", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		var req struct {
			Keys  []string `json:"keys"`
			Scope string   `json:"scope"` // dead | alive | all
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "JSON invalido"})
			return
		}
		switch req.Scope {
		case "", "dead", "alive", "all":
		default:
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "scope desconocido (dead|alive|all)"})
			return
		}
		keys := make(map[string]bool, len(req.Keys))
		for _, k := range req.Keys {
			if k = strings.TrimSpace(k); k != "" {
				keys[k] = true
			}
		}
		if len(keys) == 0 && req.Scope == "" {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "indica keys o scope"})
			return
		}
		removed, written, err := a.removeProxies(keys, req.Scope)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		_, total := a.counts()
		jsonOut(w, map[string]interface{}{
			"ok": true, "removed": removed, "total": total, "files": written,
			"persist": req.Scope != "all", // false = vaciar todo (solo memoria)
		})
	})

	mux.HandleFunc("/proxy-edit", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		var req struct {
			Key  string `json:"key"`
			Line string `json:"line"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "JSON invalido"})
			return
		}
		req.Key = strings.TrimSpace(req.Key)
		req.Line = strings.TrimSpace(req.Line)
		if req.Key == "" || req.Line == "" {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "key y line son obligatorios"})
			return
		}
		newKey, err := a.editProxy(req.Key, req.Line)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		_, total := a.counts()
		jsonOut(w, map[string]interface{}{"ok": true, "key": newKey, "total": total})
	})

	// Validacion e importacion de listas (panel web)
	mux.HandleFunc("/validate", a.importHandler(true))
	mux.HandleFunc("/import", a.importHandler(false))

	mux.HandleFunc("/set-strategy", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		s := r.URL.Query().Get("strategy")
		if s != "round-robin" && s != "random" && s != "sticky" && s != "fastest" {
			http.Error(w, "estrategia invalida", http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.strategy = s
		a.mu.Unlock()
		a.logf("estrategia cambiada a %s", s)
		jsonOut(w, map[string]interface{}{"ok": true, "strategy": s})
	})

	mux.HandleFunc("/set-check-mode", func(w http.ResponseWriter, r *http.Request) {
		// Modo del auto-check (se elige desde el panel):
		//   alive -> solo vivos + sin verificar (barato, por defecto)
		//   full  -> chequeo COMPLETO de la lista en cada ciclo
		if !a.allowPanel(w, r) {
			return
		}
		mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
		if mode != "alive" && mode != "full" && mode != "all" {
			http.Error(w, "modo invalido (alive|full)", http.StatusBadRequest)
			return
		}
		if mode == "all" {
			mode = "full"
		}
		a.mu.Lock()
		a.checkScope = mode
		a.checkAll = mode == "full"
		a.mu.Unlock()
		a.logf("modo de health-check: %s", mode)
		jsonOut(w, map[string]interface{}{"ok": true, "check_mode": mode})
	})

	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		// Ajustes del panel (pestana "Configuracion").
		// GET  -> ajustes vigentes.  POST -> aplica y guarda en settings.json.
		if r.Method == http.MethodGet {
			if !a.leerOK(w, r) {
				return
			}
			jsonOut(w, normSettings(a.currentSettings()))
			return
		}
		if !a.allowPanel(w, r) {
			return
		}
		var s appSettings
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "no se pudo leer el cuerpo", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			http.Error(w, "json invalido: "+err.Error(), http.StatusBadRequest)
			return
		}
		cur, err := a.applyAndSave(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.logf("ajustes aplicados: %s", cur.CheckMode)
		jsonOut(w, map[string]interface{}{"ok": true, "settings": cur})
	})

	mux.HandleFunc("/tls-test", func(w http.ResponseWriter, r *http.Request) {
		// Prueba de la cadena uTLS: motor externo -> nuestro gateway -> pool.
		// Devuelve la IP de salida, el perfil usado y si la IP es del pool
		// (o sea: si el motor salio por los proxies y no por tu IP real).
		if !a.allowPanel(w, r) {
			return
		}
		if a.tlsEngineURL == "" {
			jsonOut(w, map[string]interface{}{"ok": false, "error": "modo uTLS apagado (arranca con --tls-engine)"})
			return
		}
		target := r.URL.Query().Get("url")
		if target == "" {
			target = "https://api.ipify.org/"
		}
		proxy := a.engineProxyFor(r.URL.Query().Get("session"), r.URL.Query().Get("country"), false)
		rep, err := a.engineForward(tlsEngineRequest{
			URL:             target,
			Method:          "GET",
			Profile:         a.tlsEngineProfile,
			Proxy:           proxy,
			TimeoutMS:       int(a.tlsEngineTimeout / time.Millisecond),
			FollowRedirects: true,
		})
		if err != nil {
			a.mu.Lock()
			a.tlsEngineLast = err.Error()
			a.tlsEngineLastAt = time.Now().Unix()
			a.tlsEngineLastOK = false
			a.mu.Unlock()
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		body, _ := base64.StdEncoding.DecodeString(rep.BodyB64)
		ip := strings.TrimSpace(string(body))
		nuestra := a.getRealIP()
		viaPool := nuestra != "" && ip != "" && ip != nuestra
		resumen := fmt.Sprintf("%s | perfil %s | %s | %d ms", ip, rep.Profile, rep.Proto, rep.LatencyMS)
		a.mu.Lock()
		a.tlsEngineLast = resumen
		a.tlsEngineLastAt = time.Now().Unix()
		a.tlsEngineLastOK = true
		a.mu.Unlock()
		jsonOut(w, map[string]interface{}{
			"ok": true, "ip": ip, "profile": rep.Profile, "proto": rep.Proto,
			"latency_ms": rep.LatencyMS, "via_pool": viaPool, "our_ip": nuestra,
			"status": rep.Status, "summary": resumen,
		})
	})

	mux.HandleFunc("/tls-engine", func(w http.ResponseWriter, r *http.Request) {
		// Estado del motor TLS externo + aviso de exposicion en red.
		if !a.leerOK(w, r) {
			return
		}
		a.mu.Lock()
		out := map[string]interface{}{
			"configurado": a.tlsEngineURL != "",
			"url":         a.tlsEngineURL,
			"profile":     a.tlsEngineProfile,
			"upgrade":     a.tlsUpgrade,
			"aviso":       a.tlsEngineWarn,
			"ultimo":      a.tlsEngineLast,
			"ultimo_ok":   a.tlsEngineLastOK,
			"peticiones":  a.tlsEngineSessions,
		}
		a.mu.Unlock()
		if a.tlsEngineURL != "" {
			if ping, err := a.enginePing(); err == nil {
				out["motor_ok"] = true
				if e, ok := ping["engine"].(string); ok {
					out["motor"] = e
				}
				if p, ok := ping["profiles"].([]interface{}); ok {
					out["perfiles"] = len(p)
				}
			} else {
				out["motor_ok"] = false
				out["motor_error"] = err.Error()
			}
		}
		jsonOut(w, out)
	})

	mux.HandleFunc("/remeasure", func(w http.ResponseWriter, r *http.Request) {
		// Re-medir: invalida la cache de capacidades (TLS 1.3 / HTTP2 / DNS)
		// y el anonimato medido, para que el siguiente ciclo del health-check
		// vuelva a medir TODO el pool vivo (por ejemplo, tras cambiar el
		// juez de anonimato o si el pool ha cambiado mucho).
		if !a.allowPanel(w, r) {
			return
		}
		n := a.invalidateCaps()
		a.logf("re-medir: %d proxies quedan por medir en el proximo ciclo", n)
		jsonOut(w, map[string]interface{}{"ok": true, "pendientes": n})
	})

	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		// scope=alive: reanaliza solo vivos+sin verificar (los muertos
		// verificados se conservan); default = toda la lista.
		scope := r.URL.Query().Get("scope")
		if scope != "alive" {
			scope = "all"
		}
		go a.runChecksScope(scope)
		jsonOut(w, map[string]interface{}{"ok": true, "started": true, "scope": scope})
	})

	// Checker masivo (masscheck.go): listas/carpeta + cascada + geo + discord
	a.registerChecker(mux)

	// Activacion/exportacion por pais (activate.go): checker -> pool
	a.registerActivate(mux)

	// Auto-Fuentes (harvest.go): recoleccion continua + descubrimiento
	a.registerHarvest(mux)

	return mux
}
