package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
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
	return statsJSON{
		Requests:  a.stats.Requests.Load(),
		Errors:    a.stats.Errors.Load(),
		BytesUp:   a.stats.BytesUp.Load(),
		BytesDown: a.stats.BytesDown.Load(),
		Alive:     alive,
		Dead:      total - alive,
		Unchecked: unchecked,
		Total:     total,
		Sessions:  sessions,
		Strategy:  strategy,
		Files:     files,
		Gateway:   gateway,
		CheckItv:  a.checkItv,
		StateFile: stateFile,
		Version:   version,
		Lic:       licDesc(),
	}
}

func (a *App) proxiesSnapshot() []proxyJSON {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]proxyJSON, 0, len(a.proxies))
	for _, p := range a.proxies {
		out = append(out, proxyJSON{
			Scheme: p.Scheme, Host: p.Host, Port: p.Port,
			Alive: p.Alive, Fails: p.Fails, Tag: p.Tag(),
			Key:     p.Key(),
			Checked: p.Checked, PingMs: p.PingMs, LastCheck: p.LastCheck,
		})
	}
	return out
}

func randomToken() string {
	b := make([]byte, 8)
	rand.Read(b)
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
	if r.Header.Get("X-API-Token") == a.apiToken || r.URL.Query().Get("token") == a.apiToken {
		a.authLim.clear(ip)
		return authOK
	}
	a.authLim.fail(ip)
	return authSinToken
}

// tokenOK valida el token opcional (--api-token) con rate-limit. Sin configurar, todo pasa.
func (a *App) tokenOK(r *http.Request) bool {
	return a.auth(r) == authOK
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
	gatewayBase := fmt.Sprintf("http://%s:%d", bind, httpPort)
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
	<code>/checker/hits</code>, <code>/checker/export</code> y <code>/checker/report</code>
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
			"proxy":     fmt.Sprintf("http://%s:clave@%s:%d", session, bind, httpPort),
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
		if offset+limit < end {
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
		list := a.AliveList()
		if len(list) == 0 {
			a.mu.Lock()
			list = append([]*Proxy(nil), a.proxies...)
			a.mu.Unlock()
		}
		if r.URL.Query().Get("sort") == "ping" {
			// Exporta el vivo mas rapido primero (estilo xRisky: latencia
			// por proxy); los sin medir (0) van al final.
			a.mu.Lock()
			sort.SliceStable(list, func(i, j int) bool {
				pi, pj := list[i].PingMs, list[j].PingMs
				if (pi > 0) != (pj > 0) {
					return pi > 0
				}
				return pi < pj
			})
			a.mu.Unlock()
		}
		var sb strings.Builder
		for _, p := range list {
			if format == "ob" {
				sb.WriteString(p.OB())
			} else {
				sb.WriteString(p.Plain())
			}
			sb.WriteString("\n")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
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
		if s != "round-robin" && s != "random" && s != "sticky" {
			http.Error(w, "estrategia invalida", http.StatusBadRequest)
			return
		}
		a.mu.Lock()
		a.strategy = s
		a.mu.Unlock()
		a.logf("estrategia cambiada a %s", s)
		jsonOut(w, map[string]interface{}{"ok": true, "strategy": s})
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

	return mux
}
