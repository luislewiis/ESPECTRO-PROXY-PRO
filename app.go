package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	Requests  atomic.Int64
	Errors    atomic.Int64
	BytesUp   atomic.Int64
	BytesDown atomic.Int64
}

// sessionInfo guarda el proxy asignado y su ultimo uso para expirar
// sesiones inactivas (evita crecimiento indefinido del mapa).
type sessionInfo struct {
	key      string
	lastSeen time.Time
}

var (
	maxSessions = 10000 // cap de sesiones simultaneas (si se llena y no expira nada, no se persiste)
	sessionTTL  = 10 * time.Minute
)

// Enfriamiento de proxies fallados (ver App.enfriar y pick): un proxy que
// falla en relay se aparta de la rotacion este tiempo (segundos). Equilibra
// dos cosas: no pagar su timeout en cada peticion (congela los bots) y
// volver a probarlo pronto (los proxies publicos se recuperan).
const (
	enfriamientoS   = 45
	minPoolEnfriar  = 8   // pools mas pequenos: no se enfria (probar todos)
	enfriarPurgaMax = 512 // purga de caducados solo al pasar este tamano
)

type App struct {
	mu       sync.Mutex
	proxies  []*Proxy
	sessions map[string]sessionInfo // session -> proxy asignado (sobrevive a LoadProxies)
	rr       int
	strategy string
	files    []string
	quiet    bool
	checkItv int
	testURL  string
	stats    Stats
	gateway  string

	// Indices O(1) (C2): por clave y de vivos. Se refrescan de forma perezosa
	// cuando cambia el slice (LoadProxies/tests) o bandera aliveDirty.
	byKey      map[string]*Proxy
	aliveIdx   []*Proxy
	idxFirst   *Proxy
	idxLen     int
	aliveDirty bool

	apiToken     string        // opcional: protege mutantes y lecturas sensibles si esta configurado
	authLim      *authLimiter  // rate-limit de fallos de token por IP (fuerza bruta)
	allowAnyPath bool          // escape de la jaula de rutas de /validate y /import
	idle         time.Duration // watchdog de inactividad en tuneles (RED-01, 0=off)

	// enfriar: proxies que acaban de fallar en relay (key -> unix sec hasta
	// el que se apartan de la rotacion). Sin esto, un proxy "vivo" segun el
	// health-check pero muerto en la practica se reelige cada pocas
	// peticiones y cada una paga el timeout completo (4s x hasta 4
	// reintentos = 16s congelados por bot; la corrida entera se "pausa").
	enfriar    map[string]int64 // key -> unix sec hasta el que se aparta de la rotacion
	sinEnfriar bool             // --no-cooldown: desactiva el enfriamiento (A/B y diagnostico)
	idxEnfriar int              // purgas pendientes (solo cuando el mapa crece)

	checkBatch int // proxies chequeados por ciclo (0 = todos)

	// Puertos propios: gwPort es el del gateway proxy (se detectan
	// auto-solicitudes: checkers de proxy tipo OpenBullet hacen "GET /" al
	// propio proxy y hay que responderles 200 en local, no relayarlos).
	// gwPorts = TODOS los puertos propios (multi-puerto, estilo DataImpulse
	// 80/8080/823): la auto-deteccion vale para cualquiera de ellos.
	gwPort  int
	gwPorts map[string]bool
	apiPort int

	// Health-check configurado (flags).
	checkTimeout time.Duration // timeout por intento de check
	checkRetries int           // reintentos extra antes de marcar muerto (estilo Espectro)
	checkConnect bool          // --check-connect: valida CONNECT (tunel) en vez de GET
	checkKey     string        // --success-key: exige este texto en el cuerpo (validacion de contenido)
	checkAll     bool          // auto-loop revisa tambien muertos (default: solo vivos+sin verificar)
	// GeoIP offline (geoip.go): base MaxMind DB local (GeoLite2/DbipLite
	// Country). Si esta, el pais del checker masivo sale de aqui (sin
	// llamadas al juez ni limites de tasa).
	geoDB *geoDB
	// Estado persistente (state.go): carga en arranque, guardado diferido.
	stateFile     string                // ruta explicita o "" = <lista1>.state.json
	stateDisabled bool                  // --no-state
	diskState     map[string]stateEntry // snapshot cargado de disco (una vez)
	stateTimer    *time.Timer
	stateTimerMu  sync.Mutex

	// Checker masivo (masscheck.go): job activo + configuracion.
	massMu       sync.Mutex
	mass         *massJob
	massBase     string // carpeta base de salidas ("Resultados"; tests la cambian)
	activateFile string // archivo propio de los activados por pais (activados.txt)

	logMu sync.Mutex
	logs  []string

	// Cache de http.Transport por upstream (Proxy.Key() -> *transporteEntry):
	// reutiliza conexiones keep-alive al mismo proxy en vez de crear un
	// Transport por peticion (ver transport.go).
	tp sync.Map

	// Auto-Fuentes (harvest.go): recolector continuo de proxies publicos.
	harv         *Harvester
	harvestCheck bool // drena health-check de los recien recolectados
}

func ExpandGlobs(args []string) []string {
	var out []string
	for _, a := range args {
		matches, err := filepath.Glob(a)
		if err != nil || len(matches) == 0 {
			out = append(out, a)
			continue
		}
		sort.Strings(matches)
		out = append(out, matches...)
	}
	return out
}

func NewApp(files []string, strategy string, quiet bool, checkItv int, testURL string) *App {
	return &App{
		sessions:     make(map[string]sessionInfo),
		enfriar:      make(map[string]int64),
		rr:           -1,
		strategy:     strategy,
		files:        files,
		quiet:        quiet,
		checkItv:     checkItv,
		testURL:      testURL,
		checkTimeout: 5 * time.Second,
		checkRetries: 1,
		massBase:     "Resultados",
		authLim:      newAuthLimiter(),
	}
}

func (a *App) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[gw] %s %s", time.Now().Format("15:04:05"), msg)
	fmt.Println(line)
	a.logMu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 500 {
		a.logs = a.logs[len(a.logs)-500:]
	}
	a.logMu.Unlock()
}

func (a *App) logTail(n int) []string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if len(a.logs) <= n {
		out := make([]string, len(a.logs))
		copy(out, a.logs)
		return out
	}
	out := make([]string, n)
	copy(out, a.logs[len(a.logs)-n:])
	return out
}

func (a *App) LoadProxies() int {
	// Copia de estado y de la lista de ficheros bajo lock (evita el data
	// race con RunChecks/markFail y con appendImported, sonda C1).
	// Prioridad de estado: memoria viva > disco (state.json) > default.
	type pstate struct {
		alive     bool
		fails     int
		checked   bool
		pingMs    int
		lastCheck int64
		country   string
	}
	old := make(map[string]pstate)
	a.mu.Lock()
	for _, p := range a.proxies {
		old[p.Key()] = pstate{p.Alive, p.Fails, p.Checked, p.PingMs, p.LastCheck, p.Country}
	}
	disk := a.diskState
	files := append([]string(nil), a.files...)
	a.mu.Unlock()

	var proxies []*Proxy
	seen := make(map[string]bool)
	skipped := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			a.logf("no se pudo leer %s: %v", f, err)
			continue
		}
		defScheme := schemeFromFileName(f)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimRight(line, "\r")
			p := ParseProxyDef(line, defScheme)
			if p == nil {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					skipped++
				}
				continue
			}
			if seen[p.Key()] {
				continue
			}
			seen[p.Key()] = true
			p.File = f
			if st, ok := old[p.Key()]; ok {
				p.Alive = st.alive
				p.Fails = st.fails
				p.Checked = st.checked
				p.PingMs = st.pingMs
				p.LastCheck = st.lastCheck
				p.Country = st.country
			} else if st, ok := disk[p.Key()]; ok {
				// Sin estado en memoria (reload total / arranque): usar disco.
				p.Alive = st.Alive
				p.Fails = st.Fails
				p.Checked = st.Checked
				p.PingMs = st.PingMs
				p.LastCheck = st.LastCheck
				p.Country = st.Country
			}
			proxies = append(proxies, p)
		}
	}
	a.mu.Lock()
	a.proxies = proxies
	n := len(proxies)
	a.mu.Unlock()
	msg := fmt.Sprintf("lista cargada: %d proxies desde %d archivo(s)", n, len(files))
	if skipped > 0 {
		msg += fmt.Sprintf(", %d lineas ignoradas", skipped)
	}
	a.logf("%s", msg)
	// El conjunto de claves cambio: persistir (poda las ausentes).
	a.scheduleStateSave()
	return skipped
}

func (a *App) AliveList() []*Proxy {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshIdxLocked()
	out := make([]*Proxy, len(a.aliveIdx))
	copy(out, a.aliveIdx)
	return out
}

// refreshIdxLocked reconstruye byKey/aliveIdx si el slice fue sustituido o si
// hubo transiciones Alive. Llamar con a.mu tomado.
func (a *App) refreshIdxLocked() {
	// Purga de enfriados caducados: solo cuando el mapa crece (pick se
	// ejecuta por request; la purga no puede costar en el camino caliente).
	if len(a.enfriar) > enfriarPurgaMax {
		now := time.Now().Unix()
		for k, t := range a.enfriar {
			if t <= now {
				delete(a.enfriar, k)
			}
		}
	}
	replaced := a.idxLen != len(a.proxies) ||
		(len(a.proxies) > 0 && a.idxFirst != a.proxies[0]) ||
		(len(a.proxies) == 0 && a.idxFirst != nil) ||
		a.byKey == nil
	if replaced {
		a.byKey = make(map[string]*Proxy, len(a.proxies))
		for _, p := range a.proxies {
			a.byKey[p.Key()] = p
		}
		if len(a.proxies) > 0 {
			a.idxFirst = a.proxies[0]
		} else {
			a.idxFirst = nil
		}
		a.idxLen = len(a.proxies)
		a.aliveDirty = true
	}
	if a.aliveDirty {
		a.aliveIdx = a.aliveIdx[:0]
		for _, p := range a.proxies {
			if p.Alive {
				a.aliveIdx = append(a.aliveIdx, p)
			}
		}
		a.aliveDirty = false
	}
}

func (a *App) counts() (alive, total int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshIdxLocked()
	return len(a.aliveIdx), len(a.proxies)
}

func (a *App) pick(session string, exclude map[*Proxy]bool) *Proxy {
	return a.pickWithCountry(session, "", exclude)
}

func (a *App) pickWithCountry(session, country string, exclude map[*Proxy]bool) *Proxy {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshIdxLocked()

	// base: vivos; si no hay vivos libres (o no hay vivos), todos los
	// no excluidos. exclude es pequeno (<=4 reintentos), los saltos son O(1).
	base := a.aliveIdx
	useAlive := len(base) > 0
	if useAlive && len(exclude) > 0 {
		free := false
		for _, p := range base {
			if !exclude[p] {
				free = true
				break
			}
		}
		if !free {
			base = a.proxies
			useAlive = false
		}
	} else if !useAlive {
		base = a.proxies
	}
	if len(base) == 0 {
		return nil
	}

	// Filtro de pais (P2.2): si viene especificado country y hay proxies que coincidan,
	// restringir la seleccion a ese pais. Acepta varios paises y nombres
	// tolerantes ("BR,US", "brasil", "united kingdom").
	if country != "" {
		wants := parseCountries(country)
		var matched []*Proxy
		for _, p := range base {
			if proxyCountryMatch(p, wants) {
				matched = append(matched, p)
			}
		}
		if len(matched) > 0 {
			base = matched
		}
	}

	// Enfriamiento: con un pool grande, los proxies que acaban de fallar se
	// apartan de la rotacion un rato (ver App.enfriar). Con pools pequenos
	// (< minPoolEnfriar) no se enfria: si solo hay 3 proxies hay que
	// probarlos todos o la corrida se quedaria sin salida (y los tests con
	// listas de 2 proxies siguen viendo los fallos esperados).
	if !a.sinEnfriar && len(base) >= minPoolEnfriar && len(a.enfriar) > 0 {
		now := time.Now().Unix()
		n := 0
		for _, p := range base {
			if t, ok := a.enfriar[p.Key()]; ok && t > now {
				continue
			}
			n++
		}
		if n > 0 && n < len(base) {
			free := make([]*Proxy, 0, n)
			for _, p := range base {
				if t, ok := a.enfriar[p.Key()]; ok && t > now {
					continue
				}
				free = append(free, p)
			}
			base = free
		}
	}

	// Sesion: hit O(1) via indice byKey (la clave Key() sobrevive a reload).
	if session != "" {
		if si, ok := a.sessions[session]; ok {
			if p := a.byKey[si.key]; p != nil && !exclude[p] && (!useAlive || p.Alive) {
				si.lastSeen = time.Now()
				a.sessions[session] = si
				return p
			}
		}
	}

	var chosen *Proxy
	if a.strategy == "fastest" {
		candidates := make([]*Proxy, 0, len(base))
		for _, p := range base {
			if !exclude[p] {
				candidates = append(candidates, p)
			}
		}
		if len(candidates) == 0 {
			return nil
		}
		if len(candidates) >= 8 {
			sort.SliceStable(candidates, func(i, j int) bool {
				pi, pj := candidates[i].PingMs, candidates[j].PingMs
				if pi > 0 && pj > 0 {
					return pi < pj
				}
				if pi > 0 {
					return true
				}
				return false
			})
			topN := len(candidates) / 4
			if topN < 2 {
				topN = 2
			}
			chosen = candidates[rand.Intn(topN)]
		} else {
			a.rr = (a.rr + 1) % len(candidates)
			chosen = candidates[a.rr]
		}
	} else {
		start := 0
		if a.strategy == "random" {
			start = rand.Intn(len(base))
		} else {
			a.rr = (a.rr + 1) % len(base)
			start = a.rr
		}
		for i := 0; i < len(base); i++ {
			idx := (start + i) % len(base)
			if !exclude[base[idx]] {
				chosen = base[idx]
				a.rr = idx
				break
			}
		}
	}
	if chosen == nil {
		return nil
	}
	if session != "" {
		now := time.Now()
		if _, exists := a.sessions[session]; !exists && len(a.sessions) >= maxSessions {
			a.sweepSessionsLocked(now)
			if len(a.sessions) >= maxSessions {
				// cap alcanzado: la peticion funciona pero no se persiste
				return chosen
			}
		}
		a.sessions[session] = sessionInfo{key: chosen.Key(), lastSeen: now}
	}
	return chosen
}

// sweepSessionsLocked elimina sesiones no vistas desde sessionTTL.
// Debe llamarse con a.mu tomado.
func (a *App) sweepSessionsLocked(now time.Time) {
	for k, si := range a.sessions {
		if now.Sub(si.lastSeen) > sessionTTL {
			delete(a.sessions, k)
		}
	}
}

// SweepSessions expira sesiones inactivas (exportado para tests).
func (a *App) SweepSessions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepSessionsLocked(time.Now())
}

// SessionSweeper corre en background y expira sesiones cada minuto.
func (a *App) SessionSweeper() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		a.SweepSessions()
	}
}

func (a *App) markFail(p *Proxy) {
	a.mu.Lock()
	p.Fails++
	p.Checked = true // el trafico por este proxy lo verifico (aun si muere)
	// Enfriamiento: apartar de la rotacion un rato (ver pick). El proxy
	// sigue vivo para el health-check; solo evita que cada bot vuelva a
	// pagar su timeout hasta que caduque.
	a.enfriar[p.Key()] = time.Now().Unix() + enfriamientoS
	died := false
	if p.Fails >= 3 && p.Alive {
		p.Alive = false
		a.aliveDirty = true
		key := p.Key()
		for k, v := range a.sessions {
			if v.key == key {
				delete(a.sessions, k)
			}
		}
		died = true
	}
	tag := p.Tag()
	a.mu.Unlock()
	if died {
		// logf fuera de a.mu: fmt.Println puede bloquear (A3)
		a.logf("proxy marcado muerto: %s (3 fallos)", tag)
	}
	a.scheduleStateSave()
}

func (a *App) markOK(p *Proxy) {
	a.mu.Lock()
	p.Fails = 0
	p.Checked = true // trafico correcto = verificado
	delete(a.enfriar, p.Key())
	a.mu.Unlock()
	a.scheduleStateSave()
}

func SessionFromHeaders(h map[string]string) string {
	v := h["proxy-authorization"]
	if len(v) > 6 && strings.EqualFold(v[:6], "basic ") {
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[6:]))
		if err == nil {
			s := string(dec)
			if i := strings.IndexByte(s, ':'); i >= 0 {
				s = s[:i]
			}
			// cap de 64: evita claves de sesion gigantes en el mapa (DoS de memoria)
			if s != "" && len(s) <= 64 {
				return s
			}
		}
	}
	return ""
}

// deleteSession purga una sesion sticky existente (P2.3 X-Proxy-Rotate: 1).
func (a *App) deleteSession(session string) {
	if session == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, session)
}

// parseUserParams desglosa nombres de usuario estilo OpenBullet y proveedores comerciales:
// user-session-12345, user-rotate, user-country-US, etc. (P2.2).
func parseUserParams(rawUser string) (session string, country string, rotate bool) {
	if rawUser == "" {
		return "", "", false
	}
	parts := strings.Split(rawUser, "-")
	base := parts[0]
	hasSub := false
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		switch {
		case strings.HasPrefix(p, "session"):
			hasSub = true
			session = strings.TrimPrefix(p, "session")
			if session == "" && i+1 < len(parts) {
				session = parts[i+1]
				i++
			}
		case p == "rotate":
			hasSub = true
			rotate = true
		case strings.HasPrefix(p, "country"):
			hasSub = true
			c := strings.TrimPrefix(p, "country")
			if c == "" && i+1 < len(parts) {
				c = parts[i+1]
				i++
			}
			country = strings.ToUpper(c)
		}
	}
	if !hasSub {
		return rawUser, "", false
	}
	if session == "" && !rotate {
		session = base
	}
	return session, country, rotate
}

// applyListChanges reescribe las listas en disco aplicando cambios por clave
// ("" = borrar la linea; otro valor = sustituirla). Escritura atomica
// (tmp + rename) para no dejar la lista a medias si se corta el proceso.
// Devuelve las listas realmente tocadas.
func (a *App) applyListChanges(edits map[string]map[string]string) []string {
	if len(edits) == 0 {
		return nil
	}
	var written []string
	for file, changes := range edits {
		data, err := os.ReadFile(file)
		if err != nil {
			a.logf("no se pudo leer %s: %v", filepath.Base(file), err)
			continue
		}
		def := schemeFromFileName(file)
		raw := strings.Split(string(data), "\n")
		out := make([]string, 0, len(raw))
		changed := 0
		for _, ln := range raw {
			p := ParseProxyDef(strings.TrimRight(ln, "\r"), def)
			if p == nil {
				out = append(out, ln) // comentarios y lineas en blanco se conservan
				continue
			}
			repl, ok := changes[p.Key()]
			if !ok {
				out = append(out, ln)
				continue
			}
			changed++
			if repl != "" {
				out = append(out, repl)
			}
		}
		if changed == 0 {
			continue
		}
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")), 0644); err != nil {
			a.logf("no se pudo reescribir %s: %v", filepath.Base(file), err)
			continue
		}
		if err := os.Rename(tmp, file); err != nil {
			os.Remove(tmp)
			a.logf("no se pudo reescribir %s: %v", filepath.Base(file), err)
			continue
		}
		written = append(written, file)
	}
	sort.Strings(written)
	return written
}

// removeProxies borra proxies de la lista EN MEMORIA. Con `keys` o con
// scope "dead"/"alive" ademas re-escribe los .txt de origen: el borrado
// SOBREVIVE a /reload y a reinicios. Con scope "all" (vaciar todo) solo
// se vacia la memoria: los .txt fuente y el state.json NO se tocan, y un
// /reload o un reinicio vuelven a cargarlos tal cual. `keys` son claves
// exactas (Proxy.Key()); "dead" = sin vivo, "alive" = vivos, "all" = todo.
// Devuelve (borrados, listas tocadas, error).
func (a *App) removeProxies(keys map[string]bool, scope string) (int, []string, error) {
	persist := scope != "all" // "all" (vaciar todo) = solo memoria, jamas escribe disco
	a.mu.Lock()
	drop := make(map[string]bool)
	edits := make(map[string]map[string]string)
	keep := make([]*Proxy, 0, len(a.proxies))
	matched := func(p *Proxy) bool {
		if keys[p.Key()] {
			return true
		}
		switch scope {
		case "dead":
			return !p.Alive
		case "alive":
			return p.Alive
		case "all":
			return true
		}
		return false
	}
	for _, p := range a.proxies {
		if !matched(p) {
			keep = append(keep, p)
			continue
		}
		drop[p.Key()] = true
		if persist && p.File != "" {
			if edits[p.File] == nil {
				edits[p.File] = map[string]string{}
			}
			edits[p.File][p.Key()] = ""
		}
	}
	removed := len(drop)
	if removed > 0 {
		a.proxies = keep
		a.aliveDirty = true
		a.rr = 0
	}
	a.mu.Unlock()
	if removed == 0 {
		return 0, nil, nil
	}
	written := []string{}
	if persist {
		written = a.applyListChanges(edits)
		a.scheduleStateSave()
		a.logf("borrados %d proxies de la lista (%d listas reescritas)", removed, len(written))
	} else {
		a.logf("lista vaciada en memoria (%d proxies); los .txt en disco NO se tocan (recarga o reinicio los trae de vuelta)", removed)
	}
	return removed, written, nil
}

// editProxy sustituye la linea de un proxy (clave `key`) por `newLine` en
// memoria y en su lista de origen. Si cambia host:puerto se reinicia su
// estado de analisis (el estado viejo ya no aplica). Devuelve la clave nueva.
func (a *App) editProxy(key, newLine string) (string, error) {
	a.mu.Lock()
	var old *Proxy
	for _, x := range a.proxies {
		if x.Key() == key {
			old = x
			break
		}
	}
	if old == nil {
		a.mu.Unlock()
		return "", fmt.Errorf("proxy no encontrado")
	}
	// esquema por defecto = el del proxy original: teclear "host:puerto"
	// en el prompt no convierte un socks5 en http.
	p := ParseProxyDef(newLine, old.Scheme)
	if p == nil {
		a.mu.Unlock()
		return "", fmt.Errorf("linea invalida: %s", whyInvalid(newLine))
	}
	newKey := p.Key()
	for _, x := range a.proxies {
		if x.Key() == newKey && x != old {
			a.mu.Unlock()
			return "", fmt.Errorf("ya existe otro proxy con %s", newKey)
		}
	}
	sameAddr := old.Addr() == p.Addr()
	file := old.File
	// preserva el estado si solo cambian credenciales (mismo host:puerto)
	p.File = file
	p.Alive, p.Checked, p.Fails = old.Alive, old.Checked, old.Fails
	p.PingMs, p.LastCheck = old.PingMs, old.LastCheck
	if !sameAddr {
		p.Alive, p.Checked, p.Fails = false, false, 0
		p.PingMs, p.LastCheck = 0, 0
	}
	for i, x := range a.proxies {
		if x == old {
			a.proxies[i] = p
			break
		}
	}
	a.aliveDirty = true
	a.mu.Unlock()

	if file != "" {
		written := a.applyListChanges(map[string]map[string]string{
			file: {key: p.LineaCanon()},
		})
		if len(written) == 0 {
			a.logf("aviso: %s no se pudo reescribir (solo cambio en memoria)", filepath.Base(file))
		}
	}
	// las sesiones apuntan a la clave antigua: se re-apuntan a la nueva
	a.mu.Lock()
	if newKey != key {
		for s, si := range a.sessions {
			if si.key == key {
				si.key = newKey
				a.sessions[s] = si
			}
		}
	}
	a.mu.Unlock()
	a.scheduleStateSave()
	a.logf("proxy editado: %s -> %s", key, p.Tag())
	return newKey, nil
}
