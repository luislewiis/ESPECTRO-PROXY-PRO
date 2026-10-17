package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Activacion por pais + exportacion por pais (checker <-> pool)
//
// El checker masivo sabe el pais de cada vivo (mmdb offline o juez). Ese dato
// se usa para dos funciones:
//
//   - ACTIVAR: pasa al pool del gateway los vivos del pais (o paises, o todos)
//     elegidos y los deja VIVOS con su ping y pais medidos, para que
//     OpenBullet los consuma al instante (/proxy.txt?alive=1). Se persisten en
//     su archivo propio (activados.txt): nunca se toca proxies.txt ni
//     harvested.txt. Con "solo estos" el resto del pool se desactiva.
//
//   - EXPORTAR: descarga los vivos del checker filtrando por pais(es),
//     protocolo y formato (plain, proto, full, ob, csv, json).
//
// El filtro de pais es TOLERANTE en las dos direcciones: ISO, ingles o
// espanol ("br" = "brazil" = "brasil"), y acepta varios paises separados por
// comas. Para valores ISO la comparacion del pool es exacta, de forma que
// "au" (Australia) no capture "Austria" por subcadena.
// ---------------------------------------------------------------------------

// activateOutDefault: archivo propio donde el checker guarda los activados.
const activateOutDefault = "activados.txt"

// countryKnownNames: alias y nombres canonicos conocidos (claves y valores de
// countryAlias). Sirve para no partir nombres compuestos por espacios
// ("estados unidos", "united states", "reino unido").
var countryKnownNames = func() map[string]bool {
	m := make(map[string]bool, len(countryAlias)*2)
	for k, v := range countryAlias {
		m[strings.ToLower(strings.TrimSpace(k))] = true
		m[strings.ToLower(strings.TrimSpace(v))] = true
	}
	return m
}()

// esNombrePaisConocido: el texto es un pais reconocido (aunque tenga espacios).
func esNombrePaisConocido(s string) bool {
	return countryKnownNames[strings.ToLower(strings.TrimSpace(s))]
}

// parseCountries: "all" / "todos" / "*" / "" -> nil (sin filtro). Acepta varios
// paises separados por comas, punto y coma, barras o saltos de linea; los
// espacios solo separan cuando no forman un nombre de pais conocido.
func parseCountries(s string) []string {
	add := func(tok string) []string {
		tok = strings.TrimSpace(tok)
		switch strings.ToLower(tok) {
		case "", "all", "todos", "todas", "*":
			return nil
		}
		return []string{tok}
	}
	var out []string
	chunks := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ',', ';', '|', '/', '\n', '\r', '\t':
			return true
		}
		return false
	})
	for _, c := range chunks {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, " ") || esNombrePaisConocido(c) {
			out = append(out, add(c)...)
			continue
		}
		// "BR US" (sin comas): no es un nombre compuesto conocido, se separa.
		for _, w := range strings.Fields(c) {
			out = append(out, add(w)...)
		}
	}
	return out
}

// hitCountryMatch: filtro multi-pais del checker (tolerante: ISO/ingles/espanol).
func hitCountryMatch(h massHit, wants []string) bool {
	if len(wants) == 0 {
		return true
	}
	for _, w := range wants {
		if countryMatches(w, h.Country, h.ISO) {
			return true
		}
	}
	return false
}

// proxyCountryMatch: filtro multi-pais del POOL (p.Country guarda el ISO del
// checker, o el nombre si no hubo ISO). Los valores ISO se comparan exactos
// (evita que "au" capture "Austria" por subcadena); los nombres usan el alias
// tolerante.
func proxyCountryMatch(p *Proxy, wants []string) bool {
	if len(wants) == 0 {
		return true
	}
	if p == nil {
		return false
	}
	code := strings.TrimSpace(p.Country)
	if code == "" {
		return false
	}
	canon := canonicalCountry(code)
	for _, w := range wants {
		t := strings.TrimSpace(w)
		if t == "" {
			continue
		}
		// ISO (2 letras): exacto contra el ISO guardado.
		if len([]rune(t)) == 2 {
			if strings.EqualFold(t, code) || canonicalCountry(t) == canon {
				return true
			}
			continue
		}
		wc := canonicalCountry(t)
		if wc == "" {
			continue
		}
		if canon == wc || strings.Contains(canon, wc) || strings.Contains(wc, canon) {
			return true
		}
	}
	return false
}

// activatePath: archivo propio de los activados.
func (a *App) activatePath() string {
	a.massMu.Lock()
	p := strings.TrimSpace(a.activateFile)
	a.massMu.Unlock()
	if p == "" {
		return activateOutDefault
	}
	return p
}

// ensurePoolFile registra un archivo propio en la lista del pool (idempotente):
// asi los activados se recargan en /reload y sobreviven al reinicio.
func (a *App) ensurePoolFile(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, f := range a.files {
		if f == path {
			return
		}
	}
	a.files = append(a.files, path)
}

// appendActivados agrega las lineas nuevas al archivo de activados (append,
// deduplicado por clave del pool). Devuelve cuantas lineas nuevas escribio.
func (a *App) appendActivados(path string, lines []string) (int, error) {
	if path == "" || len(lines) == 0 {
		return 0, nil
	}
	have := make(map[string]bool)
	if data, err := os.ReadFile(path); err == nil {
		for _, ln := range strings.Split(string(data), "\n") {
			if p := ParseProxyDef(ln, ""); p != nil {
				have[p.Key()] = true
			}
		}
	}
	var nuevos []string
	for _, ln := range lines {
		p := ParseProxyDef(ln, "")
		if p == nil || have[p.Key()] {
			continue
		}
		have[p.Key()] = true
		nuevos = append(nuevos, ln)
	}
	if len(nuevos) == 0 {
		return 0, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(nuevos, "\n") + "\n"); err != nil {
		return 0, err
	}
	return len(nuevos), nil
}

type massActivateCfg struct {
	countries []string // nil/vacio = todos
	proto     string   // "", "all", "http", "socks4", "socks5"
	only      bool     // true = desactiva del pool los que NO coincidan
}

type massActivateRes struct {
	Activated int            `json:"activated"` // vivos que coinciden con el filtro
	New       int            `json:"new"`       // proxies nuevos en el pool
	Updated   int            `json:"updated"`   // ya estaban en el pool
	Demoted   int            `json:"demoted"`   // desactivados por "solo estos"
	InFile    int            `json:"in_file"`   // lineas nuevas en activados.txt
	Countries map[string]int `json:"countries,omitempty"`
	File      string         `json:"file"`
	PoolAlive int            `json:"pool_alive"`
	PoolTotal int            `json:"pool_total"`
	At        string         `json:"at"`
}

// massActivate: activa en el pool los vivos del checker que coincidan con el
// pais/paises indicados (o todos). Ver cabecera del archivo.
func (a *App) massActivate(cfg massActivateCfg) (massActivateRes, error) {
	res := massActivateRes{Countries: map[string]int{}, At: time.Now().Format("2006-01-02 15:04:05")}
	j := a.massCurrent()
	if j == nil {
		return res, fmt.Errorf("sin datos (ejecuta un checker masivo primero)")
	}
	j.mu.Lock()
	hits := append([]massHit(nil), j.hits...)
	j.mu.Unlock()
	if len(hits) == 0 {
		return res, fmt.Errorf("el checker no tiene vivos todavia")
	}

	type pickInfo struct {
		line string
		ping int
		pais string // ISO (o nombre si no hubo ISO)
	}
	picks := make(map[string]pickInfo, len(hits))
	lines := make([]string, 0, len(hits))
	for _, h := range hits {
		if !hitCountryMatch(h, cfg.countries) {
			continue
		}
		if cfg.proto != "" && cfg.proto != "all" && !protoMatch(h.Proto, cfg.proto) {
			continue
		}
		line := strings.TrimSpace(h.Line)
		proto := strings.ToLower(strings.TrimSpace(h.Proto))
		if line == "" || proto == "" {
			continue
		}
		canon := proto + "://" + line
		p := ParseProxyDef(canon, "")
		if p == nil {
			continue
		}
		k := p.Key()
		if _, dup := picks[k]; dup {
			continue
		}
		pais := strings.ToUpper(strings.TrimSpace(h.ISO))
		if pais == "" {
			pais = h.Country
		}
		if pais == "" {
			pais = "Desconocido"
		}
		picks[k] = pickInfo{line: canon, ping: h.Ping, pais: pais}
		lines = append(lines, canon)
		res.Countries[pais]++
	}
	if len(picks) == 0 {
		return res, fmt.Errorf("ningun vivo coincide con el filtro")
	}

	path := a.activatePath()
	res.File = path
	nuevas, err := a.appendActivados(path, lines)
	if err != nil {
		return res, fmt.Errorf("no se pudo escribir %s: %v", path, err)
	}
	res.InFile = nuevas
	a.ensurePoolFile(path)

	now := time.Now().Unix()
	a.mu.Lock()
	a.refreshIdxLocked()
	for k, info := range picks {
		if pp := a.byKey[k]; pp != nil {
			// Ya estaba en el pool (p. ej. venia de proxies.txt o harvested):
			// se refresca y se deja VIVO con el ping/pais del checker.
			pp.Alive = true
			pp.Checked = true
			pp.Fails = 0
			pp.PingMs = info.ping
			pp.LastCheck = now
			pp.Country = info.pais
			res.Updated++
			continue
		}
		np := ParseProxyDef(info.line, "")
		if np == nil {
			continue
		}
		np.Alive = true
		np.Checked = true
		np.Fails = 0
		np.PingMs = info.ping
		np.LastCheck = now
		np.Country = info.pais
		np.File = path
		a.proxies = append(a.proxies, np)
		a.byKey[k] = np
		res.New++
	}
	res.Activated = len(picks)
	// "solo estos": el pool queda solo con los paises pedidos. Los activados
	// en esta pasada nunca se desactivan (aunque no tuvieran pais).
	if cfg.only && len(cfg.countries) > 0 {
		for _, pp := range a.proxies {
			if !pp.Alive {
				continue
			}
			if _, esActivado := picks[pp.Key()]; esActivado {
				continue
			}
			if proxyCountryMatch(pp, cfg.countries) {
				continue
			}
			pp.Alive = false
			pp.Checked = false
			res.Demoted++
		}
	}
	a.aliveDirty = true
	a.refreshIdxLocked()
	res.PoolAlive = len(a.aliveIdx)
	res.PoolTotal = len(a.proxies)
	a.mu.Unlock()

	a.scheduleStateSave()
	paises := ""
	if len(cfg.countries) > 0 {
		paises = " de " + strings.Join(cfg.countries, ", ")
	}
	a.logf("checker: activados %d vivos%s (nuevos %d, refrescados %d%s) -> pool %d/%d · archivo %s",
		res.Activated, paises, res.New, res.Updated,
		map[bool]string{true: fmt.Sprintf(", desactivados %d", res.Demoted), false: ""}[cfg.only],
		res.PoolAlive, res.PoolTotal, path)
	return res, nil
}

// obLineFromHit: linea en formato OpenBullet (tipo:host:puerto:user:pass).
func obLineFromHit(h massHit) string {
	p := ParseProxyDef(strings.TrimSpace(h.Line), "")
	if p == nil {
		return ""
	}
	if proto := strings.ToLower(strings.TrimSpace(h.Proto)); proto != "" {
		p.Scheme = proto
	}
	return p.OB()
}

// massExportSel: vivos del checker filtrados por protocolo y por paises.
// formatos: plain (ip:puerto), proto (esquema://ip:puerto), full (linea
// completa con ping/anon/pais), ob (tipo:ip:puerto:user:pass), csv, json.
func (a *App) massExportSel(proto, format string, countries []string) (string, bool) {
	j := a.massCurrent()
	if j == nil {
		return "", false
	}
	j.mu.Lock()
	hits := append([]massHit(nil), j.hits...)
	j.mu.Unlock()

	format = strings.ToLower(strings.TrimSpace(format))
	var out []massHit
	for _, h := range hits {
		if proto != "" && proto != "all" && !protoMatch(h.Proto, proto) {
			continue
		}
		if !hitCountryMatch(h, countries) {
			continue
		}
		out = append(out, h)
	}
	if format == "json" {
		b, _ := json.Marshal(out)
		return string(b) + "\n", true
	}
	var sb strings.Builder
	for _, h := range out {
		switch format {
		case "full":
			sb.WriteString(fmt.Sprintf("%-21s | %-5s | %4dms | %s | %s", h.Line,
				strings.ToUpper(h.Proto), h.Ping, h.Anon, h.Country))
		case "proto":
			sb.WriteString(h.Proto + "://" + h.Line)
		case "ob":
			sb.WriteString(obLineFromHit(h))
		case "csv":
			iso := h.ISO
			sb.WriteString(strings.Join([]string{h.Line, h.Proto, strconv.Itoa(h.Ping),
				h.Anon, h.Country, iso}, ","))
		default:
			sb.WriteString(h.Line)
		}
		sb.WriteString("\n")
	}
	return sb.String(), true
}

// massExport: compatibilidad (sin filtro de pais).
func (a *App) massExport(proto, format string) (string, bool) {
	return a.massExportSel(proto, format, nil)
}

// massCountryList: paises de los vivos con ISO y conteo (para el selector del
// panel), ordenado por conteo descendente.
func (a *App) massCountryList() []map[string]interface{} {
	j := a.massCurrent()
	if j == nil {
		return nil
	}
	j.mu.Lock()
	hits := append([]massHit(nil), j.hits...)
	j.mu.Unlock()
	type agg struct {
		name, iso string
		n         int
	}
	byName := map[string]*agg{}
	for _, h := range hits {
		name := h.Country
		if name == "" {
			name = "Desconocido"
		}
		a := byName[name]
		if a == nil {
			a = &agg{name: name, iso: h.ISO}
			byName[name] = a
		}
		if a.iso == "" && h.ISO != "" {
			a.iso = h.ISO
		}
		a.n++
	}
	list := make([]*agg, 0, len(byName))
	for _, a := range byName {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].name < list[j].name
	})
	out := make([]map[string]interface{}, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]interface{}{
			"name": a.name, "iso": a.iso, "count": a.n,
		})
	}
	return out
}

// registerActivate monta /checker/activate y amplia /checker/export y
// /checker/countries con el filtro por pais.
func (a *App) registerActivate(mux *http.ServeMux) {
	mux.HandleFunc("/checker/activate", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		var req struct {
			Countries string `json:"countries"`
			Proto     string `json:"proto"`
			Only      bool   `json:"only"`
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
		cfg := massActivateCfg{
			countries: parseCountries(req.Countries),
			proto:     strings.ToLower(strings.TrimSpace(req.Proto)),
			only:      req.Only,
		}
		switch cfg.proto {
		case "", "all", "http", "socks4", "socks5":
		default:
			cfg.proto = ""
		}
		res, err := a.massActivate(cfg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		jsonOut(w, map[string]interface{}{"ok": true, "result": res})
	})
}
