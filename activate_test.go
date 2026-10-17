package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseCountriesYMatch: el filtro de pais acepta varios paises y es
// tolerante (ISO, ingles, espanol) tanto en los vivos del checker como en el
// pool. "all"/"todos"/"" = sin filtro.
func TestParseCountriesYMatch(t *testing.T) {
	for _, s := range []string{"", "all", "ALL", "todos", "*", " all ; todos "} {
		if got := parseCountries(s); len(got) != 0 {
			t.Errorf("parseCountries(%q) = %v, esperaba vacio", s, got)
		}
	}
	got := parseCountries("BR, us; reino unido|japan")
	if len(got) != 4 {
		t.Fatalf("parseCountries multi = %v", got)
	}
	if got[0] != "BR" || got[1] != "us" || got[2] != "reino unido" || got[3] != "japan" {
		t.Errorf("tokens: %v (los nombres compuestos no se parten)", got)
	}
	// sin comas: "BR US" se separa, "estados unidos" no
	if got := parseCountries("BR US"); len(got) != 2 {
		t.Errorf("parseCountries(\"BR US\") = %v, esperaba 2", got)
	}
	if got := parseCountries("estados unidos"); len(got) != 1 || got[0] != "estados unidos" {
		t.Errorf("parseCountries(\"estados unidos\") = %v, esperaba un nombre compuesto", got)
	}
	// nombres compuestos separados por comas
	if got := parseCountries("reino unido,japan"); len(got) != 2 {
		t.Errorf("parseCountries con comas = %v", got)
	}

	us := massHit{Line: "1.2.3.4:80", Proto: "http", Country: "United States", ISO: "US"}
	br := massHit{Line: "5.6.7.8:80", Proto: "http", Country: "Brazil", ISO: "BR"}
	sin := massHit{Line: "9.9.9.9:80", Proto: "http"}
	// sin filtro: todo pasa
	if !hitCountryMatch(sin, nil) || !hitCountryMatch(br, nil) {
		t.Error("sin filtro deben pasar todos los vivos")
	}
	// ISO, ingles y espanol
	for _, f := range [][]string{{"US"}, {"us"}, {"united states"}, {"estados unidos"}, {"eeuu"}, {"usa"}} {
		if !hitCountryMatch(us, f) {
			t.Errorf("hitCountryMatch(US) con %v = false", f)
		}
		if hitCountryMatch(br, f) {
			t.Errorf("hitCountryMatch(BR) con %v no deberia coincidir", f)
		}
	}
	for _, f := range [][]string{{"br"}, {"BRAZIL"}, {"brasil"}, parseCountries("BR,US")} {
		if !hitCountryMatch(br, f) {
			t.Errorf("hitCountryMatch(BR) con %v = false", f)
		}
	}
	// un vivo sin pais no coincide con un filtro (pero si pasa sin filtro)
	if hitCountryMatch(sin, []string{"BR"}) {
		t.Error("un vivo sin pais no debe coincidir con un filtro")
	}
	// multi-pais: cualquiera de los elegidos vale
	if !hitCountryMatch(br, []string{"japan", "brasil"}) {
		t.Error("multi-pais: brasil debe coincidir")
	}
}

// TestProxyCountryMatchISOExacto: el pool guarda ISO; un ISO no debe capturar
// por subcadena a otro pais ("au" -> Australia no captura "AT"/Austria).
func TestProxyCountryMatchISOExacto(t *testing.T) {
	au := &Proxy{Scheme: "http", Host: "1.2.3.4", Port: 80, Country: "AU"}
	at := &Proxy{Scheme: "http", Host: "5.6.7.8", Port: 80, Country: "AT"}
	us := &Proxy{Scheme: "http", Host: "9.9.9.9", Port: 80, Country: "US"}
	sin := &Proxy{Scheme: "http", Host: "8.8.8.8", Port: 80}
	if !proxyCountryMatch(au, []string{"au"}) || !proxyCountryMatch(au, []string{"AU"}) {
		t.Error("AU debe coincidir con au/AU")
	}
	if proxyCountryMatch(at, []string{"au"}) {
		t.Error("AT (Austria) no debe coincidir con au (Australia) por subcadena")
	}
	if !proxyCountryMatch(us, []string{"united states"}) || !proxyCountryMatch(us, []string{"eeuu"}) {
		t.Error("US debe coincidir con el nombre en ingles y en espanol")
	}
	if proxyCountryMatch(sin, []string{"us"}) {
		t.Error("un proxy sin pais no debe coincidir con un filtro")
	}
	if !proxyCountryMatch(sin, nil) {
		t.Error("sin filtro todo pasa")
	}
	// varios paises
	if !proxyCountryMatch(at, []string{"us", "AT"}) {
		t.Error("multi-pais en el pool")
	}
}

// activacionApp: app de prueba con el archivo de activados en un temporal y un
// pool propio (sin tocar proxies.txt/harvested.txt).
func activacionApp(t *testing.T, hits ...massHit) (*App, string) {
	t.Helper()
	a := newMassApp(t)
	dir := t.TempDir()
	a.activateFile = filepath.Join(dir, "activados.txt")
	a.mass = mkJob(hits...)
	return a, a.activateFile
}

// TestActivacionPorPais: activar por pais mete los vivos en el pool, VIVOS y
// con ping/pais medidos, y los persiste en activados.txt (nunca proxies.txt).
func TestActivacionPorPais(t *testing.T) {
	a, file := activacionApp(t,
		massHit{Line: "1.2.3.4:8080", Proto: "http", Ping: 120, Country: "United States", ISO: "US"},
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Ping: 90, Country: "Brazil", ISO: "BR"},
		massHit{Line: "user:pass@9.9.9.9:3128", Proto: "http", Ping: 200, Country: "Brazil", ISO: "BR"},
		massHit{Line: "7.7.7.7:1080", Proto: "socks4", Ping: 300, Country: "Germany", ISO: "DE"},
	)

	res, err := a.massActivate(massActivateCfg{countries: parseCountries("brasil")})
	if err != nil {
		t.Fatalf("massActivate: %v", err)
	}
	if res.Activated != 2 || res.New != 2 || res.Updated != 0 {
		t.Fatalf("res = %+v, esperaba 2 activados nuevos", res)
	}
	if res.Countries["BR"] != 2 {
		t.Errorf("desglose por pais = %v", res.Countries)
	}
	if res.PoolAlive != 2 || res.PoolTotal != 2 {
		t.Errorf("pool = %d/%d, esperaba 2/2", res.PoolAlive, res.PoolTotal)
	}
	if res.File != file {
		t.Errorf("archivo = %q, esperaba %q", res.File, file)
	}
	// pool: vivos y con pais ISO
	alive, total := a.counts()
	if alive != 2 || total != 2 {
		t.Fatalf("pool del gateway = %d vivos / %d totales", alive, total)
	}
	a.mu.Lock()
	byHost := map[string]*Proxy{}
	for _, p := range a.proxies {
		byHost[p.Host] = p
	}
	a.mu.Unlock()
	p := byHost["5.6.7.8"]
	if p == nil || !p.Alive || !p.Checked || p.PingMs != 90 || p.Country != "BR" {
		t.Fatalf("proxy activado = %+v", p)
	}
	if !hasFile(a.files, file) {
		t.Error("el archivo de activados debe quedar registrado en el pool (sobrevive a /reload)")
	}
	// archivo: lineas canonicas con esquema
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("leer activados: %v", err)
	}
	txt := string(data)
	if !strings.Contains(txt, "socks5://5.6.7.8:1080") || !strings.Contains(txt, "http://user:pass@9.9.9.9:3128") {
		t.Errorf("activados.txt = %q", txt)
	}
	if strings.Contains(txt, "1.2.3.4") || strings.Contains(txt, "7.7.7.7") {
		t.Errorf("activados.txt no debe tener los paises no elegidos: %q", txt)
	}
	// /proxy.txt (lo que consume OpenBullet) sirve el activado y respeta el pais
	mux := http.NewServeMux()
	a.registerChecker(mux)
	mux = a.APIMux(8080, "127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/proxy.txt?alive=1&country=BR&sort=ping", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	body := strings.TrimSpace(rr.Body.String())
	if !strings.Contains(body, "5.6.7.8:1080") || strings.Contains(body, "1.2.3.4") {
		t.Errorf("/proxy.txt?country=BR = %q", body)
	}
}

// TestActivacionSoloEstos: "solo estos" deja el pool unicamente con los paises
// elegidos (el resto se desactiva) y no desactiva lo recien activado.
func TestActivacionSoloEstos(t *testing.T) {
	a, _ := activacionApp(t,
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Ping: 90, Country: "Brazil", ISO: "BR"},
	)
	// pool previo: US y DE vivos, BR ya vivo
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "1.1.1.1", Port: 80, Country: "US", Alive: true},
		{Scheme: "http", Host: "2.2.2.2", Port: 80, Country: "DE", Alive: true},
		{Scheme: "http", Host: "3.3.3.3", Port: 80, Country: "BR", Alive: true},
		{Scheme: "http", Host: "4.4.4.4", Port: 80, Country: "BR", Alive: false},
	}
	res, err := a.massActivate(massActivateCfg{countries: parseCountries("br"), only: true})
	if err != nil {
		t.Fatalf("massActivate only: %v", err)
	}
	// El vivo del checker (5.6.7.8:1080 socks5) no estaba en el pool: 1 nuevo.
	// El BR del pool (3.3.3.3) no se toca y sigue vivo; US y DE se desactivan.
	if res.New != 1 || res.Updated != 0 {
		t.Errorf("res = %+v, esperaba 1 nuevo y 0 refrescados", res)
	}
	if res.PoolAlive != 2 || res.PoolTotal != 5 {
		t.Errorf("pool = %d/%d, esperaba 2 vivos de 5", res.PoolAlive, res.PoolTotal)
	}
	if res.Demoted != 2 {
		t.Errorf("desactivados = %d, esperaba 2 (US y DE)", res.Demoted)
	}
	alive, total := a.counts()
	if alive != 2 || total != 5 {
		t.Fatalf("pool tras 'solo estos' = %d/%d, esperaba 2 vivos de 5", alive, total)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.proxies {
		if p.Country == "BR" && p.Host != "4.4.4.4" && !p.Alive {
			t.Errorf("BR %s deberia seguir vivo", p.Host)
		}
		if (p.Country == "US" || p.Country == "DE") && p.Alive {
			t.Errorf("%s (%s) deberia estar desactivado", p.Host, p.Country)
		}
	}
}

// TestActivacionSinDuplicados: activar dos veces el mismo lote no duplica
// lineas en activados.txt ni proxies en el pool.
func TestActivacionSinDuplicados(t *testing.T) {
	a, file := activacionApp(t,
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Ping: 90, Country: "Brazil", ISO: "BR"},
	)
	if _, err := a.massActivate(massActivateCfg{}); err != nil {
		t.Fatalf("primera activacion: %v", err)
	}
	res, err := a.massActivate(massActivateCfg{})
	if err != nil {
		t.Fatalf("segunda activacion: %v", err)
	}
	if res.InFile != 0 || res.New != 0 || res.Updated != 1 {
		t.Errorf("segunda pasada = %+v, esperaba sin cambios en archivo/pool", res)
	}
	data, _ := os.ReadFile(file)
	if n := strings.Count(strings.TrimSpace(string(data)), "\n"); n != 0 {
		t.Errorf("activados.txt con %d lineas extra: %q", n, string(data))
	}
	_, total := a.counts()
	if total != 1 {
		t.Errorf("pool = %d, esperaba 1 sin duplicar", total)
	}
	// y sobrevive a un reload de listas (el estado en memoria manda)
	a.LoadProxies()
	alive, total2 := a.counts()
	if alive != 1 || total2 != 1 {
		t.Errorf("tras LoadProxies el activado debe seguir vivo: %d/%d", alive, total2)
	}
}

// TestActivacionFiltroProtoYSinDatos: filtro por protocolo y errores claros.
func TestActivacionFiltroProtoYSinDatos(t *testing.T) {
	a, _ := activacionApp(t,
		massHit{Line: "1.2.3.4:8080", Proto: "http", Country: "Brazil", ISO: "BR"},
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Country: "Brazil", ISO: "BR"},
	)
	res, err := a.massActivate(massActivateCfg{proto: "socks5"})
	if err != nil {
		t.Fatalf("activar solo socks5: %v", err)
	}
	if res.Activated != 1 || res.New != 1 {
		t.Errorf("activar solo socks5 = %+v", res)
	}
	a.mu.Lock()
	host := a.proxies[0].Host
	a.mu.Unlock()
	if host != "5.6.7.8" {
		t.Errorf("se activo %s, esperaba 5.6.7.8", host)
	}
	// ningun vivos con ese filtro
	if _, err := a.massActivate(massActivateCfg{countries: []string{"japan"}}); err == nil ||
		!strings.Contains(err.Error(), "coincide") {
		t.Errorf("filtro sin coincidencias = %v", err)
	}
	// sin job
	b := newMassApp(t)
	if _, err := b.massActivate(massActivateCfg{}); err == nil || !strings.Contains(err.Error(), "sin datos") {
		t.Errorf("sin job = %v", err)
	}
}

// TestExportPorPaisYFormatos: el exportador filtra por pais (varios, tolerante)
// y respeta protocolo y formato.
func TestExportPorPaisYFormatos(t *testing.T) {
	a := newMassApp(t)
	a.mass = mkJob(
		massHit{Line: "1.2.3.4:8080", Proto: "http", Ping: 120, Anon: "Elite", Country: "United States", ISO: "US"},
		massHit{Line: "user:pass@5.6.7.8:1080", Proto: "socks5", Ping: 90, Anon: "High", Country: "Brazil", ISO: "BR"},
		massHit{Line: "9.9.9.9:1080", Proto: "socks4", Ping: 300, Country: "Germany", ISO: "DE"},
	)
	casos := []struct {
		paises []string
		espera []string
	}{
		{nil, []string{"1.2.3.4:8080", "user:pass@5.6.7.8:1080", "9.9.9.9:1080"}},
		{parseCountries("brasil"), []string{"user:pass@5.6.7.8:1080"}},
		{parseCountries("BR,US"), []string{"1.2.3.4:8080", "user:pass@5.6.7.8:1080"}},
		{parseCountries("estados unidos"), []string{"1.2.3.4:8080"}},
		{parseCountries("all"), []string{"1.2.3.4:8080", "user:pass@5.6.7.8:1080", "9.9.9.9:1080"}},
	}
	for _, c := range casos {
		txt, ok := a.massExportSel("all", "plain", c.paises)
		if !ok {
			t.Fatalf("export %v sin datos", c.paises)
		}
		lines := lineasNonVacias(txt)
		if len(lines) != len(c.espera) {
			t.Fatalf("export %v = %q, esperaba %v", c.paises, txt, c.espera)
		}
		for i, want := range c.espera {
			if lines[i] != want {
				t.Errorf("export %v linea %d = %q, esperaba %q", c.paises, i, lines[i], want)
			}
		}
	}
	// protocolo
	if txt, _ := a.massExportSel("socks5", "plain", nil); lineasNonVacias(txt)[0] != "user:pass@5.6.7.8:1080" {
		t.Errorf("export socks5 = %q", txt)
	}
	// formatos
	if txt, _ := a.massExportSel("http", "proto", nil); txt != "http://1.2.3.4:8080\n" {
		t.Errorf("format proto = %q", txt)
	}
	if txt, _ := a.massExportSel("socks5", "ob", nil); txt != "2:5.6.7.8:1080:user:pass\n" {
		t.Errorf("format ob = %q", txt)
	}
	if txt, _ := a.massExportSel("socks4", "ob", nil); txt != "1:9.9.9.9:1080::\n" {
		t.Errorf("format ob socks4 = %q", txt)
	}
	if txt, _ := a.massExportSel("all", "csv", parseCountries("br")); !strings.Contains(txt, "user:pass@5.6.7.8:1080,socks5,90,High,Brazil,BR") {
		t.Errorf("format csv = %q", txt)
	}
	if txt, _ := a.massExportSel("all", "json", parseCountries("us,br")); !strings.HasPrefix(txt, "[") ||
		strings.Count(txt, `"line"`) != 2 {
		t.Errorf("format json = %q", txt)
	}
	if txt, _ := a.massExportSel("all", "full", parseCountries("br")); !strings.Contains(txt, "SOCKS5") ||
		!strings.Contains(txt, "Brazil") {
		t.Errorf("format full = %q", txt)
	}
	// compatibilidad: massExport (sin filtro)
	if txt, _ := a.massExport("all", "plain"); len(lineasNonVacias(txt)) != 3 {
		t.Errorf("massExport compat = %q", txt)
	}
}

// TestActivacionYExportEndpoint: los endpoints /checker/activate,
// /checker/export?countries= y /checker/countries (list con ISO).
func TestActivacionYExportEndpoint(t *testing.T) {
	a, file := activacionApp(t,
		massHit{Line: "1.2.3.4:8080", Proto: "http", Ping: 120, Country: "United States", ISO: "US"},
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Ping: 90, Country: "Brazil", ISO: "BR"},
	)
	mux := a.APIMux(8080, "127.0.0.1")
	post := func(body string, panel bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/checker/activate", strings.NewReader(body))
		if panel {
			req.Header.Set("X-GW-Panel", "1")
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	// sin cabecera de panel: 403
	if rr := post(`{}`, false); rr.Code != http.StatusForbidden {
		t.Errorf("sin X-GW-Panel = %d, esperaba 403", rr.Code)
	}
	// JSON invalido
	if rr := post(`{no-json}`, true); rr.Code != http.StatusBadRequest {
		t.Errorf("json invalido = %d", rr.Code)
	}
	// activar solo Brasil
	rr := post(`{"countries":"brasil"}`, true)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"activated":1`) ||
		!strings.Contains(rr.Body.String(), `"BR":1`) {
		t.Fatalf("activate = %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("no se creo activados.txt: %v", err)
	}
	// export filtrado por pais (lectura)
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	if rr := get("/checker/export?proto=all&format=plain&countries=brasil"); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Body.String(), "5.6.7.8:1080") || strings.Contains(rr.Body.String(), "1.2.3.4") {
		t.Errorf("export por pais = %d %q", rr.Code, rr.Body.String())
	}
	if rr := get("/checker/export?format=json"); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Header().Get("Content-Type"), "json") {
		t.Errorf("export json content-type = %q", rr.Header().Get("Content-Type"))
	}
	rrC := get("/checker/countries")
	if rrC.Code != http.StatusOK {
		t.Fatalf("/checker/countries = %d", rrC.Code)
	}
	var resp struct {
		Countries map[string]int `json:"countries"`
		List      []struct {
			Name  string `json:"name"`
			ISO   string `json:"iso"`
			Count int    `json:"count"`
		} `json:"list"`
	}
	if err := json.Unmarshal(rrC.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json de countries: %v (%s)", err, rrC.Body.String())
	}
	if len(resp.List) != 2 || resp.List[0].Count != 1 || resp.List[0].Name == "" {
		t.Fatalf("list de countries = %+v", resp.List)
	}
	iso := map[string]string{}
	for _, it := range resp.List {
		iso[it.Name] = it.ISO
	}
	if iso["Brazil"] != "BR" || iso["United States"] != "US" {
		t.Errorf("ISO por pais = %v", iso)
	}
}

func lineasNonVacias(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

func hasFile(files []string, path string) bool {
	for _, f := range files {
		if f == path {
			return true
		}
	}
	return false
}
