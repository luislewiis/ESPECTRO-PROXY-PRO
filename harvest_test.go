package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestHarvester(t *testing.T, listBody string) (*Harvester, string) {
	t.Helper()
	dir := t.TempDir()
	proxies := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(proxies, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	app := NewApp([]string{proxies}, "round-robin", true, 0, "http://api.ipify.org/")
	app.checkTimeout = 2 * time.Second
	app.harvestCheck = false
	out := filepath.Join(dir, "harvested.txt")
	h := newHarvester(app, out, 15)
	h.allowLocal = true // tests: el httptest vive en 127.0.0.1

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(listBody))
	}))
	t.Cleanup(srv.Close)

	// una sola fuente apuntando al mirror local
	h.mu.Lock()
	h.src = []HarvestSource{{Name: "test", URL: srv.URL, Proto: "http", Enabled: true}}
	h.mu.Unlock()
	return h, out
}

func TestHarvestExtractFiltraBasura(t *testing.T) {
	body := `
1.2.3.4:8080
1.2.3.4:8080
10.0.0.5:3128
127.0.0.1:1080
192.168.1.1:8080
169.254.10.10:80
0.0.0.0:80
0.2.209.58:999
100.64.7.7:8080
192.0.2.44:8080
198.51.100.9:8080
203.0.113.5:8080
240.0.0.1:8080
8.8.8.8:99999
5.6.7.8:1080
# 9.9.9.9:80 comentado tambien entra (regex puro)
`
	got := harvestExtract(body, "socks5")
	if _, dup := got["socks5|1.2.3.4|8080|"]; !dup {
		t.Fatalf("deberia incluir 1.2.3.4:8080 (dedupe por Key)")
	}
	for _, bad := range []string{
		"socks5|10.0.0.5|3128|", "socks5|127.0.0.1|1080|",
		"socks5|192.168.1.1|8080|", "socks5|169.254.10.10|80|",
		"socks5|0.0.0.0|80|", "socks5|8.8.8.8|99999|",
		"socks5|0.2.209.58|999|", "socks5|100.64.7.7|8080|",
		"socks5|192.0.2.44|8080|", "socks5|198.51.100.9|8080|",
		"socks5|203.0.113.5|8080|", "socks5|240.0.0.1|8080|",
	} {
		if _, ok := got[bad]; ok {
			t.Fatalf("no deberia incluir %s", bad)
		}
	}
	if len(got) != 3 { // 1.2.3.4, 5.6.7.8, 9.9.9.9
		t.Fatalf("esperaba 3 unicos, obtuve %d", len(got))
	}
	// protocolo vacio -> http
	gotHTTP := harvestExtract("1.2.3.4:80", "")
	if _, ok := gotHTTP["http|1.2.3.4|80|"]; !ok {
		t.Fatalf("proto vacio debe caer a http")
	}
}

func TestHarvestBlockedHost(t *testing.T) {
	blocked := []string{"localhost", "127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.1.1", "0.0.0.0", "::1", "algo.local", ""}
	for _, hh := range blocked {
		if !harvestBlockedHost(hh) {
			t.Fatalf("%q deberia estar bloqueado", hh)
		}
	}
	if harvestBlockedHost("1.1.1.1") {
		t.Fatalf("una IP publica no debe bloquearse")
	}
}

func TestHarvestProtoFromName(t *testing.T) {
	cases := map[string]string{
		"https://x/socks5.txt": "socks5",
		"https://x/socks4.txt": "socks4",
		"https://x/http.txt":   "http",
		"https://x/all.txt":    "http",
	}
	for url, want := range cases {
		if got := harvestProtoFromName(url); got != want {
			t.Fatalf("%s -> %s (esperaba %s)", url, got, want)
		}
	}
}

func TestHarvestRunOnceYDedupe(t *testing.T) {
	list := "1.2.3.4:8080\n5.6.7.8:1080\n9.9.9.9:3128\n"
	h, out := newTestHarvester(t, list)

	if err := h.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1
	if lines != 3 {
		t.Fatalf("esperaba 3 lineas escritas, hay %d: %q", lines, string(data))
	}
	if !strings.Contains(string(data), "http://1.2.3.4:8080") {
		t.Fatalf("formato canonico esperado, hay %q", string(data))
	}
	alive, total := h.a.counts()
	if total != 3 || alive != 0 {
		t.Fatalf("pool esperado 3/0, hay %d/%d", alive, total)
	}
	// segunda pasada: mismas lineas -> 0 nuevas
	if err := h.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := h.Stats()
	if st.New != 0 {
		t.Fatalf("la segunda pasada no debe agregar nada, New=%d", st.New)
	}
	if st.Unique != 3 || st.Raw != 3 {
		t.Fatalf("stats esperadas 3/3, hay %d/%d", st.Unique, st.Raw)
	}
	if st.SourcesOK != 1 || st.SourcesFail != 0 {
		t.Fatalf("fuentes esperadas 1 OK / 0 fail, hay %d/%d", st.SourcesOK, st.SourcesFail)
	}
}

func TestHarvestFetchBloqueaPrivados(t *testing.T) {
	dir := t.TempDir()
	app := NewApp([]string{filepath.Join(dir, "proxies.txt")}, "round-robin", true, 0, "")
	h := newHarvester(app, filepath.Join(dir, "h.txt"), 15)
	// allowLocal=false (produccion)
	if _, err := h.fetch(context.Background(), "http://127.0.0.1:9/x.txt"); err == nil {
		t.Fatal("deberia bloquear loopback")
	}
	if _, err := h.fetch(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("deberia bloquear esquemas no http")
	}
	if err := h.SetSource(HarvestSource{URL: "ftp://x/y.txt", Enabled: true}); err == nil {
		t.Fatal("SetSource deberia rechazar ftp")
	}
	if err := h.SetSource(HarvestSource{URL: "http://10.0.0.1/l.txt", Enabled: true}); err == nil {
		t.Fatal("SetSource deberia rechazar host privado")
	}
}

func TestHarvestSourcesPersistenciaYMerge(t *testing.T) {
	dir := t.TempDir()
	app := NewApp([]string{filepath.Join(dir, "proxies.txt")}, "round-robin", true, 0, "")
	out := filepath.Join(dir, "harvested.txt")
	h := newHarvester(app, out, 15)

	// debe arrancar con el catalogo builtin
	if len(h.ListSources()) != len(harvestBuiltin) {
		t.Fatalf("esperaba %d builtins, hay %d", len(harvestBuiltin), len(h.ListSources()))
	}
	// deshabilitar un builtin + agregar una propia
	if err := h.SetSource(HarvestSource{URL: harvestBuiltin[0].URL, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err := h.SetSource(HarvestSource{Name: "mia", URL: "https://example.com/lista.txt", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	h.saveSources()
	if _, err := os.Stat(h.sourcesPath()); err != nil {
		t.Fatalf("no se guardo harvest_sources.json: %v", err)
	}
	// recargar (simula reinicio)
	h2 := newHarvester(app, out, 15)
	found := false
	for _, s := range h2.ListSources() {
		if s.URL == harvestBuiltin[0].URL && s.Enabled {
			t.Fatalf("el builtin deshabilitado volvio a enabled")
		}
		if s.URL == "https://example.com/lista.txt" {
			found = true
		}
	}
	if !found {
		t.Fatal("la fuente propia no sobrevivio al reinicio")
	}
	// quitar la propia
	if !h2.RemoveSource("https://example.com/lista.txt") {
		t.Fatal("RemoveSource deberia devolver true")
	}
	if h2.RemoveSource("https://example.com/lista.txt") {
		t.Fatal("RemoveSource deberia devolver false la segunda vez")
	}
}

func TestHarvestDiscoverEncuentraFuenteBuena(t *testing.T) {
	// mirror local con 6 proxies: pasa el umbral (>=5)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1:80\n2.2.2.2:81\n3.3.3.3:82\n4.4.4.4:83\n5.5.5.5:84\n6.6.6.6:85\n"))
	}))
	defer good.Close()
	// mirror que NO sirve proxies: no debe aceptarse
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hola mundo, sin proxies aqui\n"))
	}))
	defer bad.Close()
	// catalogo: lista de fuentes (como config.toml de otro scraper)
	catalogo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("lista buena: " + good.URL + "/socks5.txt\notra: " + bad.URL + "/vacia.txt\n"))
	}))
	defer catalogo.Close()

	dir := t.TempDir()
	app := NewApp([]string{filepath.Join(dir, "proxies.txt")}, "round-robin", true, 0, "")
	h := newHarvester(app, filepath.Join(dir, "harvested.txt"), 15)
	h.allowLocal = true
	h.discoverCatalogs = []string{catalogo.URL}

	n, err := h.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("esperaba 1 fuente descubierta, hay %d", n)
	}
	found := false
	for _, s := range h.ListSources() {
		if strings.HasPrefix(s.URL, good.URL) {
			found = true
			if !s.Enabled || s.Origin != "discovered" {
				t.Fatalf("la fuente descubierta debe quedar enabled/discovered: %+v", s)
			}
		}
		if strings.HasPrefix(s.URL, bad.URL) {
			t.Fatalf("una fuente sin proxies no debe agregarse")
		}
	}
	if !found {
		t.Fatal("no se agrego la fuente buena")
	}
}

func TestHarvestPurgeEliminaMuertos(t *testing.T) {
	dir := t.TempDir()
	proxies := filepath.Join(dir, "proxies.txt")
	_ = os.WriteFile(proxies, []byte(""), 0o644)
	out := filepath.Join(dir, "harvested.txt")
	_ = os.WriteFile(out, []byte("http://1.2.3.4:8080\nhttp://5.6.7.8:1080\n"), 0o644)

	app := NewApp([]string{proxies}, "round-robin", true, 0, "")
	h := newHarvester(app, out, 15)
	app.LoadProxies()
	if _, total := app.counts(); total != 2 {
		t.Fatalf("esperaba 2 cargados, hay %d", total)
	}
	// marcar 1.2.3.4 como muerto verificado
	app.mu.Lock()
	for _, p := range app.proxies {
		if p.Host == "1.2.3.4" {
			p.Checked = true
			p.Alive = false
		} else {
			p.Checked = true
			p.Alive = true
		}
	}
	app.mu.Unlock()

	removed, err := h.Purge()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("esperaba 1 purgado, hay %d", removed)
	}
	data, _ := os.ReadFile(out)
	if strings.Contains(string(data), "1.2.3.4") {
		t.Fatalf("el muerto sigue en el archivo: %q", string(data))
	}
	if !strings.Contains(string(data), "5.6.7.8") {
		t.Fatalf("el vivo se perdio: %q", string(data))
	}
}

func TestHarvestTopeLineas(t *testing.T) {
	list := "1.1.1.1:80\n2.2.2.2:81\n3.3.3.3:82\n4.4.4.4:83\n5.5.5.5:84\n"
	h, out := newTestHarvester(t, list)
	h.maxLines = 2

	if err := h.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1
	if n != 2 {
		t.Fatalf("el tope debe limitar a 2 lineas, hay %d: %q", n, string(data))
	}
	// segunda pasada: tope alcanzado -> nada nuevo
	if err := h.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := h.Stats(); st.New != 0 {
		t.Fatalf("con el tope alcanzado no debe agregar, New=%d", st.New)
	}
	if _, total := h.a.counts(); total != 2 {
		t.Fatalf("el pool debe tener 2, tiene %d", total)
	}
}

func TestHarvestDemoteReciennLlegados(t *testing.T) {
	list := "1.2.3.4:8080\n5.6.7.8:1080\n"
	h, _ := newTestHarvester(t, list)
	if err := h.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Politica "solo vivo y filtrado": nada recolectado llega a OB sin validar.
	alive, total := h.a.counts()
	if total != 2 || alive != 0 {
		t.Fatalf("esperaba 0 vivos / 2 totales, hay %d/%d", alive, total)
	}
	for _, p := range h.a.AliveList() {
		t.Fatalf("AliveList no debe tener sin verificar: %s", p.Tag())
	}
}

func TestHarvestBuiltinSano(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range harvestBuiltin {
		if !strings.HasPrefix(s.URL, "https://") {
			t.Fatalf("builtin no https: %s", s.URL)
		}
		if seen[s.URL] {
			t.Fatalf("builtin duplicado: %s", s.URL)
		}
		seen[s.URL] = true
		if s.Name == "" {
			t.Fatalf("builtin sin nombre: %s", s.URL)
		}
		switch s.Proto {
		case "", "http", "socks4", "socks5":
		default:
			t.Fatalf("proto invalido en %s: %q", s.Name, s.Proto)
		}
	}
	if len(harvestBuiltin) < 40 {
		t.Fatalf("el catalogo deberia tener 40+ fuentes, tiene %d", len(harvestBuiltin))
	}
}

func TestHarvestLooksLikeList(t *testing.T) {
	yes := []string{"https://x/socks5.txt", "https://x/l.csv", "https://api.x/get?type=http", "https://x/proxylist"}
	for _, u := range yes {
		if !harvestLooksLikeList(u) {
			t.Fatalf("%s deberia ser lista", u)
		}
	}
	no := []string{"https://x/logo.png", "https://x/README.md", "https://x/config.toml", "https://x/index.html"}
	for _, u := range no {
		if harvestLooksLikeList(u) {
			t.Fatalf("%s no deberia ser lista", u)
		}
	}
}

func TestHarvestGithubBlobToRaw(t *testing.T) {
	got := githubBlobToRaw("https://github.com/u/r/blob/main/socks5.txt")
	if got != "https://raw.githubusercontent.com/u/r/main/socks5.txt" {
		t.Fatalf("conversion mala: %s", got)
	}
	if githubBlobToRaw("https://example.com/x") != "" {
		t.Fatal("una URL que no es de github no debe convertirse")
	}
}
