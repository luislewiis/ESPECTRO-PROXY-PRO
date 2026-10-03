package main

// Tests del Checker Masivo (fusion EspectroProxy -> ESPECTRO PROXY PRO).
// Verificacion: go test -count=1 . y go test -race -count=1 .

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

/* ---------------- parseMassLine ---------------- */

func TestParseMassLine(t *testing.T) {
	cases := []struct {
		in   string
		want string // esquema explicito ("" = cascada)
		host string
		port int
	}{
		{"1.2.3.4:8080", "", "1.2.3.4", 8080},
		{"# comentario", "", "", 0},
		{"", "", "", 0},
		{"socks5://1.2.3.4:1080", "socks5", "1.2.3.4", 1080},
		{"http://u:p@1.2.3.4:3128", "http", "1.2.3.4", 3128},
		{"user:pass@1.2.3.4:8080", "", "1.2.3.4", 8080},
		{"2:1.2.3.4:1080", "socks5", "1.2.3.4", 1080},
		{"0:1.2.3.4:8080::", "http", "1.2.3.4", 8080},
		{"1:1.2.3.4:1080", "socks4", "1.2.3.4", 1080},
		{"[2001:db8::1]:1080", "", "2001:db8::1", 1080},
		{"basura", "", "", 0},
		{"1.2.3.4:70000", "", "", 0},
	}
	for _, c := range cases {
		got := parseMassLine(c.in)
		if c.want == "" && c.host == "" {
			if got != nil {
				t.Errorf("parseMassLine(%q) = %v, esperaba nil", c.in, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("parseMassLine(%q) = nil, esperaba item", c.in)
			continue
		}
		if got.explicit != c.want || got.host != c.host || got.port != c.port {
			t.Errorf("parseMassLine(%q) = {host=%s port=%d expl=%s}, esperaba {host=%s port=%d expl=%s}",
				c.in, got.host, got.port, got.explicit, c.host, c.port, c.want)
		}
	}
	// credenciales conservadas en la forma normal (dedup/export)
	it := parseMassLine("user:pass@1.2.3.4:8080")
	if it == nil || it.plain != "user:pass@1.2.3.4:8080" {
		t.Errorf("plain de user:pass = %v", it)
	}
}

/* ---------------- helpers de test ---------------- */

// miniJuez: servidor local que devuelve un JSON estilo ip-api (geo) o un
// cuerpo de azenv (anonimato). Cierra al terminar el test.
func miniJuez(t *testing.T, body string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// miniProxyHTTP: escucha en 127.0.0.1 y responde a cualquier request
// "GET <url>" con 200 OK y el body indicado (para geo: el JSON del juez).
func miniProxyHTTP(t *testing.T, body string) (addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s",
					len(body), body)
			}(c)
		}
	}()
	return ln.Addr().String(), ln.Addr().(*net.TCPAddr).Port
}

// miniProxyMixto: un SOLO puerto que habla SOCKS5 (si el primer byte es 0x05)
// o HTTP (si no). Permite probar que la cascada prefiere SOCKS5 y que un
// esquema explicito "http" NO se deja enganar.
func miniProxyMixto(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMixed(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveMixed(c net.Conn) {
	defer c.Close()
	first := make([]byte, 1)
	if _, err := c.Read(first); err != nil {
		return
	}
	if first[0] == 0x05 {
		serveSOCKS5(c, first[0])
		return
	}
	// rama HTTP: first[0] ya consumido, sigue como proxy HTTP generico
	rest := make([]byte, 4096)
	if _, err := c.Read(rest); err != nil {
		return
	}
	io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
}

// miniSoloSOCKS5: un puerto que SOLO entiende SOCKS5 (cualquier otra cosa
// se corta) — sirve para demostrar que un esquema explicito "http" no se
// salta la cascada ni se cuela en un puerto ajeno.
func miniSoloSOCKS5(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				first := make([]byte, 1)
				if _, err := c.Read(first); err != nil {
					return
				}
				if first[0] != 0x05 {
					return // no es SOCKS5: corta (sin respuesta HTTP)
				}
				serveSOCKS5(c, first[0])
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// serveSOCKS5: handshake minimo (sin autenticacion) + CONNECT relay hacia
// el destino pedido (el juez local).
func serveSOCKS5(c net.Conn, firstByte byte) {
	_ = firstByte
	n := make([]byte, 1)
	if _, err := c.Read(n); err != nil {
		return
	}
	meth := make([]byte, int(n[0]))
	if _, err := io.ReadFull(c, meth); err != nil {
		return
	}
	c.Write([]byte{0x05, 0x00})
	// CONNECT [0x05, 0x01, 0x00, ATYP, ...]
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	var host string
	switch hdr[3] {
	case 0x01:
		ab := make([]byte, 4)
		if _, err := io.ReadFull(c, ab); err != nil {
			return
		}
		host = net.IP(ab).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		hb := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, hb); err != nil {
			return
		}
		host = string(hb)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	go io.Copy(up, c)
	io.Copy(c, up)
}

/* ---------------- cascada + esquema explicito ---------------- */

// TestMassCascadaPrefiereSocks5: linea sin esquema contra un puerto mixto
// (SOCKS5 y HTTP): la cascada debe elegir SOCKS5 (se prueba primero).
func TestMassCascadaPrefiereSocks5(t *testing.T) {
	port := miniProxyMixto(t)
	judge := miniJuez(t, "OK").URL
	it := parseMassLine(fmt.Sprintf("127.0.0.1:%d", port))
	if it == nil {
		t.Fatal("parse fallo")
	}
	proto, _, _, _ := massProbe(it, judge, 2*time.Second, false)
	if proto != "socks5" {
		t.Fatalf("cascada eligio %q, esperaba socks5", proto)
	}
}

// TestMassEsquemaExplicitoSeRespeta: con esquema "http" explicito NO se
// debe probar el SOCKS5 que hay en el mismo puerto (muerto) mientras que
// una linea sin esquema (cascada) si lo encuentra vivo.
func TestMassEsquemaExplicitoSeRespeta(t *testing.T) {
	port := miniProxyMixto(t)
	judge := miniJuez(t, "OK").URL

	explicito := parseMassLine(fmt.Sprintf("http://127.0.0.1:%d", port))
	if explicito == nil {
		t.Fatal("parse fallo")
	}
	// el mock mixto SOCKS habla socks5 y HTTP; con esquema explicito http
	// se manda un GET y el mock responde 200 -> vivo. Para probar el
	// "respeto" usamos un mock solo-socks5 (no entiende HTTP).
	onlySocks := miniSoloSOCKS5(t)
	linea := fmt.Sprintf("127.0.0.1:%d", onlySocks)
	conEsquema := parseMassLine("http://" + linea)
	if conEsquema == nil {
		t.Fatal("parse explicito fallo")
	}
	if proto, _, _, _ := massProbe(conEsquema, judge, 1200*time.Millisecond, false); proto != "" {
		t.Errorf("esquema explicito http contra puerto solo-socks5 devolvio %q, esperaba muerto", proto)
	}
	sinEsquema := parseMassLine(linea)
	proto, _, _, _ := massProbe(sinEsquema, judge, 2*time.Second, false)
	if proto != "socks5" {
		t.Errorf("cascada contra solo-socks5 devolvio %q, esperaba socks5", proto)
	}
	_ = port
}

/* ---------------- geo / anonimato / juez ---------------- */

func TestExtractCountryYNormalize(t *testing.T) {
	if got := extractCountry(`{"status":"success","country":"Spain","query":"1.2.3.4"}`); got != "Spain" {
		t.Errorf("extractCountry = %q", got)
	}
	if got := extractCountry("sin pais aqui"); got != "" {
		t.Errorf("extractCountry sin match = %q", got)
	}
	dict := map[string]string{"brazil": "brasil", "BR": "brasil", "japan": "japón", "us": "estados unidos"}
	for in, want := range dict {
		if got := normalizeCountryInput(in); got != want {
			t.Errorf("normalizeCountryInput(%q) = %q, esperaba %q", in, got, want)
		}
	}
	if normalizeCountryInput("  BrAsIl ") != "brasil" {
		t.Errorf("normalizeCountryInput debe recortar y pasar a minusculas")
	}
}

func TestAnonLevel(t *testing.T) {
	elites := "REMOTE_ADDR=1.2.3.4 HTTP_HOST=azenv.net"
	if got := anonLevel("socks5", elites); got != "Elite" {
		t.Errorf("socks sin headers anonimos = %q, esperaba Elite", got)
	}
	if got := anonLevel("http", "pagina simple sin marcas"); got != "Unknown" {
		t.Errorf("http sin marcas = %q, esperaba Unknown", got)
	}
	if got := anonLevel("http", "REQUEST_METHOD=GET HTTP_X_FORWARDED_FOR=9.9.9.9"); got != "Transparent" {
		t.Errorf("http con XFF = %q, esperaba Transparent", got)
	}
	if got := anonLevel("http", "REQUEST_METHOD=GET HTTP_VIA=1.1 proxy"); got != "Anonymous" {
		t.Errorf("http con VIA = %q, esperaba Anonymous", got)
	}
}

func TestDynamicTimeout(t *testing.T) {
	judge := miniJuez(t, "OK").URL
	ping, to := dynamicTimeout(judge)
	if ping < 0 || ping > 4999 {
		t.Errorf("ping inesperado: %d", ping)
	}
	if to != 2500 && to != 4000 && to != 6000 {
		t.Errorf("timeout %d fuera de {2500,4000,6000}", to)
	}
	// juez caido -> 5000ms y ping 999
	_, to2 := dynamicTimeout("http://127.0.0.1:1/")
	if to2 != 5000 {
		t.Errorf("juez caido: timeout %d, esperaba 5000", to2)
	}
}

func TestMassJudge(t *testing.T) {
	if got := massJudge("http://mio.test/", true); got != "http://mio.test/" {
		t.Errorf("custom debe tener prioridad, got %q", got)
	}
	if got := massJudge("", true); got != "http://ip-api.com/json?lang=es" {
		t.Errorf("geo debe forzar ip-api, got %q", got)
	}
	got := massJudge("", false)
	if !strings.HasPrefix(got, "http") || strings.Contains(got, "ip-api") {
		t.Errorf("default debe ser un juez ofuscado, got %q", got)
	}
}

/* ---------------- ciclo de vida del job ---------------- */

func newMassApp(t *testing.T) *App {
	t.Helper()
	a := NewApp(nil, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.allowAnyPath = true
	a.massBase = t.TempDir()
	return a
}

func waitMassDone(t *testing.T, a *App, d time.Duration) massStatusJSON {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st := a.massStatusJSON()
		if st.Done {
			return st
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("el job no termino en %s: %+v", d, a.massStatusJSON())
	return massStatusJSON{}
}

// TestMassJobMuertosOffline: listas de puertos cerrados; el job termina con
// todos marcados muertos y sin vivos (funciona sin red externa).
func TestMassJobMuertosOffline(t *testing.T) {
	a := newMassApp(t)
	if _, err := a.massStart(massCfg{
		text:      "127.0.0.1:1\n127.0.0.1:2\nsocks5://127.0.0.1:3\n",
		timeoutMs: 300,
		threads:   4,
		skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	st := waitMassDone(t, a, 20*time.Second)
	if st.Total != 3 || st.Tested != 3 {
		t.Errorf("total/tested = %d/%d, esperaba 3/3", st.Total, st.Tested)
	}
	if st.Alive != 0 || st.Bad != 3 {
		t.Errorf("alive/bad = %d/%d, esperaba 0/3", st.Alive, st.Bad)
	}
	if st.Error != "" {
		t.Errorf("error inesperado: %s", st.Error)
	}
	// export/report responden aunque no haya vivos
	if txt, ok := a.massExport("all", "full"); !ok || txt != "" {
		t.Errorf("export sin vivos = %q ok=%v", txt, ok)
	}
	var rep map[string]interface{}
	if err := json.Unmarshal(a.massCurrent().reportBytes(), &rep); err != nil {
		(t.Fatalf("report invalido: %v", err))
	}
	if rep["TotalEvaluados"].(float64) != 3 {
		t.Errorf("report TotalEvaluados = %v", rep["TotalEvaluados"])
	}
	// carpeta de sesion creada bajo massBase
	entries, err := os.ReadDir(a.massBase)
	if err != nil || len(entries) != 1 {
		t.Fatalf("carpeta de sesion: entries=%d err=%v", len(entries), err)
	}
	if _, err := os.Stat(filepath.Join(a.massBase, entries[0].Name(), "Report.json")); err != nil {
		t.Errorf("falta Report.json: %v", err)
	}
	for _, f := range []string{"Live_HTTP.txt", "Live_SOCKS4.txt", "Live_SOCKS5.txt"} {
		if _, err := os.Stat(filepath.Join(a.massBase, entries[0].Name(), f)); err != nil {
			t.Errorf("falta %s: %v", f, err)
		}
	}
}

// TestMassVivoYFiltroPais: un proxy vivo contra un juez local; con filtro de
// pais que NO coincide se descarta silenciosamente; al coincidir, cuenta.
func TestMassVivoYFiltroPais(t *testing.T) {
	a := newMassApp(t)
	_, port := miniProxyHTTP(t, `{"country":"Spain"}`)
	judge := miniJuez(t, `{"country":"Spain"}`).URL
	line := fmt.Sprintf("127.0.0.1:%d", port)

	// 1) filtro de pais distinto -> todo filtrado
	if _, err := a.massStart(massCfg{
		text: line, judge: judge, country: "brasil",
		threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	st := waitMassDone(t, a, 20*time.Second)
	if st.Alive != 0 || st.Filtered != 1 || st.Tested != 1 {
		t.Fatalf("filtro brasil: alive=%d filtered=%d tested=%d (esperaba 0/1/1)",
			st.Alive, st.Filtered, st.Tested)
	}

	// 2) pais que coincide -> hit con pais y anonimato
	if _, err := a.massStart(massCfg{
		text: line, judge: judge, country: "Spain",
		threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart 2: %v", err)
	}
	st2 := waitMassDone(t, a, 20*time.Second)
	if st2.Alive != 1 || st2.HTTP != 1 || st2.Filtered != 0 {
		t.Fatalf("filtro Spain: alive=%d http=%d filtered=%d (esperaba 1/1/0)",
			st2.Alive, st2.HTTP, st2.Filtered)
	}
	hits := a.massHits("http", 10)
	if len(hits) != 1 || hits[0].Country != "Spain" || hits[0].Anon == "" {
		t.Fatalf("hits = %+v", hits)
	}
	countries := a.massCountries()
	if countries["Spain"] != 1 {
		t.Errorf("countries = %v", countries)
	}
	// export full estilo Espectro
	txt, ok := a.massExport("http", "full")
	if !ok || !strings.Contains(txt, "127.0.0.1:") || !strings.Contains(txt, "Spain") {
		t.Errorf("export full = %q", txt)
	}
	// carpeta por pais creada
	base := a.massCurrent().statusJSON().OutDir
	paises := filepath.Join(base, "Paises Validados")
	if _, err := os.Stat(filepath.Join(paises, "Spain.txt")); err != nil {
		t.Errorf("falta Spain.txt: %v", err)
	}
}

// TestMassCarpetaDedup: recorre carpeta completa y descarta duplicados
// entre archivos (mismo filtro que Espectro).
func TestMassCarpetaDedup(t *testing.T) {
	a := newMassApp(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("127.0.0.1:1\n127.0.0.1:2\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("127.0.0.1:2\n127.0.0.1:3\n# x\n"), 0644)
	os.WriteFile(filepath.Join(dir, "ignorada.md"), []byte("127.0.0.1:4\n"), 0644)
	if _, err := a.massStart(massCfg{
		path: dir, timeoutMs: 200, threads: 4, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	st := waitMassDone(t, a, 20*time.Second)
	if st.Total != 3 || st.Tested != 3 {
		t.Errorf("total/tested = %d/%d, esperaba 3/3 (dedup entre a.txt y b.txt, .md ignorado)",
			st.Total, st.Tested)
	}
}

// TestMassCancel: cancelar un job en marcha termina limpio (done+cancelled).
func TestMassCancel(t *testing.T) {
	a := newMassApp(t)
	var lines []string
	for i := 0; i < 400; i++ {
		lines = append(lines, fmt.Sprintf("127.0.0.1:%d", 20000+i))
	}
	if _, err := a.massStart(massCfg{
		text: strings.Join(lines, "\n"), timeoutMs: 800,
		threads: 2, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	j := a.massCurrent()
	if j == nil {
		t.Fatal("job no registrado")
	}
	time.Sleep(40 * time.Millisecond)
	if !j.cancel() {
		// puede haber terminado demasiado rapido; no es fallo del sistema
		t.Log("job termino antes del cancel")
	}
	st := waitMassDone(t, a, 20*time.Second)
	if !st.Cancelled && st.Tested < st.Total {
		t.Errorf("job parado sin marcarse cancelado: %+v", st)
	}
	// tras cancelar, un segundo job puede arrancar
	if _, err := a.massStart(massCfg{
		text: "127.0.0.1:1", timeoutMs: 200, threads: 1, skipLocal: false,
	}); err != nil {
		t.Errorf("nuevo job tras cancel: %v", err)
	}
	waitMassDone(t, a, 20*time.Second)
}

// TestMassShutdownSalvavidas: Ctrl+C con checker en marcha cancela el job y
// ESPERA a finish() (flush de buffers + Report.json en disco) antes de
// devolver true. Contra un listener que acepta y nunca responde, el job
// sigue vivo cuando llega el shutdown.
func TestMassShutdownSalvavidas(t *testing.T) {
	a := newMassApp(t)

	// sin job activo -> true inmediato
	if !a.massShutdown(0) {
		t.Fatal("massShutdown sin job debio devolver true")
	}

	// listener que acepta conexiones y nunca responde (checks se cuelgan)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	if _, err := a.massStart(massCfg{
		text:      "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		timeoutMs: 1000, threads: 1, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	if !a.massShutdown(30 * time.Second) {
		t.Fatalf("massShutdown devolvio false (no llego a guardar): %+v", a.massStatusJSON())
	}
	st := waitMassDone(t, a, time.Second)
	if !st.Cancelled {
		t.Error("el job interrumpido por shutdown debe quedar Cancelled")
	}
	// Report.json en disco (finish() lo escribio antes de salir)
	entries, err := os.ReadDir(a.massBase)
	if err != nil || len(entries) != 1 {
		t.Fatalf("carpeta de sesion: entries=%d err=%v", len(entries), err)
	}
	if _, err := os.Stat(filepath.Join(a.massBase, entries[0].Name(), "Report.json")); err != nil {
		t.Errorf("falta Report.json tras el salvavidas: %v", err)
	}
}

// TestMassUnicoJob: dos starts solapados -> el segundo recibe error.
func TestMassUnicoJob(t *testing.T) {
	a := newMassApp(t)
	var lines []string
	for i := 0; i < 400; i++ {
		lines = append(lines, fmt.Sprintf("127.0.0.1:%d", 30000+i))
	}
	if _, err := a.massStart(massCfg{
		text: strings.Join(lines, "\n"), timeoutMs: 800,
		threads: 1, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	if _, err := a.massStart(massCfg{
		text: "127.0.0.1:1", timeoutMs: 200, skipLocal: false,
	}); err == nil {
		t.Error("segundo start debio fallar (job en curso)")
	}
	a.massCurrent().cancel()
	waitMassDone(t, a, 20*time.Second)
}

/* ---------------- borrado de vivos (removeHits / /checker/remove) ---------------- */

// mkJob monta un job solo con hits en memoria (sin red ni ficheros).
func mkJob(hits ...massHit) *massJob {
	j := &massJob{done: true}
	for _, h := range hits {
		j.hits = append(j.hits, h)
		switch h.Proto {
		case "http":
			j.nHTTP.Add(1)
		case "socks4", "socks4a":
			j.nS4.Add(1)
		case "socks5":
			j.nS5.Add(1)
		}
	}
	return j
}

// TestRemoveHitsLine: borrar por linea exacta afecta solo a esa fila y
// descuenta el contador del protocolo correspondiente.
func TestRemoveHitsLine(t *testing.T) {
	j := mkJob(
		massHit{Line: "1.2.3.4:8080", Proto: "http", Ping: 100},
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Ping: 120},
		massHit{Line: "9.9.9.9:1080", Proto: "socks4", Ping: 90},
	)
	n, rest := j.removeHits("1.2.3.4:8080", "")
	if n != 1 || rest != 2 {
		t.Fatalf("removeHits(line) = %d borrados / %d restantes, esperaba 1/2", n, rest)
	}
	st := j.statusJSON()
	if st.Alive != 2 || st.HTTP != 0 || st.Socks4 != 1 || st.Socks5 != 1 {
		t.Errorf("contadores tras borrar http: %+v", st)
	}
	if st.Removed != 1 || st.Hits != 2 {
		t.Errorf("removed/hits = %d/%d, esperaba 1/2", st.Removed, st.Hits)
	}
	if n, rest := j.removeHits("1.1.1.1:1", ""); n != 0 || rest != 2 {
		t.Errorf("linea inexistente borró algo: n=%d rest=%d", n, rest)
	}
	if got := len(a_hits(t, j)); got != 2 {
		t.Errorf("hits en memoria = %d, esperaba 2", got)
	}
}

// TestRemoveProtoDecrementaContadores: borrar por protocolo deja a cero el
// contador de ese protocolo (socks4a cuenta como socks4) y no toca al resto.
func TestRemoveProtoDecrementaContadores(t *testing.T) {
	j := mkJob(
		massHit{Line: "1.2.3.4:8080", Proto: "http"},
		massHit{Line: "2.2.2.2:1080", Proto: "socks4a"},
		massHit{Line: "3.3.3.3:1080", Proto: "socks5"},
	)
	n, rest := j.removeHits("", "socks4")
	if n != 1 || rest != 2 {
		t.Fatalf("removeHits(socks4) = %d/%d, esperaba 1/2", n, rest)
	}
	st := j.statusJSON()
	if st.Socks4 != 0 || st.HTTP != 1 || st.Socks5 != 1 || st.Alive != 2 {
		t.Errorf("contadores tras borrar socks4 (socks4a incluido): %+v", st)
	}
	if a_hitsN(t, j, "socks4") != 0 {
		t.Error("siguen quedando hits socks4")
	}
	n, rest = j.removeHits("", "all")
	if n != 2 || rest != 0 {
		t.Errorf("vaciar todo = %d/%d, esperaba 2/0", n, rest)
	}
	st = j.statusJSON()
	if st.Alive != 0 || st.Hits != 0 || st.Removed != 3 {
		t.Errorf("tras vaciar: %+v", st)
	}
	// proto desconocido no borra nada
	if n, _ := j.removeHits("", "ftp"); n != 0 {
		t.Errorf("proto desconocido borró %d", n)
	}
}

// TestExportTrasRemove: export/hits/countries reflejan el borrado (los .txt
// de la sesion no se tocan, pero la memoria manda).
func TestExportTrasRemove(t *testing.T) {
	j := mkJob(
		massHit{Line: "1.2.3.4:8080", Proto: "http", Ping: 100, Country: "Spain"},
		massHit{Line: "5.6.7.8:1080", Proto: "socks5", Ping: 90, Country: "Spain"},
	)
	a := newMassApp(t)
	a.mass = j
	j.removeHits("1.2.3.4:8080", "")
	if txt, ok := a.massExport("all", "full"); !ok || !strings.Contains(txt, "5.6.7.8:1080") || strings.Contains(txt, "1.2.3.4") {
		t.Errorf("export tras remove = %q", txt)
	}
	if hits := a.massHits("http", 10); len(hits) != 0 {
		t.Errorf("massHits(http) tras borrar = %d", len(hits))
	}
	if hits := a.massHits("all", 10); len(hits) != 1 || hits[0].Line != "5.6.7.8:1080" {
		t.Errorf("massHits(all) tras borrar = %+v", hits)
	}
	if c := a.massCountries()["Spain"]; c != 1 {
		t.Errorf("countries[Spain] = %d, esperaba 1", c)
	}
	j.removeHits("", "all")
	if txt, ok := a.massExport("all", "plain"); !ok || txt != "" {
		t.Errorf("export vacio = %q ok=%v", txt, ok)
	}
}

// TestRemoveEndpoint: validaciones y respuestas de POST /checker/remove.
func TestRemoveEndpoint(t *testing.T) {
	a := newMassApp(t)
	mux := http.NewServeMux()
	a.registerChecker(mux)
	post := func(body string, panelHeader bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/checker/remove", strings.NewReader(body))
		if panelHeader {
			req.Header.Set("X-GW-Panel", "1")
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	// sin job todavia
	if rr := post(`{"proto":"all"}`, true); rr.Code != http.StatusBadRequest ||
		!strings.Contains(rr.Body.String(), "sin datos") {
		t.Errorf("sin job = %d %s", rr.Code, rr.Body.String())
	}
	// sin cabecera de panel
	if rr := post(`{"proto":"all"}`, false); rr.Code != http.StatusForbidden {
		t.Errorf("sin X-GW-Panel = %d, esperaba 403", rr.Code)
	}
	// protocolo desconocido
	a.mass = mkJob(massHit{Line: "1.2.3.4:8080", Proto: "http"})
	if rr := post(`{"proto":"ftp"}`, true); rr.Code != http.StatusBadRequest ||
		!strings.Contains(rr.Body.String(), "protocolo") {
		t.Errorf("proto invalido = %d %s", rr.Code, rr.Body.String())
	}
	// sin line ni proto
	if rr := post(`{}`, true); rr.Code != http.StatusBadRequest {
		t.Errorf("payload vacio = %d, esperaba 400", rr.Code)
	}
	// JSON invalido
	if rr := post(`{no-json}`, true); rr.Code != http.StatusBadRequest {
		t.Errorf("json invalido = %d, esperaba 400", rr.Code)
	}
	// borrado correcto
	rr := post(`{"line":"1.2.3.4:8080"}`, true)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"removed":1`) ||
		!strings.Contains(rr.Body.String(), `"remaining":0`) {
		t.Errorf("remove ok = %d %s", rr.Code, rr.Body.String())
	}
	// GET no vale (allowPanel exige POST)
	req := httptest.NewRequest(http.MethodGet, "/checker/remove", nil)
	req.Header.Set("X-GW-Panel", "1")
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET = %d, esperaba 405", rr.Code)
	}
	// tras borrar, el status refleja 0 vivos
	if st := a.massStatusJSON(); st.Alive != 0 || st.Removed != 1 {
		t.Errorf("status tras remove = %+v", st)
	}
}

// a_hits: copia de los hits en memoria del job.
func a_hits(t *testing.T, j *massJob) []massHit {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]massHit, len(j.hits))
	copy(out, j.hits)
	return out
}

func a_hitsN(t *testing.T, j *massJob, proto string) int {
	t.Helper()
	n := 0
	for _, h := range a_hits(t, j) {
		if protoMatch(h.Proto, proto) {
			n++
		}
	}
	return n
}

/* ---------------- discord ---------------- */

func TestSendDiscord(t *testing.T) {
	var gotBody atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		w.WriteHeader(204)
	}))
	defer ts.Close()
	if err := sendDiscord(ts.URL, "hola mundo"); err != nil {
		t.Fatalf("sendDiscord: %v", err)
	}
	body, _ := gotBody.Load().(string)
	if !strings.Contains(body, "hola mundo") || !strings.Contains(body, "content") {
		t.Errorf("payload discord = %q", body)
	}
	if err := sendDiscord("http://127.0.0.1:1/", "x"); err == nil {
		t.Error("webhook caido debio devolver error")
	}
}
