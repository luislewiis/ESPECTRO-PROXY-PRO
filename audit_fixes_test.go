package main

// Auditoria exhaustiva del 17/10/2026: cada test reproduce un hallazgo
// encontrado leyendo el codigo (no por casualidad) y lo deja fijado para que
// no vuelva. Todos deben pasar TAMBIEN con -race y -count=1:
//
//	go test -count=1 -run Audit .
//	go test -race -count=1 -run Audit .
//
// Hallazgos cubiertos aqui:
//   H1 geoip: carrera de datos en ipv4Start (bases IPv6 + checker en paralelo)
//   H2 checker: los vivos con esquema explicito socks4a no llegaban a
//      Live_SOCKS4.txt (si al .txt por pais y al panel)
//   H3 API: /import y /validate no exigian la cabecera X-GW-Panel (CSRF:
//      una web ajena podia escribir proxys en la lista del usuario)
//   H4 pool: editar un proxy del mismo host:puerto perdia el pais (GeoIP)
//   H5 estado: un archivo de lista ilegible (bloqueado/exclusivo) expulsaba
//      sus proxies del pool y podaba su estado persistido
//   H6 checker: isLocalLine no cubria 172.16/12, 169.254/16, CGNAT ni IPv6 local

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

/* ---------------- H1: carrera en ipv4Start ---------------- */

// mmDBIPv6: base mmdb IPv6 minima con el subarbol IPv4 de una /32 (estructura
// "IPv4 dentro de un arbol IPv6": 96 ramas de ceros + los 32 bits de la IP).
func mmDBIPv6(t *testing.T, ip string, names map[string]string, iso string) []byte {
	t.Helper()
	p4 := net.ParseIP(ip).To4()
	if p4 == nil {
		t.Fatalf("ip %q no es IPv4", ip)
	}
	nodeCnt, recSize := 128, 24
	tree := nodeCnt * recSize / 4

	var nom []byte
	for k, v := range names {
		nom = mmCat(nom, mmStr(k), mmStr(v))
	}
	namesBlob := mmMap(len(names), nom)
	country := mmMap(2, mmCat(mmStr("iso_code"), mmStr(iso),
		mmStr("names"), mmPtr(0)))
	rec := mmMap(1, mmCat(mmStr("country"), mmPtr(len(namesBlob))))
	data := mmCat(namesBlob, country, rec)
	recValue := nodeCnt + mmdbSepSize + len(namesBlob) + len(country)

	buf := make([]byte, 0, tree+mmdbSepSize+len(data)+128)
	for i := 0; i < nodeCnt; i++ {
		left, right := nodeCnt, nodeCnt
		switch {
		case i < 96:
			left = i + 1 // rama de ceros: subarbol IPv4 (spec MaxMind)
		case i < nodeCnt-1:
			if bitAt(p4, i-96) == 0 {
				left = i + 1
			} else {
				right = i + 1
			}
		default:
			if bitAt(p4, 31) == 0 {
				left = recValue
			} else {
				right = recValue
			}
		}
		buf = append(buf, byte(left>>16), byte(left>>8), byte(left),
			byte(right>>16), byte(right>>8), byte(right))
	}
	buf = append(buf, make([]byte, mmdbSepSize)...)
	buf = append(buf, data...)

	meta := mmMap(5, mmCat(
		mmStr("node_count"), mmU32(nodeCnt),
		mmStr("record_size"), mmU16(recSize),
		mmStr("ip_version"), mmU16(6),
		mmStr("database_type"), mmStr("Test-Country6"),
		mmStr("build_epoch"), mmU64(1700000000),
	))
	buf = append(buf, mmdbMarker...)
	buf = append(buf, meta...)
	return buf
}

// TestAuditGeoIPIPv4StartSinCarrera: con una base IPv6, cada consulta IPv4
// pasa por ipv4Start(). El checker resuelve paises desde decenas de hilos con
// IPs distintas (todas sin cache): si ipv4Start escribe el campo compartido
// sin sincronizacion, con -race esto denuncia la carrera.
func TestAuditGeoIPIPv4StartSinCarrera(t *testing.T) {
	raw := mmDBIPv6(t, "8.8.8.8", map[string]string{"en": "Testland"}, "TS")
	p := filepath.Join(t.TempDir(), "test6.mmdb")
	if err := os.WriteFile(p, raw, 0644); err != nil {
		t.Fatal(err)
	}
	// la comprobacion de correccion va sobre OTRA instancia: consultar 8.8.8.8
	// aqui dejaria ipv4 ya calculado (y la carrera no se reproducira).
	ref, err := openGeoDB(p)
	if err != nil {
		t.Fatalf("openGeoDB: %v", err)
	}
	if !ref.ipv6 {
		t.Fatalf("la base sintetica debe ser IPv6 (ipv6=%v)", ref.ipv6)
	}
	if got := ref.countryIP("8.8.8.8"); got != "Testland" {
		t.Fatalf("countryIP(8.8.8.8) = %q, esperaba Testland", got)
	}

	g, err := openGeoDB(p) // instancia fresca: ipv4 aun sin calcular
	if err != nil {
		t.Fatalf("openGeoDB 2: %v", err)
	}

	// 32 IPs DISTINTAS (sin cache) resueltas a la vez: el primer camino de
	// cada una pasa por ipv4Start().
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan string, 64)
	for i := 0; i < 32; i++ {
		ip := fmt.Sprintf("8.8.8.%d", i+1)
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			<-start
			if rec := g.countryRecIP(ip); ip == "8.8.8.8" && rec.Name != "Testland" {
				errs <- "8.8.8.8 -> " + rec.Name
			}
		}(ip)
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	// segunda pasada en caliente: mismo resultado (cache y nodo ya fijados)
	if got := g.countryIP("8.8.8.8"); got != "Testland" {
		t.Errorf("tras la tormenta: countryIP = %q", got)
	}
}

/* ---------------- H2: socks4a en Live_SOCKS4.txt ---------------- */

func TestAuditSocks4aVaAlArchivoDeVivos(t *testing.T) {
	j := &massJob{outBase: t.TempDir(), start: time.Now()}
	if err := j.prepareOut(); err != nil {
		t.Fatalf("prepareOut: %v", err)
	}
	j.addHit(massHit{Line: "1.2.3.4:1080", Proto: "socks4a", Ping: 12, Anon: "Elite"})
	j.addHit(massHit{Line: "5.6.7.8:1080", Proto: "socks4", Ping: 20, Anon: "Elite"})
	j.addHit(massHit{Line: "9.9.9.9:3128", Proto: "http", Ping: 30, Anon: "High"})

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
	j.wmu.Unlock()

	b, err := os.ReadFile(filepath.Join(j.dir, "Live_SOCKS4.txt"))
	if err != nil {
		t.Fatalf("Live_SOCKS4.txt: %v", err)
	}
	txt := string(b)
	if !strings.Contains(txt, "1.2.3.4:1080") {
		t.Errorf("un vivo socks4a no quedo registrado en Live_SOCKS4.txt: %q", txt)
	}
	if !strings.Contains(txt, "5.6.7.8:1080") {
		t.Errorf("el vivo socks4 no quedo registrado: %q", txt)
	}
	if strings.Contains(txt, "9.9.9.9") {
		t.Errorf("un vivo http no debe estar en Live_SOCKS4.txt: %q", txt)
	}
}

/* ---------------- H3: /import exige X-GW-Panel ---------------- */

func TestAuditImportYValidateExigenCabeceraPanel(t *testing.T) {
	dir := t.TempDir()
	lista := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(lista, []byte("# lista de prueba\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{lista}, "round-robin", true, 0, "")
	a.allowAnyPath = true
	a.LoadProxies()
	mux := a.APIMux(8080, "127.0.0.1")

	payload := `{"text":"9.9.9.9:8080\n9.9.9.10:8080\n"}`

	// a) POST /import sin cabecera del panel: debe rechazarse (CSRF) y NO tocar
	// la lista del usuario.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain") // asi lo enviaria una web ajena
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("/import sin X-GW-Panel = %d, esperaba 403", rr.Code)
	}
	if b, _ := os.ReadFile(lista); strings.Contains(string(b), "9.9.9.9") {
		t.Fatalf("el import se ejecuto sin cabecera del panel: %q", string(b))
	}

	// b) POST /validate sin cabecera: tambien fuera (lee archivos del disco)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/validate",
		strings.NewReader(`{"path":`+fmt.Sprintf("%q", lista)+`}`))
	req.Header.Set("Content-Type", "text/plain")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("/validate sin X-GW-Panel = %d, esperaba 403", rr.Code)
	}

	// c) con la cabecera (lo que envia el panel) funciona igual que siempre
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GW-Panel", "1")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/import con X-GW-Panel = %d (%s)", rr.Code, rr.Body.String())
	}
	if b, _ := os.ReadFile(lista); !strings.Contains(string(b), "9.9.9.9:8080") {
		t.Fatalf("la lista no recibio el import valido: %q", string(b))
	}
}

/* ---------------- H4: editar no debe perder el pais ---------------- */

func TestAuditEditProxyPreservaPais(t *testing.T) {
	dir := t.TempDir()
	lista := filepath.Join(dir, "proxies.txt")
	if err := os.WriteFile(lista, []byte("1.2.3.4:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{lista}, "round-robin", true, 0, "")
	a.stateDisabled = true
	a.LoadProxies()
	a.mu.Lock()
	if len(a.proxies) != 1 {
		a.mu.Unlock()
		t.Fatalf("pool = %d, esperaba 1", len(a.proxies))
	}
	old := a.proxies[0]
	old.Country, old.Alive, old.Checked, old.PingMs = "Spain", true, true, 42
	key := old.Key()
	a.mu.Unlock()

	// cambio de credenciales del MISMO host:puerto -> estado se conserva
	if _, err := a.editProxy(key, "socks5://u:p@1.2.3.4:8080"); err != nil {
		t.Fatalf("editProxy: %v", err)
	}
	a.mu.Lock()
	if len(a.proxies) != 1 {
		a.mu.Unlock()
		t.Fatal("el pool cambio de tamano al editar")
	}
	p := a.proxies[0]
	a.mu.Unlock()
	if p.Country != "Spain" {
		t.Errorf("pais perdido al editar (mismo host:puerto): %q", p.Country)
	}
	if !p.Alive || !p.Checked || p.PingMs != 42 {
		t.Errorf("estado de analisis perdido: alive=%v checked=%v ping=%d", p.Alive, p.Checked, p.PingMs)
	}
	if p.Scheme != "socks5" || p.User != "u" {
		t.Errorf("la edicion no se aplico: %s://%s@%s", p.Scheme, p.User, p.Addr())
	}

	// cambio de direccion -> estado (y pais) a cero: es otro proxy
	if _, err := a.editProxy(p.Key(), "socks5://u:p@5.6.7.8:1080"); err != nil {
		t.Fatalf("editProxy 2: %v", err)
	}
	a.mu.Lock()
	p2 := a.proxies[0]
	a.mu.Unlock()
	if p2.Country != "" || p2.Alive || p2.Checked {
		t.Errorf("al cambiar de direccion el estado debe resetearse: %+v", p2)
	}
}

/* ---------------- H5: archivo ilegible no debe vaciar el pool ---------------- */

func TestAuditLoadProxiesArchivoIlegibleNoPierdePool(t *testing.T) {
	dir := t.TempDir()
	lista := filepath.Join(dir, "proxies.txt")
	recolectada := filepath.Join(dir, "harvested.txt")
	if err := os.WriteFile(lista, []byte("1.2.3.4:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recolectada, []byte("5.6.7.8:1080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{lista, recolectada}, "round-robin", true, 0, "")
	a.stateDisabled = true
	a.LoadProxies()
	if _, total := a.counts(); total != 2 {
		t.Fatalf("pool inicial = %d, esperaba 2", total)
	}

	// el archivo existe pero no se puede leer como fichero (p. ej. bloqueado,
	// o sustituido por un directorio): NO debe expulsar sus 1 proxies
	os.Remove(lista)
	if err := os.Mkdir(lista, 0755); err != nil {
		t.Fatal(err)
	}
	a.LoadProxies()
	if _, total := a.counts(); total != 2 {
		t.Errorf("pool tras archivo ilegible = %d, esperaba 2 (se conservan los del archivo ilegible)", total)
	}

	// si el archivo desaparece de verdad, sus proxies si se van
	os.Remove(lista)
	a.LoadProxies()
	if _, total := a.counts(); total != 1 {
		t.Errorf("pool tras borrar el archivo = %d, esperaba 1", total)
	}
}

/* ---------------- H6: isLocalLine ---------------- */

func TestAuditIsLocalLineCubreRangosPrivados(t *testing.T) {
	locales := []string{
		"127.0.0.1:8080", "10.0.0.5:1", "192.168.1.1:80",
		"172.16.0.1:8080", "172.31.255.254:1",
		"169.254.10.10:80", "100.64.0.7:80", "0.0.0.0:80",
		"localhost:8080", "[::1]:8080", "::1:8080", "fe80::1:8080",
		"socks5://127.0.0.1:1080", "http://user:pass@10.1.2.3:8080",
	}
	for _, in := range locales {
		if !isLocalLine(in) {
			t.Errorf("isLocalLine(%q) = false, esperaba true", in)
		}
	}
	publicos := []string{
		"8.8.8.8:8080", "1.2.3.4:80", "172.32.0.1:80",
		"socks5://1.2.3.4:1080", "2.1.1.1:3128", "[2001:4860:4860::8888]:80",
		"", "# comentario", "basura",
	}
	for _, in := range publicos {
		if isLocalLine(in) {
			t.Errorf("isLocalLine(%q) = true, esperaba false", in)
		}
	}
}
