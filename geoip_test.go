package main

// Tests del lector GeoIP offline (geoip.go). Verificacion:
//   go test -count=1 -run 'GeoDB|MMDB' .
//   ESPECTRO_TEST_MMDB="C:\...\GeoLite2-Country.mmdb" go test -run TestMMDBReal .

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/* --------- helpers de codificacion MaxMind DB (v2.0) --------- */

func mmStr(s string) []byte { return append([]byte{byte(2<<5) | byte(len(s))}, s...) }

func mmMap(n int, body []byte) []byte { return append([]byte{byte(7<<5) | byte(n)}, body...) }

func mmArr(n int, body []byte) []byte { return append([]byte{byte(n), 11 - 7}, body...) }

func mmU16(v int) []byte { return []byte{byte(5<<5) | 2, byte(v >> 8), byte(v)} }

func mmU32(v int) []byte {
	return []byte{byte(6<<5) | 4, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func mmU64(v uint64) []byte {
	return []byte{byte(8), 9 - 7, byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// mmPtr: puntero con tamaño 0 (valor 0..2047) -> control 001SSVVV.
func mmPtr(v int) []byte { return []byte{byte(1<<5) | byte((v>>8)&0x7), byte(v & 0xff)} }

func mmCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// mmDBIPv4: construye una base mmdb IPv4 minima y valida con:
//
//	record_size 24, 32 nodos (una /32), punteros para compartir el mapa
//	"names", metadata con node_count/record_size/ip_version.
func mmDBIPv4(t *testing.T, ip string, names map[string]string, iso string) []byte {
	t.Helper()
	p4 := net.ParseIP(ip).To4()
	if p4 == nil {
		t.Fatalf("ip %q no es IPv4", ip)
	}
	nodeCnt, recSize := 32, 24
	tree := nodeCnt * recSize / 4

	// seccion de datos: names + country + record (compartido por punteros)
	var nom []byte
	for k, v := range names {
		nom = mmCat(nom, mmStr(k), mmStr(v))
	}
	namesBlob := mmMap(len(names), nom)
	country := mmMap(2, mmCat(mmStr("iso_code"), mmStr(iso),
		mmStr("names"), mmPtr(0))) // puntero a namesBlob (offset 0)
	rec := mmMap(1, mmCat(mmStr("country"), mmPtr(len(namesBlob))))
	data := mmCat(namesBlob, country, rec)
	recValue := nodeCnt + mmdbSepSize + len(namesBlob) + len(country) // (v-nodeCnt)+tree = dataOff+recOff

	// arbol: el nodo i prueba el bit i de la IP; los otros registros = "sin datos"
	buf := make([]byte, 0, tree+mmdbSepSize+len(data)+128)
	for i := 0; i < nodeCnt; i++ {
		left, right := nodeCnt, nodeCnt // nodeCnt == "sin datos"
		switch {
		case i < nodeCnt-1:
			if bitAt(p4, i) == 0 {
				left = i + 1
			} else {
				right = i + 1
			}
		default:
			// nodo final: el bit 31 elige el registro de datos
			if bitAt(p4, 31) == 0 {
				left = recValue
			} else {
				right = recValue
			}
		}
		buf = append(buf, byte(left>>16), byte(left>>8), byte(left), byte(right>>16), byte(right>>8), byte(right))
	}
	buf = append(buf, make([]byte, mmdbSepSize)...) // separador de ceros
	buf = append(buf, data...)

	meta := mmMap(5, mmCat(
		mmStr("node_count"), mmU32(nodeCnt),
		mmStr("record_size"), mmU16(recSize),
		mmStr("ip_version"), mmU16(4),
		mmStr("database_type"), mmStr("Test-Country"),
		mmStr("build_epoch"), mmU64(1700000000),
	))
	buf = append(buf, mmdbMarker...)
	buf = append(buf, meta...)
	return buf
}

func bitAt(b []byte, i int) int { return int(b[i/8]>>uint(7-i%8)) & 1 }

func TestGeoDBSintetico(t *testing.T) {
	raw := mmDBIPv4(t, "1.2.3.4", map[string]string{"en": "Testland", "es": "Testilandia"}, "TS")
	p := filepath.Join(t.TempDir(), "test.mmdb")
	if err := os.WriteFile(p, raw, 0644); err != nil {
		t.Fatal(err)
	}
	g, err := openGeoDB(p)
	if err != nil {
		t.Fatalf("openGeoDB: %v", err)
	}
	if g.nodeCnt != 32 || g.recSize != 24 || g.ipv6 {
		t.Errorf("metadata mal leida: nodeCnt=%d recSize=%d ipv6=%v", g.nodeCnt, g.recSize, g.ipv6)
	}
	// nombre en ingles (el espanol de la base puede venir abreviado: "RU")
	if got := g.countryIP("1.2.3.4"); got != "Testland" {
		t.Errorf("countryIP(1.2.3.4) = %q, esperaba Testland (names.en via puntero)", got)
	}
	if rec := g.countryRecIP("1.2.3.4"); rec.ISO != "TS" || rec.Name != "Testland" {
		t.Errorf("countryRecIP = %+v, esperaba {Testland TS}", rec)
	}
	// IP fuera del arbol -> sin pais (y cacheado como "")
	if got := g.countryIP("9.9.9.9"); got != "" {
		t.Errorf("countryIP(9.9.9.9) = %q, esperaba vacio", got)
	}
	if got := g.countryIP("9.9.9.9"); got != "" {
		t.Errorf("segunda consulta (cache) = %q", got)
	}
	if got := g.countryIP("no-es-una-ip"); got != "" {
		t.Errorf("host no-IP = %q", got)
	}
	if g.info() == "" || !strings.Contains(g.info(), "Test-Country") {
		t.Errorf("info() = %q", g.info())
	}
	// IPv6 contra una base IPv4: error controlado, no panico
	if got := g.countryIP("2001:db8::1"); got != "" {
		t.Errorf("IPv6 en base IPv4 = %q", got)
	}
}

func TestGeoDBArchivosInvalidos(t *testing.T) {
	dir := t.TempDir()
	casos := map[string][]byte{
		"corto.mmdb":    []byte("MZ"),
		"sinmarca.mmdb": bytes.Repeat([]byte("A"), 2048),
		"vacio.mmdb":    nil,
	}
	for name, raw := range casos {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := openGeoDB(p); err == nil {
			t.Errorf("%s: se acepto un archivo invalido", name)
		}
	}
	if _, err := openGeoDB(filepath.Join(dir, "no-existe.mmdb")); err == nil {
		t.Error("archivo inexistente aceptado")
	}
	// base nula: no debe entrar en panico
	var nilDB *geoDB
	if got := nilDB.countryIP("1.2.3.4"); got != "" {
		t.Errorf("geoDB nil = %q", got)
	}
	if nilDB.info() != "" {
		t.Error("info() de geoDB nil debe ser vacio")
	}
}

func TestGeoDBPunteroACiclo(t *testing.T) {
	// puntero que apunta a si mismo: el limite de profundidad debe cortarlo
	// sin colgar el proceso ni desbordar la pila.
	blob := mmPtr(0) // en offset 0: puntero -> offset 0
	g := &geoDB{buf: blob, dataOff: 0, nodeCnt: 1, recSize: 24}
	d := &mmdbDec{g: g, base: 0}
	if _, _, err := d.value(0); err == nil {
		t.Error("un puntero ciclico debio devolver error")
	}
	if d.depth > mmdbMaxDepth+1 {
		t.Errorf("profundidad %d fuera de limite", d.depth)
	}
}

// TestMMDBReal: contra una base .mmdb real. Solo corre si se indica la ruta
// (las bases tienen licencia propia y no se versionan en el repo).
//
//	ESPECTRO_TEST_MMDB="C:\...\GeoLite2-Country.mmdb" go test -run TestMMDBReal -v .
func TestMMDBReal(t *testing.T) {
	p := strings.TrimSpace(os.Getenv("ESPECTRO_TEST_MMDB"))
	if p == "" {
		t.Skip("ESPECTRO_TEST_MMDB no definido")
	}
	g, err := openGeoDB(p)
	if err != nil {
		t.Fatalf("openGeoDB(%s): %v", p, err)
	}
	t.Logf("base: %s", g.info())
	casos := []struct {
		ip  string
		iso string
	}{
		{"81.2.69.142", "GB"},
		{"8.8.8.8", "US"},
		{"2.125.160.216", "GB"},
		{"89.160.20.112", "SE"},
	}
	for _, c := range casos {
		got := g.countryRecIP(c.ip)
		if !strings.EqualFold(got.ISO, c.iso) {
			t.Errorf("countryRecIP(%s) = %+v, esperaba ISO %s", c.ip, got, c.iso)
		} else {
			t.Logf("countryRecIP(%s) = %q (ISO %s)", c.ip, got.Name, got.ISO)
		}
	}
	// IPv6 de la base (si es v6) y una IP privada (sin pais asignado)
	t.Logf("countryIP(2001:4860:4860::8888) = %q", g.countryIP("2001:4860:4860::8888"))
	t.Logf("countryIP(10.0.0.1) = %q (privada)", g.countryIP("10.0.0.1"))
}

func TestFindGeoDB(t *testing.T) {
	// sin bases en el directorio temporal -> ""
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	// el ejecutable de test vive fuera: findGeoDB mira tambien junto al exe,
	// asi que solo comprobamos que no entra en panico y devuelve string.
	_ = findGeoDB()
	os.WriteFile(filepath.Join(dir, "GeoLite2-Country.mmdb"), []byte("x"), 0644)
	if got := findGeoDB(); got == "" {
		t.Error("findGeoDB no encontro la base creada en el cwd")
	}
}

func TestMMDBInt(t *testing.T) {
	if mmdbInt(uint64(7)) != 7 || mmdbInt(int64(-2)) != -2 || mmdbInt("x") != 0 {
		t.Error("mmdbInt conversion incorrecta")
	}
}

func TestMMAPunteros(t *testing.T) {
	// tamaños 0..3 del puntero (001SSVVV)
	casos := []struct {
		v    int
		want []byte
	}{
		{0, []byte{0x20, 0x00}},
		{255, []byte{0x20, 0xff}},
		{2047, []byte{0x27, 0xff}},
	}
	for _, c := range casos {
		if !bytes.Equal(mmPtr(c.v), c.want) {
			t.Errorf("mmPtr(%d) = %v, esperaba %v", c.v, mmPtr(c.v), c.want)
		}
	}
	// lectura de un puntero de tamaño 3 (32 bits)
	buf := append([]byte{0x20 | 0x18}, 0x00, 0x01, 0x00, 0x00) // size=3 (0x18>>3=3)
	v, n, err := readPointer(buf, buf[0], 1)
	if err != nil || v != 0x00010000 || n != 5 {
		t.Errorf("readPointer size3 = %d/%d/%v", v, n, err)
	}
	// array (tipo extendido 11) para cubrir esa rama
	d := &mmdbDec{g: &geoDB{buf: mmArr(2, mmCat(mmStr("a"), mmStr("b")))}, base: 0}
	val, _, err := d.value(0)
	if err != nil {
		t.Fatalf("array: %v", err)
	}
	arr, ok := val.([]any)
	if !ok || len(arr) != 2 || arr[0] != "a" || arr[1] != "b" {
		t.Errorf("array = %#v", val)
	}
}
