package main

// Auditoria profunda (fase de tests): cubre huecos hasta ahora sin test:
//   - readCappedLine / readBody en fase de cuerpo: una linea de chunk o de
//     trailer sin '\n' inflaba bufio sin limite (DoS de memoria). readHead
//     ya tenia byteCap; el cuerpo se leia con cap desactivado.
//   - ServeGateway: cualquier error transitorio de Accept mataba el gateway
//     en silencio (ahora solo sale con net.ErrClosed).
//   - allowPanel: matriz de permisos 405/403/401/200 con y sin --api-token.
//   - ParseProxyDef: bordes de parseo (BOM, CRLF, IPv6, puertos limite,
//     formato OB, credenciales) e inferencia de esquema por nombre de fichero.
//   - readBodyLimited (health.go): cabeceras de respuesta con tope.
// Verificacion: go test -count=1 .   (y con -race ./...)

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// readerInfinito nunca devuelve EOF: simula un peer que transmite bytes
// sin '\n' para siempre. Sin tope, readCappedLine/readBody/readBodyLimited
// colgarian aqui indefinidamente (los tests con watchdog lo detectarian).
type readerInfinito struct{ b byte }

func (r readerInfinito) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// ---------------- readCappedLine ----------------

func TestReadCappedLineNormalYTope(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("hola\nmundo\n"))
	got, err := readCappedLine(br, 64)
	if err != nil || got != "hola\n" {
		t.Fatalf("primera linea = %q, %v; esperaba %q, nil", got, err, "hola\n")
	}
	got, err = readCappedLine(br, 64)
	if err != nil || got != "mundo\n" {
		t.Fatalf("segunda linea = %q, %v; esperaba %q, nil", got, err, "mundo\n")
	}
	// tope exacto: max == longitud de la linea -> pasa; max uno menos -> rechaza
	if _, err := readCappedLine(bufio.NewReader(strings.NewReader("abc\n")), 4); err != nil {
		t.Fatalf("linea de 4 bytes con max=4 rechazada: %v", err)
	}
	if _, err := readCappedLine(bufio.NewReader(strings.NewReader("abc\n")), 3); err != errLineTooLong {
		t.Fatalf("linea de 4 bytes con max=3: esperaba errLineTooLong, got %v", err)
	}
}

func TestReadCappedLineEOFConParcial(t *testing.T) {
	_, err := readCappedLine(bufio.NewReader(strings.NewReader("parcial")), 64)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("esperaba EOF con linea parcial, got %v", err)
	}
}

func TestReadCappedLineLineaInfinitaNoCuelga(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := readCappedLine(bufio.NewReader(readerInfinito{b: 'A'}), 10000)
		done <- err
	}()
	select {
	case err := <-done:
		if err != errLineTooLong {
			t.Fatalf("esperaba errLineTooLong, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readCappedLine se colgo con una linea sin fin (falta tope)")
	}
}

// ---------------- readBody: fase de cuerpo sin tope ----------------

func TestReadBodyChunkSizeLineSinFinNoCuelga(t *testing.T) {
	h := map[string]string{"transfer-encoding": "chunked"}
	done := make(chan error, 1)
	go func() {
		_, err := readBody(bufio.NewReader(readerInfinito{b: 'f'}), h)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("linea de chunk sin fin aceptada, se esperaba error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readBody se colgo con la linea de chunk sin fin (DoS de memoria)")
	}
}

func TestReadBodyTrailerSinFinNoCuelga(t *testing.T) {
	h := map[string]string{"transfer-encoding": "chunked"}
	done := make(chan error, 1)
	go func() {
		r := io.MultiReader(strings.NewReader("0\r\n"), readerInfinito{b: 'T'})
		_, err := readBody(bufio.NewReader(r), h)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("trailer sin fin aceptado, se esperaba error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readBody se colgo con un trailer sin fin (DoS de memoria)")
	}
}

func TestReadBodyTrailerAcumuladoConTope(t *testing.T) {
	// lineas de trailer validas (con '\n') que suman ~96 KB > presupuesto 64 KB
	var sb strings.Builder
	sb.WriteString("0\r\n")
	linea := strings.Repeat("t", 8000) + "\n"
	for i := 0; i < 12; i++ {
		sb.WriteString(linea)
	}
	_, err, pan := readBodyChunked(sb.String())
	if pan != nil {
		t.Fatalf("panic: %v", pan)
	}
	if err == nil {
		t.Fatal("trailers de 96KB aceptados (presupuesto maxHeadBytes=64KB)")
	}
}

func TestReadBodyChunkedConTrailerNormalFunciona(t *testing.T) {
	body, err, pan := readBodyChunked("5\r\nhello\r\n0\r\nX-Extra: 1\r\n\r\n")
	if pan != nil {
		t.Fatalf("panic: %v", pan)
	}
	if err != nil {
		t.Fatalf("chunked valido con trailer fallo: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, esperaba %q", body, "hello")
	}
}

// ---------------- ServeGateway: error transitorio de Accept ----------------

type fakeListener struct{ n atomic.Int32 }

func (f *fakeListener) Accept() (net.Conn, error) {
	if f.n.Add(1) == 1 {
		return nil, errors.New("error transitorio de prueba")
	}
	return nil, net.ErrClosed
}

func (f *fakeListener) Close() error { return nil }

func (f *fakeListener) Addr() net.Addr { return fakeAddr("fake") }

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

func TestServeGatewayAtraviesaErrorTransitorioDeAccept(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	fl := &fakeListener{}
	done := make(chan struct{})
	go func() {
		a.ServeGateway(fl)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ServeGateway no retorno tras net.ErrClosed")
	}
	if n := fl.n.Load(); n < 2 {
		t.Fatalf("Accept invocado %d vez(es): el gateway murio en el primer error transitorio", n)
	}
}

// ---------------- allowPanel: matriz de permisos ----------------

func TestAllowPanelMatrizDePermisos(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")

	rr := httptest.NewRecorder()
	if a.allowPanel(rr, httptest.NewRequest(http.MethodGet, "/reload", nil)) || rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET debio dar 405, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	if a.allowPanel(rr, httptest.NewRequest(http.MethodPost, "/reload", nil)) || rr.Code != http.StatusForbidden {
		t.Fatalf("POST sin X-GW-Panel debio dar 403, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("X-GW-Panel", "1")
	if !a.allowPanel(rr, req) || rr.Code != http.StatusOK {
		t.Fatalf("POST + cabecera sin token configurado debio pasar, got %d", rr.Code)
	}

	a.apiToken = "secreto123"

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("X-GW-Panel", "1")
	if a.allowPanel(rr, req) || rr.Code != http.StatusUnauthorized {
		t.Fatalf("con --api-token y sin X-API-Token debio dar 401, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("X-GW-Panel", "1")
	req.Header.Set("X-API-Token", "secreto123")
	if !a.allowPanel(rr, req) {
		t.Fatal("token correcto en cabecera debio pasar")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/reload?token=secreto123", nil)
	req.Header.Set("X-GW-Panel", "1")
	if !a.allowPanel(rr, req) {
		t.Fatal("token correcto en query debio pasar")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/reload?token=malo", nil)
	req.Header.Set("X-GW-Panel", "1")
	if a.allowPanel(rr, req) || rr.Code != http.StatusUnauthorized {
		t.Fatalf("token incorrecto debio dar 401, got %d", rr.Code)
	}
}

// ---------------- ParseProxyDef: bordes ----------------

func TestParseProxyDefBordes(t *testing.T) {
	casos := []struct {
		in, def, scheme, host, user, pass string
		port                              int
	}{
		{in: "\ufeff1.2.3.4:80\r\n", def: "http", scheme: "http", host: "1.2.3.4", port: 80},
		{in: "1.2.3.4:65535", def: "http", scheme: "http", host: "1.2.3.4", port: 65535},
		{in: "socks5://1.2.3.4", scheme: "socks5", host: "1.2.3.4", port: 1080},
		{in: "http://1.2.3.4", scheme: "http", host: "1.2.3.4", port: 8080},
		{in: "socks5://u:p@1.2.3.4:1081", scheme: "socks5", host: "1.2.3.4", port: 1081, user: "u", pass: "p"},
		{in: "u:p@1.2.3.4:8080", def: "socks5", scheme: "socks5", host: "1.2.3.4", port: 8080, user: "u", pass: "p"},
		{in: "[::1]:8080", def: "http", scheme: "http", host: "::1", port: 8080},
		{in: "0:1.2.3.4:8080::", scheme: "http", host: "1.2.3.4", port: 8080},
		{in: "2:1.2.3.4:1080:usuario:clave", scheme: "socks5", host: "1.2.3.4", port: 1080, user: "usuario", pass: "clave"},
		{in: "1.2.3.4:8080:user", def: "http", scheme: "http", host: "1.2.3.4", port: 8080, user: "user"},
		{in: "1.2.3.4:8080:user:pass", def: "http", scheme: "http", host: "1.2.3.4", port: 8080, user: "user", pass: "pass"},
		{in: "socks5://[2001:db8::1]:1080", scheme: "socks5", host: "2001:db8::1", port: 1080},
	}
	for _, c := range casos {
		p := ParseProxyDef(c.in, c.def)
		if p == nil {
			t.Errorf("ParseProxyDef(%q) = nil, esperaba proxy valido", c.in)
			continue
		}
		if p.Scheme != c.scheme || p.Host != c.host || p.Port != c.port || p.User != c.user || p.Password != c.pass {
			t.Errorf("ParseProxyDef(%q) = %s://%s:%d user=%q pass=%q, esperaba %s://%s:%d user=%q pass=%q",
				c.in, p.Scheme, p.Host, p.Port, p.User, p.Password,
				c.scheme, c.host, c.port, c.user, c.pass)
		}
	}
}

func TestParseProxyDefInvalidos(t *testing.T) {
	invalidos := []string{
		"", "   ", "# comentario", "1.2.3.4", "1.2.3.4:0", "1.2.3.4:65536",
		"1.2.3.4:-1", "ftp://1.2.3.4:80", "http://:80", "http://1.2.3.4:99999",
		"http://", "basura total", "1.2.3.4:8080:x:y:z", "::1",
	}
	for _, in := range invalidos {
		if p := ParseProxyDef(in, "http"); p != nil {
			t.Errorf("ParseProxyDef(%q) = %+v, esperaba nil", in, p)
		}
	}
}

func TestSchemeFromFileName(t *testing.T) {
	casos := map[string]string{
		"socks5.txt":           "socks5",
		"socks4a.txt":          "socks4a",
		"socks4.txt":           "socks4",
		"http.txt":             "http",
		"https_cache.txt":      "http",
		"lista.txt":            "",
		"proxy.txt":            "",
		`C:\listas\SOCKS5.TXT`: "socks5",
	}
	for in, want := range casos {
		if got := schemeFromFileName(in); got != want {
			t.Errorf("schemeFromFileName(%q) = %q, esperaba %q", in, got, want)
		}
	}
}

func TestProxySerializacion(t *testing.T) {
	p := ParseProxyDef("socks5://u:p@[::1]:1080", "")
	if p == nil {
		t.Fatal("parse de IPv6 con credenciales fallo")
	}
	if got, want := p.Key(), "socks5|::1|1080|u"; got != want {
		t.Errorf("Key() = %q, esperaba %q", got, want)
	}
	if got, want := p.Addr(), "[::1]:1080"; got != want {
		t.Errorf("Addr() = %q, esperaba %q", got, want)
	}
	if got, want := p.Tag(), "socks5://u@@::1:1080"; got != want {
		t.Errorf("Tag() = %q, esperaba %q", got, want)
	}
	if got, want := p.LineaCanon(), "socks5://u:p@[::1]:1080"; got != want {
		t.Errorf("LineaCanon() = %q, esperaba %q", got, want)
	}

	q := ParseProxyDef("2:1.2.3.4:1080:usuario:clave", "")
	if q == nil {
		t.Fatal("parse de formato OB fallo")
	}
	if got, want := q.OB(), "2:1.2.3.4:1080:usuario:clave"; got != want {
		t.Errorf("OB() = %q, esperaba %q", got, want)
	}
	if got, want := q.LineaCanon(), "socks5://usuario:clave@1.2.3.4:1080"; got != want {
		t.Errorf("LineaCanon() = %q, esperaba %q", got, want)
	}
}

// ---------------- readBodyLimited (health.go): cabeceras con tope ----------------

func TestReadBodyLimitedCabeceraNormal(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("Content-Type: text/html\r\n\r\nHOLA"))
	if got := readBodyLimited(br, 100); got != "HOLA" {
		t.Fatalf("got %q, esperaba %q", got, "HOLA")
	}
	if got := readBodyLimited(bufio.NewReader(strings.NewReader("x")), 0); got != "" {
		t.Fatalf("max<=0 debio devolver vacio, got %q", got)
	}
}

func TestReadBodyLimitedLineaSinFinNoCuelga(t *testing.T) {
	done := make(chan string, 1)
	go func() {
		done <- readBodyLimited(bufio.NewReader(readerInfinito{b: 'A'}), 100)
	}()
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("got %q, esperaba vacio ante cabecera sin fin", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readBodyLimited se colgo con una cabecera sin fin (falta tope)")
	}
}
