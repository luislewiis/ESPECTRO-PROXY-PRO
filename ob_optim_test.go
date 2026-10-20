package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestStealthHeaderStripping: valida P1.3 (Stealth Headers anti-detección).
// Cabeceras que delatan proxies (Via, X-Forwarded-For, X-Real-IP, X-Gateway-*, etc.)
// deben ser eliminadas antes de que la petición llegue al upstream.
func TestStealthHeaderStripping(t *testing.T) {
	// 1. Verificación unitaria de la función isStrippedHeader
	mustStrip := []string{
		"via", "Via", "VIA",
		"x-forwarded-for", "X-Forwarded-For",
		"x-real-ip", "X-Real-IP",
		"forwarded", "Forwarded",
		"x-proxy-id", "X-Proxy-ID",
		"proxy-connection", "Proxy-Connection",
		"x-forwarded-host", "X-Forwarded-Proto", "x-forwarded-server",
		"client-ip", "true-client-ip",
		"x-gateway-custom", "X-Gateway-Trace",
	}
	for _, h := range mustStrip {
		if !isStrippedHeader(h) {
			t.Errorf("isStrippedHeader(%q) debió ser true", h)
		}
	}

	mustKeep := []string{
		"host", "Host", "user-agent", "User-Agent", "accept", "Accept",
		"accept-encoding", "authorization", "cookie", "content-type",
	}
	for _, h := range mustKeep {
		if isStrippedHeader(h) {
			t.Errorf("isStrippedHeader(%q) debió ser false", h)
		}
	}

	// 2. Verificación de roundTrip: servidor destino inspecciona las cabeceras recibidas
	var receivedHeaders http.Header
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer targetServer.Close()

	u, _ := url.Parse(targetServer.URL)
	targetHost, targetPortStr, _ := net.SplitHostPort(u.Host)
	targetPort := 80
	if p, err := net.LookupPort("tcp", targetPortStr); err == nil {
		targetPort = p
	}

	// Proxy directo (el propio servidor destino simula ser un proxy HTTP que responde al GET)
	p := &Proxy{Scheme: "http", Host: targetHost, Port: targetPort, Alive: true}
	a := NewApp(nil, "round-robin", true, 0, "")

	headersToSend := map[string]string{
		"via":             "1.1 test-proxy",
		"x-forwarded-for": "198.51.100.1",
		"x-real-ip":       "198.51.100.1",
		"x-proxy-id":      "bot-tracer-99",
		"x-gateway-debug": "internal-tag",
		"user-agent":      "OpenBullet-Client/1.0",
		"accept":          "*/*",
		"authorization":   "Bearer token123",
	}

	resp, err := a.roundTrip(p, "GET", u, headersToSend, nil)
	if err != nil {
		t.Fatalf("roundTrip fallo: %v", err)
	}
	defer resp.Body.Close()

	for _, h := range []string{"Via", "X-Forwarded-For", "X-Real-Ip", "X-Proxy-Id", "X-Gateway-Debug"} {
		if receivedHeaders.Get(h) != "" {
			t.Errorf("cabecera sensible %s no fue eliminada, recibida: %q", h, receivedHeaders.Get(h))
		}
	}
	if receivedHeaders.Get("User-Agent") != "OpenBullet-Client/1.0" {
		t.Errorf("User-Agent no preservado: %q", receivedHeaders.Get("User-Agent"))
	}
	if receivedHeaders.Get("Authorization") != "Bearer token123" {
		t.Errorf("Authorization no preservado: %q", receivedHeaders.Get("Authorization"))
	}
}

// TestStrategyFastest: valida P1.2 (Selector fastest / Top 25% ping).
func TestStrategyFastest(t *testing.T) {
	// Pool de 20 proxies con pings crecientes (50ms a 1000ms)
	a := NewApp(nil, "fastest", true, 0, "")
	a.proxies = make([]*Proxy, 20)
	for i := 0; i < 20; i++ {
		a.proxies[i] = &Proxy{
			Scheme: "http",
			Host:   fmt.Sprintf("10.0.0.%d", i+1),
			Port:   8080,
			Alive:  true,
			PingMs: (i + 1) * 50, // 50, 100, 150 ... 1000 ms
		}
	}

	// Con 20 proxies, el top 25% son los 5 primeros (índices 0..4, pings 50..250ms)
	topHostSet := make(map[string]bool)
	for i := 0; i < 5; i++ {
		topHostSet[a.proxies[i].Host] = true
	}

	for n := 0; n < 100; n++ {
		p := a.pick("", nil)
		if p == nil {
			t.Fatal("pick fastest devolvio nil")
		}
		if !topHostSet[p.Host] {
			t.Fatalf("pick fastest eligio proxy fuera del top 25%%: host=%s ping=%dms", p.Host, p.PingMs)
		}
	}

	// Con pool pequeño (< 8 proxies), debe caer en round-robin sin fallar
	aSmall := NewApp(nil, "fastest", true, 0, "")
	aSmall.proxies = make([]*Proxy, 4)
	for i := 0; i < 4; i++ {
		aSmall.proxies[i] = &Proxy{
			Scheme: "http",
			Host:   fmt.Sprintf("10.1.0.%d", i+1),
			Port:   8080,
			Alive:  true,
			PingMs: 500 - (i * 100),
		}
	}
	for n := 0; n < 20; n++ {
		p := aSmall.pick("", nil)
		if p == nil {
			t.Fatalf("pick fastest en pool pequeno devolvio nil")
		}
	}
}

// TestFailoverSilentPlain: valida P1.1 (Failover silencioso en handlePlain).
// Un proxy primario cerrado/caído no debe provocar 502 al cliente si existe
// otro proxy secundario vivo que pueda servir la petición.
func TestFailoverSilentPlain(t *testing.T) {
	// Servidor destino final
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("exito-destino"))
	}))
	defer targetServer.Close()

	u, _ := url.Parse(targetServer.URL)

	// Proxy 1 (roto: puerto cerrado inmediatamente)
	lnDead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadPort := lnDead.Addr().(*net.TCPAddr).Port
	lnDead.Close() // cerrado a propósito

	// Proxy 2 (vivo: relaya al targetServer)
	goodProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("exito-destino"))
	}))
	defer goodProxy.Close()
	uGood, _ := url.Parse(goodProxy.URL)
	goodHost, goodPortStr, _ := net.SplitHostPort(uGood.Host)
	goodPort, _ := net.LookupPort("tcp", goodPortStr)

	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "127.0.0.1", Port: deadPort, Alive: true},
		{Scheme: "http", Host: goodHost, Port: goodPort, Alive: true},
	}

	// Simular una petición cliente hacia handlePlain
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan string)
	go func() {
		br := bufio.NewReader(clientConn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			done <- fmt.Sprintf("error leyendo respuesta: %v", err)
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- fmt.Sprintf("%d:%s", resp.StatusCode, string(body))
	}()

	brServer := bufio.NewReader(serverConn)
	reqHeaders := map[string]string{
		"host": u.Host,
	}

	a.handlePlain(serverConn, brServer, "GET", targetServer.URL, reqHeaders)

	select {
	case res := <-done:
		if !strings.HasPrefix(res, "200:exito-destino") {
			t.Fatalf("failover silencioso fallo: respuesta recibida %q (esperaba 200:exito-destino)", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout esperando respuesta con failover")
	}

	// Comprobar que el proxy roto acumuló fallo
	if a.proxies[0].Fails == 0 {
		t.Error("el proxy roto debio recibir al menos 1 fail")
	}
}

// TestParseUserParams: valida P2.2 (Parser user-session-country).
func TestParseUserParams(t *testing.T) {
	tests := []struct {
		rawUser     string
		wantSession string
		wantCountry string
		wantRotate  bool
	}{
		{"", "", "", false},
		{"simpleuser", "simpleuser", "", false},
		{"user-session-abc123", "abc123", "", false},
		{"user-session-sess456-country-US", "sess456", "US", false},
		{"user-country-DE", "user", "DE", false},
		{"user-rotate", "", "", true},
		{"user-session-xyz-rotate", "xyz", "", true},
		{"user-country-fr-rotate", "", "FR", true},
		{"user-sessionxyz", "xyz", "", false},
		{"user-countryBR", "user", "BR", false},
	}

	for _, tc := range tests {
		gotSession, gotCountry, gotRotate := parseUserParams(tc.rawUser)
		if gotSession != tc.wantSession || gotCountry != tc.wantCountry || gotRotate != tc.wantRotate {
			t.Errorf("parseUserParams(%q) = (%q, %q, %v); esperados (%q, %q, %v)",
				tc.rawUser, gotSession, gotCountry, gotRotate,
				tc.wantSession, tc.wantCountry, tc.wantRotate)
		}
	}
}

// TestPickWithCountry: valida filtrado por país en selección de proxy.
func TestPickWithCountry(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "10.0.0.1", Port: 8080, Country: "US", Alive: true},
		{Scheme: "http", Host: "10.0.0.2", Port: 8080, Country: "DE", Alive: true},
		{Scheme: "http", Host: "10.0.0.3", Port: 8080, Country: "US", Alive: true},
	}
	a.mu.Lock()
	a.refreshIdxLocked()
	a.mu.Unlock()

	// Pedir país US debe retornar solo 10.0.0.1 o 10.0.0.3
	for i := 0; i < 20; i++ {
		p := a.pickWithCountry("", "US", nil)
		if p == nil || p.Country != "US" {
			t.Fatalf("pickWithCountry con US devolvió proxy no-US: %+v", p)
		}
	}

	// Pedir país DE debe retornar 10.0.0.2
	pDE := a.pickWithCountry("", "DE", nil)
	if pDE == nil || pDE.Host != "10.0.0.2" {
		t.Fatalf("pickWithCountry con DE devolvió: %+v", pDE)
	}

	// Pedir país inexistente (FR) debe caer al pool general sin colgarse
	pFR := a.pickWithCountry("", "FR", nil)
	if pFR == nil {
		t.Fatalf("pickWithCountry con pais desconocido retorno nil")
	}
}

// TestProxyRotateHeader: valida P2.3 (Cabecera X-Proxy-Rotate: 1 y deleteSession).
func TestProxyRotateHeader(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	p1 := &Proxy{Scheme: "http", Host: "10.0.0.1", Port: 8080, Alive: true}
	p2 := &Proxy{Scheme: "http", Host: "10.0.0.2", Port: 8080, Alive: true}
	a.proxies = []*Proxy{p1, p2}
	a.mu.Lock()
	a.refreshIdxLocked()
	a.mu.Unlock()

	// Crear sesión sticky
	sessionID := "sticky-test-123"
	_ = a.pick(sessionID, nil)

	a.mu.Lock()
	if _, ok := a.sessions[sessionID]; !ok {
		a.mu.Unlock()
		t.Fatal("la sesion sticky debio guardarse en a.sessions")
	}
	a.mu.Unlock()

	// Llamar a deleteSession simula la acción disparada por X-Proxy-Rotate
	a.deleteSession(sessionID)

	a.mu.Lock()
	if _, ok := a.sessions[sessionID]; ok {
		a.mu.Unlock()
		t.Fatal("deleteSession no borro la sesion")
	}
	a.mu.Unlock()
}

// TestProxyTxtAdvancedFilters: valida P2.4 (Filtros en /proxy.txt).
func TestProxyTxtAdvancedFilters(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "10.0.0.1", Port: 8080, Country: "US", PingMs: 120, Alive: true, Checked: true},
		{Scheme: "socks5", Host: "10.0.0.2", Port: 1080, Country: "DE", PingMs: 250, Alive: true, Checked: true},
		{Scheme: "socks4", Host: "10.0.0.3", Port: 1080, Country: "US", PingMs: 0, Alive: false, Checked: true},
		{Scheme: "http", Host: "10.0.0.4", Port: 8080, Country: "FR", PingMs: 600, Alive: true, Checked: true},
	}
	a.mu.Lock()
	a.refreshIdxLocked()
	a.mu.Unlock()

	mux := a.APIMux(8080, "127.0.0.1")

	// 1. Filtrar solo vivos (?alive=1)
	req1 := httptest.NewRequest("GET", "/proxy.txt?alive=1", nil)
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)
	body1 := strings.TrimSpace(rec1.Body.String())
	lines1 := strings.Split(body1, "\n")
	if len(lines1) != 3 {
		t.Fatalf("esperados 3 proxies vivos, se recibieron %d:\n%s", len(lines1), body1)
	}

	// 2. Filtrar por país (?country=US&alive=1)
	req2 := httptest.NewRequest("GET", "/proxy.txt?country=US&alive=1", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	body2 := strings.TrimSpace(rec2.Body.String())
	lines2 := strings.Split(body2, "\n")
	if len(lines2) != 1 || !strings.Contains(lines2[0], "10.0.0.1") {
		t.Fatalf("esperado solo 10.0.0.1 para country=US vivo, recibido: %s", body2)
	}

	// 3. Filtrar por protocolo (?proto=socks5)
	req3 := httptest.NewRequest("GET", "/proxy.txt?proto=socks5", nil)
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)
	body3 := strings.TrimSpace(rec3.Body.String())
	if !strings.Contains(body3, "10.0.0.2") || strings.Contains(body3, "10.0.0.1") {
		t.Fatalf("filtro proto=socks5 fallo: %s", body3)
	}

	// 4. Filtrar por max_ping (?max_ping=300&alive=1)
	req4 := httptest.NewRequest("GET", "/proxy.txt?max_ping=300&alive=1", nil)
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req4)
	body4 := strings.TrimSpace(rec4.Body.String())
	lines4 := strings.Split(body4, "\n")
	if len(lines4) != 2 {
		t.Fatalf("esperados 2 proxies con ping <= 300ms, recibidos %d: %s", len(lines4), body4)
	}

	// 5. Formato full (?format=full)
	req5 := httptest.NewRequest("GET", "/proxy.txt?format=full&alive=1", nil)
	rec5 := httptest.NewRecorder()
	mux.ServeHTTP(rec5, req5)
	body5 := rec5.Body.String()
	if !strings.Contains(body5, "http://10.0.0.1:8080") || !strings.Contains(body5, "socks5://10.0.0.2:1080") {
		t.Fatalf("formato full no incluyo esquemas: %s", body5)
	}
}

// TestSOCKS4aZeroDNSLeak: valida P2.1 (SOCKS4a Zero DNS Leak).
func TestSOCKS4aZeroDNSLeak(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallo al escuchar: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		if err != nil {
			done <- fmt.Errorf("read error: %v", err)
			return
		}
		data := buf[:n]

		// Validación del paquete SOCKS4a RFC:
		// [0]: VN = 0x04
		// [1]: CD = 0x01 (CONNECT)
		// [2..3]: Port (443 -> 0x01 0xbb)
		// [4..7]: IP = 0x00 0x00 0x00 0x01 (indica SOCKS4a hostname a resolver remoto)
		if len(data) < 9 {
			done <- fmt.Errorf("paquete socks4a muy corto: %d bytes", len(data))
			return
		}
		if data[0] != 0x04 || data[1] != 0x01 {
			done <- fmt.Errorf("cabecera invalida: %02x %02x", data[0], data[1])
			return
		}
		if data[2] != 0x01 || data[3] != 0xbb {
			done <- fmt.Errorf("puerto esperado 443 (0x01bb), recibido: %02x%02x", data[2], data[3])
			return
		}
		if data[4] != 0x00 || data[5] != 0x00 || data[6] != 0x00 || data[7] != 0x01 {
			done <- fmt.Errorf("IP socks4a esperada 0.0.0.1 (Zero DNS Leak), recibida: %v", data[4:8])
			return
		}

		// Debe contener el dominio al final terminado en \0
		payloadStr := string(data[8:])
		if !strings.Contains(payloadStr, "target.example.com") {
			done <- fmt.Errorf("paquete no contiene target.example.com: %q", payloadStr)
			return
		}

		// Responder OK: 0x00 0x5a (request granted) + 6 bytes arbitrarios
		conn.Write([]byte{0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		done <- nil
	}()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(ln.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortStr)
	p := &Proxy{
		Scheme: "socks4",
		Host:   proxyHost,
		Port:   proxyPort,
		User:   "testuser",
	}

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial a mock socks4 fallo: %v", err)
	}
	defer clientConn.Close()

	if err := socks4Connect(clientConn, p, "target.example.com:443"); err != nil {
		t.Fatalf("socks4Connect fallo: %v", err)
	}

	select {
	case srvErr := <-done:
		if srvErr != nil {
			t.Fatalf("servidor mock detecto paquete SOCKS4a invalido: %v", srvErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout esperando handshake socks4a")
	}
}

// TestConnectPipelinedTLS: valida que peticiones CONNECT que traen datos
// TLS ClientHello en el mismo paquete/lectura no pierdan los bytes bufferizados
// en el bufio.Reader (evita que el handshake TLS de OpenBullet se congele y reintente).
func TestConnectPipelinedTLS(t *testing.T) {
	// 1. Mock upstream HTTP proxy
	targetReceived := make(chan []byte, 1)
	lnProxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("lnProxy error: %v", err)
	}
	defer lnProxy.Close()

	go func() {
		conn, err := lnProxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		// Responde 200 al CONNECT upstream
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// Ahora lee los datos TLS enviados por el cliente
		buf := make([]byte, 128)
		n, err := br.Read(buf)
		if err == nil {
			targetReceived <- buf[:n]
		} else {
			targetReceived <- nil
		}
	}()

	proxyHost, proxyPortStr, _ := net.SplitHostPort(lnProxy.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortStr)

	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: proxyHost, Port: proxyPort, Alive: true},
	}
	a.mu.Lock()
	a.refreshIdxLocked()
	a.mu.Unlock()

	// 2. Gateway listener
	lnGW, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("lnGW error: %v", err)
	}
	defer lnGW.Close()
	go a.ServeGateway(lnGW)

	// 3. Cliente simula OpenBullet enviando CONNECT + TLS ClientHello simulado de golpe
	client, err := net.Dial("tcp", lnGW.Addr().String())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()

	tlsDummyPayload := []byte("\x16\x03\x01\x00\x10MOCK_TLS_CLIENT_HELLO")
	connectReq := []byte("CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com:443\r\n\r\n")

	// Escribir ambos juntos simulando coalescencia TCP / early data
	combined := append(connectReq, tlsDummyPayload...)
	if _, err := client.Write(combined); err != nil {
		t.Fatalf("write combined error: %v", err)
	}

	// Leer respuesta del gateway (200 Connection Established)
	brClient := bufio.NewReader(client)
	respLine, err := brClient.ReadString('\n')
	if err != nil || !strings.Contains(respLine, "200") {
		t.Fatalf("esperado 200 del gateway, recibido: %q, err: %v", respLine, err)
	}

	// Consumir el resto del encabezado 200
	for {
		line, _ := brClient.ReadString('\n')
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// 4. Verificar que el upstream recibió intacto el payload TLS
	select {
	case received := <-targetReceived:
		if !bytes.Equal(received, tlsDummyPayload) {
			t.Fatalf("datos TLS corruptos o perdidos en buffer: esperado %q, recibido %q",
				string(tlsDummyPayload), string(received))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout esperando entrega de TLS ClientHello (se perdió en el buffer del gateway)")
	}
}

// TestTunnelHalfCloseClient: valida que un cliente que envía su petición y
// hace TCP half-close (CloseWrite) no provoque el cierre prematuro del túnel
// antes de recibir la respuesta completa del servidor (elimina errores y retrys en OBM).
func TestTunnelHalfCloseClient(t *testing.T) {
	// Mock upstream
	lnUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream error: %v", err)
	}
	defer lnUpstream.Close()

	go func() {
		conn, err := lnUpstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		// Consume CONNECT
		for {
			l, _ := br.ReadString('\n')
			if l == "\r\n" || l == "\n" {
				break
			}
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// Lee datos de la petición hasta EOF (el cliente hará CloseWrite)
		io.ReadAll(br)

		// Simula tiempo de procesamiento en el servidor y responde
		time.Sleep(50 * time.Millisecond)
		conn.Write([]byte("SERVER_DELAYED_RESPONSE_OK"))
	}()

	upHost, upPortStr, _ := net.SplitHostPort(lnUpstream.Addr().String())
	upPort, _ := strconv.Atoi(upPortStr)

	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: upHost, Port: upPort, Alive: true},
	}
	a.mu.Lock()
	a.refreshIdxLocked()
	a.mu.Unlock()

	lnGW, _ := net.Listen("tcp", "127.0.0.1:0")
	defer lnGW.Close()
	go a.ServeGateway(lnGW)

	client, err := net.Dial("tcp", lnGW.Addr().String())
	if err != nil {
		t.Fatalf("dial gw error: %v", err)
	}
	defer client.Close()

	// Enviar CONNECT
	client.Write([]byte("CONNECT api.target.com:443 HTTP/1.1\r\nHost: api.target.com:443\r\n\r\n"))
	brC := bufio.NewReader(client)
	for {
		l, _ := brC.ReadString('\n')
		if l == "\r\n" || l == "\n" {
			break
		}
	}

	// Cliente envía payload y hace CloseWrite
	client.Write([]byte("POST_DATA_FINISHED"))
	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}

	// Leer respuesta del servidor
	resp, err := io.ReadAll(brC)
	if err != nil && err != io.EOF {
		t.Fatalf("error leyendo respuesta tras half-close: %v", err)
	}
	if string(resp) != "SERVER_DELAYED_RESPONSE_OK" {
		t.Fatalf("respuesta cortada prematuramente: esperado 'SERVER_DELAYED_RESPONSE_OK', recibido %q", string(resp))
	}
}
