package main

// Tests de las mejoras del 20/10/2026 (pedido del usuario, estilo
// "Proxy Checker by xRisky"):
//
//  1. Los reintentos del health-check ROTAN el protocolo: el primer intento
//     usa el esquema declarado y cada reintento prueba otro distinto
//     (socks5 -> socks4 -> http). Si el proxy responde con otro protocolo se
//     recuerda en AltScheme y el trafico real lo usa (EffScheme).
//  2. Dos modos de chequeo:
//       "alive" -> solo vivos + nunca verificados (barato, por defecto)
//       "full"  -> chequeo COMPLETO de la lista en cada ciclo
//     Se eligen con --check-mode y se cambian en caliente con
//     POST /set-check-mode (el panel).

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSchemeCascade: el propio esquema primero y despues los otros dos,
// sin repetir ninguno.
func TestSchemeCascade(t *testing.T) {
	casos := map[string][]string{
		"http":    {"http", "socks5", "socks4"},
		"socks5":  {"socks5", "socks4", "http"},
		"socks4":  {"socks4", "socks5", "http"},
		"socks4a": {"socks4a", "socks5", "socks4", "http"},
		"":        {"socks5", "socks4", "http"},
	}
	for own, want := range casos {
		got := schemeCascade(own)
		if len(got) != len(want) {
			t.Fatalf("schemeCascade(%q) = %v, esperaba %v", own, got, want)
		}
		seen := map[string]bool{}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("schemeCascade(%q) = %v, esperaba %v", own, got, want)
			}
			if seen[got[i]] {
				t.Fatalf("schemeCascade(%q) repite %s: %v", own, got[i], got)
			}
			seen[got[i]] = true
		}
	}
}

// fakeSocks5Tunnel levanta un SOCKS5 que tuneliza de verdad (para poder
// validar un proxy "rotulado" como http que en realidad es socks5).
func fakeSocks5Tunnel(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(br, hdr); err != nil {
					return
				}
				io.ReadFull(br, make([]byte, hdr[1]))
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				req := make([]byte, 4)
				if _, err := io.ReadFull(br, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 0x01: // IPv4
					b := make([]byte, 4)
					io.ReadFull(br, b)
					host = net.IP(b).String()
				case 0x03: // dominio
					l := make([]byte, 1)
					io.ReadFull(br, l)
					b := make([]byte, int(l[0]))
					io.ReadFull(br, b)
					host = string(b)
				default:
					return
				}
				pb := make([]byte, 2)
				io.ReadFull(br, pb)
				port := int(pb[0])<<8 | int(pb[1])
				up, err := net.DialTimeout("tcp", net.JoinHostPort(host, itoa(port)), 3*time.Second)
				if err != nil {
					c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				go func() { io.Copy(up, br); up.Close() }()
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestHealthCheckRotaProtocolo: un proxy DECLARADO http que en realidad es
// socks5 debe detectarse (AltScheme=socks5) en vez de darse por muerto.
func TestHealthCheckRotaProtocolo(t *testing.T) {
	// Destino: un servidor HTTP local.
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer dst.Close()
	dstHost, dstPort := splitAddr(t, strings.TrimPrefix(dst.URL, "http://"))

	// "Proxy" roto: en realidad es un SOCKS5.
	addr, closeFn := fakeSocks5Tunnel(t)
	defer closeFn()
	ph, pp := splitAddr(t, addr)

	p := &Proxy{Scheme: "http", Host: ph, Port: pp}
	sp := checkSpec{url: "http://" + dstHost + ":" + itoa(dstPort) + "/", timeout: 3 * time.Second}

	ok, ping, used := checkWithProtocolRotation(p, sp, 3)
	if !ok {
		t.Fatal("el proxy (rotulado http, real socks5) deberia responder con la cascada")
	}
	if used != "socks5" {
		t.Fatalf("protocolo detectado = %q, esperaba socks5", used)
	}
	if ping < 0 {
		t.Fatalf("ping invalido: %d", ping)
	}
}

// TestHealthCheckRotaNoReclasificaSiElDeclaradoSirve: un proxy http que
// funciona como http NO debe marcarse con AltScheme.
func TestHealthCheckRotaNoReclasificaSiElDeclaradoSirve(t *testing.T) {
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer dst.Close()
	dstHost, dstPort := splitAddr(t, strings.TrimPrefix(dst.URL, "http://"))

	// Proxy HTTP real minimo: responde 200 a cualquier GET.
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
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
			}(c)
		}
	}()
	ph, pp := splitAddr(t, ln.Addr().String())

	p := &Proxy{Scheme: "http", Host: ph, Port: pp}
	sp := checkSpec{url: "http://" + dstHost + ":" + itoa(dstPort) + "/", timeout: 3 * time.Second}
	ok, _, used := checkWithProtocolRotation(p, sp, 3)
	if !ok {
		t.Fatal("el proxy http deberia responder")
	}
	if used != "http" {
		t.Fatalf("protocolo detectado = %q, esperaba http (sin reclasificar)", used)
	}
}

// TestEffSchemeUsaAlt: el trafico real usa el protocolo detectado.
func TestEffSchemeUsaAlt(t *testing.T) {
	p := &Proxy{Scheme: "http", Host: "1.2.3.4", Port: 8080}
	if p.EffScheme() != "http" {
		t.Fatalf("EffScheme sin Alt = %q", p.EffScheme())
	}
	p.AltScheme = "socks5"
	if p.EffScheme() != "socks5" {
		t.Fatalf("EffScheme con Alt = %q, esperaba socks5", p.EffScheme())
	}
}

// TestScopeAliveVsFull: el modo "alive" NO toca los proxies ya marcados
// como muertos y verificados; el modo "full" si los re-revisa.
func TestScopeAliveVsFull(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.checkRetries = 0
	a.checkTimeout = 300 * time.Millisecond
	vivo := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: true, Checked: true, LastCheck: 111}
	muerto := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: false, Checked: true, LastCheck: 222}
	nuevo := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: true, Checked: false, LastCheck: 0}
	a.proxies = []*Proxy{vivo, muerto, nuevo}

	// Modo alive: el muerto verificado queda fuera.
	a.runChecksScope("alive")
	if !muerto.Checked || muerto.LastCheck != 222 {
		t.Fatalf("modo alive toco el proxy muerto verificado (lastcheck=%d)", muerto.LastCheck)
	}
	if nuevo.LastCheck == 0 {
		t.Fatal("modo alive no reviso el proxy nunca verificado")
	}

	// Modo full: el muerto verificado entra en la cola.
	muerto.LastCheck = 222
	a.runChecksScope("all")
	if muerto.LastCheck == 222 {
		t.Fatal("modo full no re-reviso el proxy muerto verificado")
	}
}

// TestSetCheckModeAPI: el panel puede cambiar el modo en caliente.
func TestSetCheckModeAPI(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	mux := a.APIMux(8080, "127.0.0.1")

	// Sin cabecera de panel -> 403.
	req := httptest.NewRequest(http.MethodPost, "/set-check-mode?mode=full", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("sin cabecera de panel: HTTP %d, esperaba 403", rec.Code)
	}

	// Con cabecera: cambia el modo.
	req = httptest.NewRequest(http.MethodPost, "/set-check-mode?mode=full", nil)
	req.Header.Set("X-GW-Panel", "1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("con cabecera: HTTP %d (%s)", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out["check_mode"] != "full" {
		t.Fatalf("respuesta = %v, esperaba check_mode=full", out)
	}
	if a.checkScopeName() != "full" {
		t.Fatalf("checkScopeName = %q, esperaba full", a.checkScopeName())
	}

	// Modo invalido -> 400.
	req = httptest.NewRequest(http.MethodPost, "/set-check-mode?mode=inventado", nil)
	req.Header.Set("X-GW-Panel", "1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("modo invalido: HTTP %d, esperaba 400", rec.Code)
	}

	// /stats expone el modo.
	req = httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var st map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st["check_mode"] != "full" {
		t.Fatalf("/stats check_mode = %v, esperaba full", st["check_mode"])
	}
	if st["check_retries"] == nil {
		t.Fatal("/stats no expone check_retries")
	}
}
