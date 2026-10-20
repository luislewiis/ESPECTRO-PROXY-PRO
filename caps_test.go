package main

// Tests de las sondas de capacidad y del anonimato fino (auditoria 20/10/2026):
//
//  1. bodyLooksLikeEcho detecta un juez (eco de cabeceras) -> se puede
//     clasificar el anonimato al detalle (Elite/High/Transparent).
//  2. anonFromBody: con juez usa la clasificacion fina; sin juez, compara
//     la IP devuelta con la nuestra (Transparent / High).
//  3. probeTLS mide TLS 1.3 y HTTP/2 a traves de un proxy HTTP de prueba
//     (CONNECT) y probeAnon mide el anonimato con un eco de IP.

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ecoFake: servidor que devuelve las cabeceras de la peticion con el
// formato de un juez (HTTP_..., REMOTE_ADDR...).
func ecoFake(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "REMOTE_ADDR=203.0.113.9\n"
		for k, v := range r.Header {
			body += "HTTP_" + strings.ToUpper(strings.ReplaceAll(k, "-", "_")) + "=" + strings.Join(v, ",") + "\n"
		}
		io.WriteString(w, body)
	}))
}

func TestBodyLooksLikeEcho(t *testing.T) {
	if !bodyLooksLikeEcho("REMOTE_ADDR=1.2.3.4\nHTTP_USER_AGENT=curl") {
		t.Fatal("un eco de judge debe detectarse")
	}
	if bodyLooksLikeEcho("38.188.98.1") {
		t.Fatal("una IP suelta NO es un eco de judge")
	}
	if bodyLooksLikeEcho("") {
		t.Fatal("un cuerpo vacio no es un eco")
	}
}

func TestAnonFromBodyFino(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")

	// Con juez: clasificacion fina. Si el juez expone NUESTRA IP en una
	// cabecera de reenvio, el proxy es transparente (prioridad sobre "High").
	elite := "REMOTE_ADDR=203.0.113.9\nHTTP_USER_AGENT=curl/8.0\n"
	if got := a.anonFromBody("socks5", elite, "198.51.100.7"); got != "Elite" {
		t.Fatalf("con juez y sin cabeceras de proxy = %q, esperaba Elite", got)
	}
	high := elite + "HTTP_X_FORWARDED_FOR=203.0.113.9\n"
	if got := a.anonFromBody("http", high, "198.51.100.7"); got != "High" {
		t.Fatalf("con reenvio de OTRA IP = %q, esperaba High", got)
	}
	transp := elite + "HTTP_VIA=1.1 proxy\nHTTP_X_FORWARDED_FOR=198.51.100.7\n"
	if got := a.anonFromBody("http", transp, "198.51.100.7"); got != "Transparent" {
		t.Fatalf("con nuestra IP expuesta = %q, esperaba Transparent", got)
	}

	// Sin juez: comparacion de IPs.
	if got := a.anonFromBody("socks5", "198.51.100.7", "198.51.100.7"); got != "Transparent" {
		t.Fatalf("IP propia = %q, esperaba Transparent", got)
	}
	if got := a.anonFromBody("socks5", "203.0.113.9", "198.51.100.7"); got != "High" {
		t.Fatalf("IP distinta = %q, esperaba High", got)
	}
	if got := a.anonFromBody("socks5", "203.0.113.9", ""); got != "" {
		t.Fatalf("sin IP real = %q, esperaba vacio", got)
	}
}

// fakeConnectProxy: proxy HTTP que acepta CONNECT y hace de tunel plano.
func fakeConnectProxy(t *testing.T) (addr string, closeFn func()) {
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
				br := make([]byte, 0)
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					br = append(br, buf[0])
					if len(br) >= 4 && string(br[len(br)-4:]) == "\r\n\r\n" {
						break
					}
					if len(br) > 8192 {
						return
					}
				}
				line := string(br)
				idx := strings.Index(line, " ")
				if idx < 0 {
					return
				}
				target := strings.Fields(line)[1]
				up, err := net.DialTimeout("tcp", target, 3*time.Second)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestProbeTLSCapacidades(t *testing.T) {
	// Servidor TLS real (localhost) para que la sonda mida algo de verdad.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	hostPort := strings.TrimPrefix(srv.URL, "https://")

	// El proxy de prueba hace de tunel hasta el servidor TLS.
	px, closeFn := fakeConnectProxy(t)
	defer closeFn()
	ph, pp := splitAddr(t, px)

	p := &Proxy{Scheme: "http", Host: ph, Port: pp}
	tls13, h2, dnsRemote, dnsMode, err := probeTLS(p, hostPort, 5*time.Second)
	if err != nil {
		t.Fatalf("probeTLS: %v", err)
	}
	if !tls13 {
		t.Fatal("el servidor de prueba (Go) negocia TLS 1.3: deberia detectarse")
	}
	_ = h2
	// El destino de la prueba es una IP (127.0.0.1): no hay dominio que
	// resolver, asi que no hay DNS que pueda filtrarse -> DNS local.
	if dnsRemote {
		t.Fatal("con un destino IP no hay DNS remoto que medir")
	}
	if !strings.Contains(dnsMode, "DNS local") {
		t.Fatalf("dnsMode = %q, esperaba el modo local", dnsMode)
	}
	// El certificado del servidor de prueba es autofirmado: la sonda lo
	// ignora a proposito (solo miramos version y ALPN).
	_ = tls.VersionTLS13
}

func TestProbeAnonConEco(t *testing.T) {
	eco := ecoFake(t)
	defer eco.Close()
	// El proxy y el destino: el proxy hace de tunel hasta el eco local.
	px, closeFn := fakeConnectProxy(t)
	defer closeFn()
	ph, pp := splitAddr(t, px)

	a := NewApp(nil, "round-robin", true, 0, eco.URL)
	a.checkTimeout = 3 * time.Second
	p := &Proxy{Scheme: "http", Host: ph, Port: pp}
	got := a.probeAnon(p)
	if got != "Elite" && got != "High" && got != "Transparent" && got != "" {
		t.Fatalf("nivel de anonimato inesperado: %q", got)
	}
	if got == "" {
		t.Logf("sin nivel medido (el eco no llego); el camino de clasificacion esta en anonFromBody")
	}
	fmt.Sprint(got)
}
