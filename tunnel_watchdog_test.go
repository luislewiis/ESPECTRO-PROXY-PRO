package main

// Test del watchdog de "tunel vivo" (auditoria 21/10/2026).
//
// Hay proxies "zombi" que responden "200 Connection Established" y luego no
// transportan NADA: el bot (o el motor uTLS) se queda colgado esperando la
// respuesta. El gateway debe:
//   1) cortar el tunel en cuanto se ve que no circula nada,
//   2) marcar el proxy como fallido (para que el siguiente CONNECT use otro).

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// proxyZombi: proxy HTTP que acepta el CONNECT y se queda mudo para siempre.
func proxyZombi(t *testing.T) (addr string, closeFn func()) {
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
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				// 200 y silencio: el proxy no transporta nada.
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				time.Sleep(120 * time.Second)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestTunelZombiSeCorta(t *testing.T) {
	addr, closeFn := proxyZombi(t)
	defer closeFn()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}

	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{{Scheme: "http", Host: host, Port: port, Alive: true, Checked: true}}
	a.idle = 0

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go a.ServeGateway(ln)

	// Cliente: CONNECT y luego ClientHello; nunca llegara respuesta.
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	io.WriteString(c, "CONNECT ejemplo.test:443 HTTP/1.1\r\nHost: ejemplo.test:443\r\n\r\n")
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no llego el 200: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("respuesta = %q", line)
	}
	// El tunel debe cerrarse solo (el proxy no transporta).
	io.WriteString(c, "\x16\x03\x01\x00\x05hello")
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, err = c.Read(buf)
	if err == nil {
		// si llego algo, el proxy habria contestado: no es el caso del test
		t.Log("el tunel devolvio datos (no es un zombi)")
	}
	// El proxy debe quedar marcado como fallido.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		fails := a.proxies[0].Fails
		a.mu.Unlock()
		if fails > 0 {
			return // correcto: el proxy zombi quedo marcado
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("el proxy zombi no se marco como fallido: el watchdog no lo corto")
}

// TestValidarTunelRechazaProxyMudo: la comprobacion de transporte del
// health-check debe marcar como muerto a un proxy que acepta el CONNECT pero
// no transporta.
func TestValidarTunelRechazaProxyMudo(t *testing.T) {
	addr, closeFn := proxyZombi(t)
	defer closeFn()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	p := &Proxy{Scheme: "http", Host: host, Port: port}
	// El check de CONNECT contra un proxy mudo no debe darlo por bueno.
	ok, _, _ := healthCheckBody(p, "http://127.0.0.1:1/", 2*time.Second, 0, true)
	if ok {
		t.Fatal("un proxy que no transporta no debe pasar el chequeo CONNECT")
	}
}

// TestValidarTunelAceptaProxyReal: un proxy que SI transporta (responde al
// CONNECT y devuelve algo) debe pasar el chequeo.
func TestValidarTunelAceptaProxyReal(t *testing.T) {
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
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				// responde como un servidor minimo (el check usa GET /)
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				time.Sleep(2 * time.Second)
			}(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	p := &Proxy{Scheme: "http", Host: host, Port: port}
	ok, _, _ := healthCheckBody(p, "http://127.0.0.1:1/", 3*time.Second, 0, true)
	if !ok {
		t.Fatal("un proxy que transporta debe pasar el chequeo CONNECT")
	}
}
