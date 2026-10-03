package main

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// scriptedListener acepta conexiones y responde siempre con resp.
func scriptedListener(t *testing.T, resp []byte) (addr string, closeFn func()) {
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
				buf := make([]byte, 1024)
				c.Read(buf)
				if resp != nil {
					c.Write(resp)
				}
				// mantener abierto un momento para que el cliente lea
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestDialRefusedEsUpstream(t *testing.T) {
	// puerto cerrado: fallo de transporte al proxy -> upstream
	_, _, err := dialThrough(&Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1},
		"example.com:443", 2*time.Second)
	if err == nil || !isUpstreamErr(err) {
		t.Fatalf("dial rechazado debe ser upstreamError, got: %v", err)
	}
}

func TestCONNECT502NoMarcaUpstream(t *testing.T) {
	addr, closeFn := scriptedListener(t, []byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	defer closeFn()
	host, port := splitAddr(t, addr)
	p := &Proxy{Scheme: "http", Host: host, Port: port}

	_, _, err := httpConnect(p, "example.com:443", 2*time.Second)
	if err == nil {
		t.Fatal("esperaba error con 502")
	}
	if isUpstreamErr(err) {
		t.Fatalf("502 del proxy NO debe ser upstreamError (el proxy respondio): %v", err)
	}
}

func TestCONNECT407SiMarcaUpstream(t *testing.T) {
	addr, closeFn := scriptedListener(t, []byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	defer closeFn()
	host, port := splitAddr(t, addr)
	p := &Proxy{Scheme: "http", Host: host, Port: port}

	_, _, err := httpConnect(p, "example.com:443", 2*time.Second)
	if err == nil || !isUpstreamErr(err) {
		t.Fatalf("407 (credenciales) debe ser upstreamError, got: %v", err)
	}
}

func TestSOCKS5RepFalloNoMarcaUpstream(t *testing.T) {
	// handshake valido + reply rep=0x05 (rechazo por reglas) -> fallo del destino
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		// greeting
		hdr := make([]byte, 2)
		io.ReadFull(br, hdr)
		methods := make([]byte, hdr[1])
		io.ReadFull(br, methods)
		c.Write([]byte{0x05, 0x00})
		// connect request: leer hasta puerto
		req := make([]byte, 5)
		io.ReadFull(br, req)
		n := int(req[4])
		rest := make([]byte, n+2)
		io.ReadFull(br, rest)
		// reply: rep=0x05 (connection refused by ruleset)
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		time.Sleep(200 * time.Millisecond)
	}()
	host, port := splitAddr(t, ln.Addr().String())
	p := &Proxy{Scheme: "socks5", Host: host, Port: port}

	c, _, err := dialThrough(p, "example.com:443", 2*time.Second)
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("esperaba error con rep=0x05")
	}
	if isUpstreamErr(err) {
		t.Fatalf("rep del proxy NO debe ser upstreamError: %v", err)
	}
}

func TestSOCKS5CierrePrecozoSiMarcaUpstream(t *testing.T) {
	// el proxy acepta y cierra sin responder: protocolo roto -> upstream
	addr, closeFn := scriptedListener(t, nil)
	defer closeFn()
	host, port := splitAddr(t, addr)
	p := &Proxy{Scheme: "socks5", Host: host, Port: port}

	c, _, err := dialThrough(p, "example.com:443", 2*time.Second)
	if c != nil {
		c.Close()
	}
	if err == nil || !isUpstreamErr(err) {
		t.Fatalf("cierre del proxy debe ser upstreamError, got: %v", err)
	}
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	return host, port
}
