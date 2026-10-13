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

// TestCONNECT502MarcaUpstream: el proxy respondio pero NO pudo tunelizar.
// Semantica CAMBIADA (evidencia: A/B bajo carga el 2026-10-12): con pools
// de proxies publicos hay muchos que superan el health-check (cualquier
// respuesta HTTP vale) y luego no tunelizan; si el 502 no contaba como
// fallo del proxy, la rotacion los reelegia sin fin y cada bot pagaba el
// timeout completo -> la corrida de OB "se pausaba". Ahora el 502 marca
// fallo del proxy (3 fallos = muerte; --check-all lo revive si recupera).
func TestCONNECT502MarcaUpstream(t *testing.T) {
	addr, closeFn := scriptedListener(t, []byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	defer closeFn()
	host, port := splitAddr(t, addr)
	p := &Proxy{Scheme: "http", Host: host, Port: port}

	_, _, err := httpConnect(p, "example.com:443", 2*time.Second)
	if err == nil {
		t.Fatal("esperaba error con 502")
	}
	if !isUpstreamErr(err) {
		t.Fatalf("502 del proxy en CONNECT debe ser upstreamError (no pudo tunelizar): %v", err)
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
		// reply: rep=0x05 (connection refused — destino, NO el proxy;
		// ver TestSocks5REPDelProxyEsUpstream para los REP del proxy)
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

// TestSocks5REPDelProxyEsUpstream: los REP de culpa del PROXY (RFC 1928:
// 01 fallo general, 02 ruleset, 07 comando no soportado, 08 atyp no
// soportado) deben contar como fallo del proxy. Mismo bug que el 502 del
// CONNECT http en su dia: un SOCKS junk que siempre devolvia estos REP
// nunca moria en la rotacion y la corrida "se pausaba".
func TestSocks5REPDelProxyEsUpstream(t *testing.T) {
	for _, rep := range []byte{0x01, 0x02, 0x07, 0x08} {
		addr, closeFn := socks5RepServer(t, rep)
		host, port := splitAddr(t, addr)
		p := &Proxy{Scheme: "socks5", Host: host, Port: port}
		c, _, err := dialThrough(p, "example.com:443", 2*time.Second)
		if c != nil {
			c.Close()
		}
		closeFn()
		if err == nil || !isUpstreamErr(err) {
			t.Fatalf("REP 0x%02X (culpa del proxy) debe ser upstreamError, got: %v", rep, err)
		}
	}
}

// TestSocks5REPDestinoNoMarcaUpstream: REP 03-06 son fallo de la red o del
// destino (ARQ-01): no matan al proxy.
func TestSocks5REPDestinoNoMarcaUpstream(t *testing.T) {
	for _, rep := range []byte{0x03, 0x04, 0x05, 0x06} {
		addr, closeFn := socks5RepServer(t, rep)
		host, port := splitAddr(t, addr)
		p := &Proxy{Scheme: "socks5", Host: host, Port: port}
		c, _, err := dialThrough(p, "example.com:443", 2*time.Second)
		if c != nil {
			c.Close()
		}
		closeFn()
		if err == nil {
			t.Fatalf("REP 0x%02X: esperaba error", rep)
		}
		if isUpstreamErr(err) {
			t.Fatalf("REP 0x%02X (destino) NO debe ser upstreamError, got: %v", rep, err)
		}
	}
}

// socks5RepServer simula un servidor SOCKS5 que responde al greeting con
// "sin auth" y a cualquier CONNECT con el REP dado.
func socks5RepServer(t *testing.T, rep byte) (addr string, closeFn func()) {
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
				if _, err := io.ReadFull(br, hdr); err != nil { // greeting
					return
				}
				io.ReadFull(br, make([]byte, hdr[1]))
				c.Write([]byte{0x05, 0x00}) // elegimos "sin auth"
				req := make([]byte, 5)
				if _, err := io.ReadFull(br, req); err != nil { // request
					return
				}
				io.ReadFull(br, make([]byte, int(req[4])+2)) // host+puerto
				// REP, atyp IPv4 0.0.0.0:0
				c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// TestSocks4RepIdentdEsUpstream: CD 5C/5D (el proxy no pudo verificar al
// cliente via identd) son fallo operativo del proxy respecto a nuestro
// trafico, no del destino -> upstreamError. El 5B generico queda como
// fallo del destino (conservador).
func TestSocks4RepIdentdEsUpstream(t *testing.T) {
	for _, rep := range []byte{0x5C, 0x5D} {
		addr, closeFn := socks4RespServer(t, rep)
		host, port := splitAddr(t, addr)
		p := &Proxy{Scheme: "socks4", Host: host, Port: port}
		c, _, err := dialThrough(p, "example.com:443", 2*time.Second)
		if c != nil {
			c.Close()
		}
		closeFn()
		if err == nil || !isUpstreamErr(err) {
			t.Fatalf("CD 0x%02X (identd) debe ser upstreamError, got: %v", rep, err)
		}
	}
	addr, closeFn := socks4RespServer(t, 0x5B)
	defer closeFn()
	host, port := splitAddr(t, addr)
	p := &Proxy{Scheme: "socks4", Host: host, Port: port}
	c, _, err := dialThrough(p, "example.com:443", 2*time.Second)
	if c != nil {
		c.Close()
	}
	if err == nil || isUpstreamErr(err) {
		t.Fatalf("CD 0x5B generico NO debe ser upstreamError, got: %v", err)
	}
}

// socks4RespServer simula un servidor SOCKS4 que responde a cualquier
// request con el codigo CD dado.
func socks4RespServer(t *testing.T, rep byte) (addr string, closeFn func()) {
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
				// request: VN CD PORT IP(4) userid\0 [host\0 si socks4a]
				head := make([]byte, 8)
				if _, err := io.ReadFull(br, head); err != nil {
					return
				}
				if _, err := br.ReadByte(); err != nil { // primer byte de userid
					return
				}
				for { // resto del userid hasta \0
					b, err := br.ReadByte()
					if err != nil || b == 0 {
						break
					}
				}
				// socks4a: si la IP es 0.0.0.1 viene el host terminado en \0
				if head[4] == 0 && head[5] == 0 && head[6] == 0 && head[7] == 1 {
					for {
						b, err := br.ReadByte()
						if err != nil || b == 0 {
							break
						}
					}
				}
				c.Write([]byte{0x00, rep, 0x00, 0x00, 0, 0, 0, 0})
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
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
