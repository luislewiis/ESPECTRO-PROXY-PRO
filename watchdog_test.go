package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// RED-01: el watchdog idle debe cerrar conexiones sin actividad.
func TestIdleConnTimeout(t *testing.T) {
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
		// servidor mudo: nunca escribe
		time.Sleep(3 * time.Second)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ic := &idleConn{Conn: c, d: 300 * time.Millisecond}
	start := time.Now()
	_, err = ic.Read(make([]byte, 1))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("esperaba timeout de inactividad")
	}
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("error no es timeout: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("watchdog demasiado lento: %v", elapsed)
	}
}

// SEC-03: la query no debe aparecer en los logs.
func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"http://x.com/a?token=SECRETO": "http://x.com/a?[redact]",
		"http://x.com/a":               "http://x.com/a",
		"http://x.com/a?k=1&api_key=2": "http://x.com/a?[redact]",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, esperaba %q", in, got, want)
		}
	}
	// el truncado combinado no puede filtrar la cola
	got := redactURL(truncate("http://x.com/p?q=SECRETO_MUY_LARGO", 90))
	if strings.Contains(got, "SECRETO") {
		t.Errorf("se filtro el secreto: %s", got)
	}
}
