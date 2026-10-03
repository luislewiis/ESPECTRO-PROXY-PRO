package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSessionTTLExpira(t *testing.T) {
	a := NewApp(nil, "sticky", true, 0, "")
	a.proxies = []*Proxy{{Scheme: "http", Host: "1.1.1.1", Port: 8080, Alive: true}}

	if p := a.pick("s1", nil); p == nil {
		t.Fatal("pick devolvio nil")
	}
	if len(a.sessions) != 1 {
		t.Fatalf("esperaba 1 sesion, hay %d", len(a.sessions))
	}

	// envejecer la sesion mas alla del TTL y barer
	a.mu.Lock()
	si := a.sessions["s1"]
	si.lastSeen = time.Now().Add(-sessionTTL - time.Minute)
	a.sessions["s1"] = si
	a.mu.Unlock()

	a.SweepSessions()
	if len(a.sessions) != 0 {
		t.Fatalf("TTL no expiro la sesion inactiva (%d restantes)", len(a.sessions))
	}
}

func TestSessionTocaLastSeen(t *testing.T) {
	a := NewApp(nil, "sticky", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "1.1.1.1", Port: 8080, Alive: true},
		{Scheme: "http", Host: "2.2.2.2", Port: 8080, Alive: true},
	}
	a.pick("s1", nil)
	a.mu.Lock()
	si := a.sessions["s1"]
	si.lastSeen = time.Now().Add(-sessionTTL + 2*time.Minute)
	a.sessions["s1"] = si
	a.mu.Unlock()

	// el uso de la sesion refresca lastSeen -> no debe expirar
	a.pick("s1", nil)
	a.SweepSessions()
	if len(a.sessions) != 1 {
		t.Fatalf("la sesion activa expiro: %d restantes", len(a.sessions))
	}
}

func TestSessionCap(t *testing.T) {
	old := maxSessions
	maxSessions = 3
	t.Cleanup(func() { maxSessions = old })

	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{{Scheme: "http", Host: "1.1.1.1", Port: 8080, Alive: true}}

	for i := 0; i < 5; i++ {
		if p := a.pick(fmt.Sprintf("sx%d", i), nil); p == nil {
			t.Fatal("pick devolvio nil")
		}
	}
	if len(a.sessions) > maxSessions {
		t.Fatalf("cap excedido: %d > %d", len(a.sessions), maxSessions)
	}
}

// TestSessionKeyCap: claves de sesion >64 chars se rechazan (DoS de memoria).
func TestSessionKeyCap(t *testing.T) {
	b64 := func(s string) string {
		return "basic " + base64.StdEncoding.EncodeToString([]byte(s))
	}
	if got := SessionFromHeaders(map[string]string{"proxy-authorization": b64(strings.Repeat("x", 65) + ":clave")}); got != "" {
		t.Fatalf("sesion de 65 chars debio rechazarse, got %q", got)
	}
	if got := SessionFromHeaders(map[string]string{"proxy-authorization": b64(strings.Repeat("x", 64) + ":clave")}); len(got) != 64 {
		t.Fatalf("sesion de 64 chars debio aceptarse, got len=%d", len(got))
	}
	if got := SessionFromHeaders(map[string]string{"proxy-authorization": b64("mikey:clave")}); got != "mikey" {
		t.Fatalf("sesion normal rota: %q", got)
	}
}
