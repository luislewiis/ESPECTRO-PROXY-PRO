package main

// Tests de la integracion con OB M2 / SilverBullet (auditoria 20/10/2026):
//
//  1. /proxy.txt acepta ?max=N (y su alias ?limit=N) para no volcar 12k+
//     lineas en el ProxyManager de OB: la UI se congela y el runner parece
//     "caerse" antes de arrancar. El tope se aplica DESPUES de ordenar.
//  2. ?max=0 / negativo = sin tope (compatibilidad con la URL historica).
//  3. ?max= enorme se recorta al techo maxProxyTxtLines.
//  4. /proxy.txt responde Cache-Control: no-store (OB re-descarga la fuente
//     al recargar; ningun intermediario debe servir una lista vieja).
//  5. El tope respeta los filtros (scheme/format) y el formato OB.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// muxConPings arma un App con proxies validados de ping conocido.
func muxConPings(t *testing.T) *http.ServeMux {
	t.Helper()
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "10.0.0.1", Port: 1001, Alive: true, Checked: true, PingMs: 300},
		{Scheme: "http", Host: "10.0.0.2", Port: 1002, Alive: true, Checked: true, PingMs: 50},
		{Scheme: "http", Host: "10.0.0.3", Port: 1003, Alive: true, Checked: true, PingMs: 900},
		{Scheme: "socks5", Host: "10.0.0.4", Port: 1004, Alive: true, Checked: true, PingMs: 120},
		{Scheme: "http", Host: "10.0.0.5", Port: 1005, Alive: true, Checked: true, PingMs: 10},
		{Scheme: "http", Host: "10.0.0.6", Port: 1006, Alive: true, Checked: true, PingMs: 700},
	}
	return a.APIMux(8080, "127.0.0.1")
}

func TestProxyTxtMaxTrasOrdenar(t *testing.T) {
	mux := muxConPings(t)

	got := proxyTxtLines(t, mux, "/proxy.txt?alive=1&sort=ping&max=3")
	if len(got) != 3 {
		t.Fatalf("max=3 devolvio %d lineas: %v", len(got), got)
	}
	// Los 3 de menor ping: 10.0.0.5 (10ms), 10.0.0.2 (50ms), 10.0.0.4 (120ms).
	want := []string{"10.0.0.5:1005", "10.0.0.2:1002", "10.0.0.4:1004"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orden/tope incorrecto en pos %d: got=%v want=%v", i, got, want)
		}
	}
}

func TestProxyTxtMaxSinTope(t *testing.T) {
	mux := muxConPings(t)

	for _, q := range []string{"?alive=1&max=0", "?alive=1&max=-5", ""} {
		got := proxyTxtLines(t, mux, "/proxy.txt"+q)
		if len(got) != 6 {
			t.Fatalf("%q devolvio %d lineas, esperaba 6", q, len(got))
		}
	}

	// Techo duro: un ?max gigante no recorta por debajo del pool, solo evita
	// desbordes absurdos.
	got := proxyTxtLines(t, mux, "/proxy.txt?alive=1&max=999999")
	if len(got) != 6 {
		t.Fatalf("max gigante devolvio %d lineas, esperaba 6", len(got))
	}
}

func TestProxyTxtMaxAliasLimit(t *testing.T) {
	mux := muxConPings(t)

	got := proxyTxtLines(t, mux, "/proxy.txt?alive=1&limit=2")
	if len(got) != 2 {
		t.Fatalf("limit=2 devolvio %d lineas: %v", len(got), got)
	}
}

func TestProxyTxtMaxRespetaFiltrosYFormatoOB(t *testing.T) {
	mux := muxConPings(t)

	// Solo socks5 queda uno: el tope no debe inventar lineas ni colar http.
	got := proxyTxtLines(t, mux, "/proxy.txt?alive=1&scheme=socks5&max=10")
	if len(got) != 1 || got[0] != "10.0.0.4:1004" {
		t.Fatalf("scheme=socks5&max=10 = %v", got)
	}

	// format=ob: tipo:host:puerto[:user:pass] y el tope corta igual.
	got = proxyTxtLines(t, mux, "/proxy.txt?alive=1&format=ob&sort=ping&max=1")
	if len(got) != 1 {
		t.Fatalf("format=ob&max=1 = %v", got)
	}
	if !strings.HasPrefix(got[0], "0:10.0.0.5:1005") && !strings.Contains(got[0], "10.0.0.5:1005") {
		t.Fatalf("format=ob no devolvio el proxy mas rapido: %v", got)
	}
}

func TestProxyTxtCacheNoStore(t *testing.T) {
	mux := muxConPings(t)

	req := httptest.NewRequest(http.MethodGet, "/proxy.txt?alive=1&max=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, esperaba no-store", cc)
	}
}
