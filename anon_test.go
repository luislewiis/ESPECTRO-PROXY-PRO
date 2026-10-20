package main

// Tests del anonimato por proxy (20/10/2026):
//
//  1. clasificaAnon: si el proxy devuelve NUESTRA IP es TRANSPARENTE; si
//     devuelve otra IP, oculta la nuestra (High). Sin cuerpo o sin IP real
//     no se inventa nada (devuelve "").
//  2. La activacion del checker masivo lleva el anonimato medido al pool.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClasificaAnon(t *testing.T) {
	casos := []struct {
		body, real, want string
	}{
		{"203.0.113.9", "198.51.100.7", "High"},         // IP distinta: oculta la nuestra
		{"198.51.100.7", "198.51.100.7", "Transparent"}, // nuestra IP: transparente
		{"IP: 198.51.100.7", "198.51.100.7", "Transparent"},
		{"", "198.51.100.7", ""},                          // sin cuerpo: no se mide
		{"203.0.113.9", "", ""},                           // sin IP real: no se mide
		{"<!doctype html><html>ok</html>", "1.2.3.4", ""}, // cuerpo que no es una IP
	}
	for _, c := range casos {
		if got := clasificaAnon(c.body, c.real); got != c.want {
			t.Fatalf("clasificaAnon(%q, %q) = %q, esperaba %q", c.body, c.real, got, c.want)
		}
	}
}

func TestAnonEnLaFicha(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "socks5", Host: "10.0.0.1", Port: 1, Alive: true, Checked: true, Anon: "Elite"},
		{Scheme: "http", Host: "10.0.0.2", Port: 2, Alive: true, Checked: true, Anon: "Transparent"},
	}
	mux := a.APIMux(8080, "127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/proxies", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out []proxyJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("/proxies: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("proxies = %d", len(out))
	}
	if out[0].Anon != "Elite" || out[1].Anon != "Transparent" {
		t.Fatalf("anon = %q / %q", out[0].Anon, out[1].Anon)
	}
}
