package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetSessionTooLong: /get rechaza sessions >64 chars con 400 (DoS de
// memoria: el session es clave del mapa de sesiones).
func TestGetSessionTooLong(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	ts := httptest.NewServer(a.APIMux(18080, "127.0.0.1"))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/get?session=" + strings.Repeat("a", 70))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("esperaba 400, got %d", resp.StatusCode)
	}
	var m map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("respuesta no JSON: %v", err)
	}
	if m["error"] == nil {
		t.Fatalf("falta campo error: %v", m)
	}

	resp2, err := http.Get(ts.URL + "/get?session=corta1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("sesion corta debio dar 200, got %d", resp2.StatusCode)
	}
}
