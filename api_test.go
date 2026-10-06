package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// TestProxiesPaginacionSinOverflow: ?limit=MaxInt64&offset=1 no debe romper.
// Antes offset+limit desbordaba a negativo, end quedaba < offset y
// all[offset:end] petaba con panic de slice (net/http lo recuperaba y
// devolvia 500 vacio). Cubre el fix de auditoria F1.
func TestProxiesPaginacionSinOverflow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte("1.2.3.4:8080\n5.6.7.8:8080\n9.9.9.9:3128\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{path}, "round-robin", true, 0, "")
	a.LoadProxies()
	ts := httptest.NewServer(a.APIMux(18080, "127.0.0.1"))
	defer ts.Close()

	// caso que antes petaba: limit=maxint64 + offset>0 -> offset+limit negativo
	resp, err := http.Get(ts.URL + "/proxies?limit=9223372036854775807&offset=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overflow de limit debio dar 200, got %d", resp.StatusCode)
	}
	var page struct {
		Proxies []proxyJSON `json:"proxies"`
		Total   int         `json:"total"`
		Offset  int         `json:"offset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("respuesta no JSON: %v", err)
	}
	if page.Total != 3 || page.Offset != 1 || len(page.Proxies) != 2 {
		t.Fatalf("paginacion incorrecta: total=%d offset=%d len=%d", page.Total, page.Offset, len(page.Proxies))
	}

	// offset fuera de rango: 200 con pagina vacia, sin panic
	resp2, err := http.Get(ts.URL + "/proxies?limit=10&offset=999999")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("offset fuera de rango debio dar 200, got %d", resp2.StatusCode)
	}
}
