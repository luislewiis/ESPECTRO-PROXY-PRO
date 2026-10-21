package main

// Tests del modo uTLS (motor TLS externo del TLS_v13_MASTER).
//
// El motor real es el HVN_TLS_Engine.exe (Go) que expone:
//	POST /hvn/forward  {url, method, headers, body_b64, profile, proxy, ...}
//	GET  /hvn/ping     {engine, ok, profiles:[...]}
// con la cabecera X-HVN-Key. Aqui se prueba contra un motor FALSO que
// imita ese contrato, para no depender del binario del usuario.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEngineForwardConMotorFalso(t *testing.T) {
	var recibido map[string]interface{}
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("X-HVN-Key")
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &recibido)
		if r.URL.Path != "/hvn/forward" {
			t.Errorf("ruta = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   201,
			"headers":  map[string]string{"Content-Type": "application/json", "X-Echo": "si"},
			"body_b64": base64.StdEncoding.EncodeToString([]byte(`{"ok":1}`)),
			"proto":    "HTTP/2.0", "profile": "chrome_131",
			"latency_ms": 123, "won": true,
		})
	}))
	defer srv.Close()

	a := NewApp(nil, "round-robin", true, 0, "")
	a.tlsEngineURL = srv.URL
	a.tlsEngineKey = "HVN-V1-PRUEBA"
	a.tlsEngineProfile = "firefox_120"

	rep, err := a.engineForward(tlsEngineRequest{
		URL: "https://ejemplo.test/x", Method: "POST",
		Headers: map[string]string{"Accept": "*/*"},
		BodyB64: base64.StdEncoding.EncodeToString([]byte("a=1")),
		Proxy:   "http://user:x@127.0.0.1:8082",
	})
	if err != nil {
		t.Fatalf("engineForward: %v", err)
	}
	if key != "HVN-V1-PRUEBA" {
		t.Fatalf("X-HVN-Key = %q", key)
	}
	if rep.Status != 201 || rep.Proto != "HTTP/2.0" || rep.Profile != "chrome_131" || !rep.Won {
		t.Fatalf("respuesta mal parseada: %+v", rep)
	}
	if b, _ := base64.StdEncoding.DecodeString(rep.BodyB64); string(b) != `{"ok":1}` {
		t.Fatalf("body = %q", b)
	}
	// lo que se mando al motor
	if recibido["url"] != "https://ejemplo.test/x" || recibido["method"] != "POST" {
		t.Fatalf("payload enviado = %v", recibido)
	}
	if recibido["body_b64"] != base64.StdEncoding.EncodeToString([]byte("a=1")) {
		t.Fatalf("body_b64 enviado = %v", recibido["body_b64"])
	}
	if recibido["proxy"] != "http://user:x@127.0.0.1:8082" {
		t.Fatalf("proxy enviado = %v", recibido["proxy"])
	}
}

func TestEnginePing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hvn/ping" {
			t.Errorf("ruta = %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"engine": "HVN_TLS_ENGINE_v13.0", "ok": true,
			"profiles": []string{"chrome_131", "firefox_120"},
		})
	}))
	defer srv.Close()
	a := NewApp(nil, "round-robin", true, 0, "")
	a.tlsEngineURL = srv.URL
	out, err := a.enginePing()
	if err != nil {
		t.Fatalf("enginePing: %v", err)
	}
	if out["engine"] != "HVN_TLS_ENGINE_v13.0" {
		t.Fatalf("engine = %v", out["engine"])
	}
}

func TestEngineProxyForSesion(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.gateway = "http://127.0.0.1:8082"
	casos := []struct {
		sesion, pais string
		rotate       bool
		want         string
	}{
		{"", "", false, "http://user:x@127.0.0.1:8082"},
		{"mi_bot", "", false, "http://user-session-mi_bot:x@127.0.0.1:8082"},
		{"mi_bot", "us", false, "http://user-session-mi_bot-country-US:x@127.0.0.1:8082"},
		{"", "", true, "http://user-rotate:x@127.0.0.1:8082"},
	}
	for _, c := range casos {
		got := a.engineProxyFor(c.sesion, c.pais, c.rotate)
		if got != c.want {
			t.Fatalf("engineProxyFor(%q,%q,%v) = %q, esperaba %q", c.sesion, c.pais, c.rotate, got, c.want)
		}
	}
}

func TestEngineURLUpgrade(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.tlsUpgrade = true
	u, _ := url.Parse("http://ejemplo.test/p?a=1")
	if got := a.engineURLFor(u); got != "https://ejemplo.test/p?a=1" {
		t.Fatalf("con upgrade = %q", got)
	}
	a.tlsUpgrade = false
	if got := a.engineURLFor(u); got != "http://ejemplo.test/p?a=1" {
		t.Fatalf("sin upgrade = %q", got)
	}
}

func TestEngineHeadersLimpias(t *testing.T) {
	h := map[string]string{
		"host": "x", "connection": "close", "proxy-authorization": "Basic zzz",
		"content-length": "12", "x-proxy-rotate": "1", "x-forwarded-for": "1.2.3.4",
		"accept": "*/*", "user-agent": "OB", "cookie": "a=b",
	}
	out := engineHeadersFor(h)
	for _, k := range []string{"host", "connection", "proxy-authorization", "content-length", "x-proxy-rotate", "x-forwarded-for"} {
		if _, ok := out[k]; ok {
			t.Fatalf("la cabecera %q deberia filtrarse", k)
		}
	}
	if out["accept"] != "*/*" || out["cookie"] != "a=b" {
		t.Fatalf("se perdieron cabeceras utiles: %v", out)
	}
}

// TestEngineReplyConError: si el motor devuelve error, no debe ser un 200.
func TestEngineReplyConError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "url requerida"})
	}))
	defer srv.Close()
	a := NewApp(nil, "round-robin", true, 0, "")
	a.tlsEngineURL = srv.URL
	_, err := a.engineForward(tlsEngineRequest{URL: "https://x.test/"})
	if err == nil || !strings.Contains(err.Error(), "url requerida") {
		t.Fatalf("error = %v", err)
	}
}
