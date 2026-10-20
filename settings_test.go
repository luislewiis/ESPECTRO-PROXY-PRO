package main

// Tests de la pestaña "Configuracion" y de las metricas del rail.
//
//  1. /settings: GET devuelve los ajustes vigentes; POST los aplica en
//     caliente (modo del chequeo, validacion GET/CONNECT, reintentos,
//     intervalo, estrategia...) y los guarda; un valor invalido -> 400.
//  2. Los flags de la linea de comandos MANDAN sobre settings.json.
//  3. /stats expone las metricas del rail medidas sobre el pool real
//     (percentiles de latencia, reparto por protocolo, geolocalizacion top).
//  4. /proxies expone lo que necesita la ficha del proxy: protocolo real,
//     si tuneliza CONNECT, enfriamiento y credenciales.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsGetYPost(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	mux := a.APIMux(8080, "127.0.0.1")

	// GET: devuelve los ajustes vigentes.
	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /settings: HTTP %d", rec.Code)
	}
	var cur appSettings
	if err := json.Unmarshal(rec.Body.Bytes(), &cur); err != nil {
		t.Fatalf("GET /settings: json invalido: %v", err)
	}
	if cur.CheckMode != "alive" {
		t.Fatalf("check_mode por defecto = %q, esperaba alive", cur.CheckMode)
	}

	// POST sin cabecera de panel -> 403.
	body := strings.NewReader(`{"check_mode":"full","check_retries":5,"check_connect":true}`)
	req = httptest.NewRequest(http.MethodPost, "/settings", body)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /settings sin cabecera: HTTP %d, esperaba 403", rec.Code)
	}

	// POST con cabecera: aplica en caliente.
	body = strings.NewReader(`{"check_mode":"full","check_retries":5,"check_connect":true,"check_interval":30,"strategy":"fastest"}`)
	req = httptest.NewRequest(http.MethodPost, "/settings", body)
	req.Header.Set("X-GW-Panel", "1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /settings: HTTP %d (%s)", rec.Code, rec.Body.String())
	}
	if a.checkScopeName() != "full" {
		t.Fatalf("modo tras aplicar = %q, esperaba full", a.checkScopeName())
	}
	if a.checkRetries != 5 {
		t.Fatalf("reintentos tras aplicar = %d, esperaba 5", a.checkRetries)
	}
	if !a.checkConnect {
		t.Fatal("check_connect no se aplico")
	}
	if a.checkItv != 30 {
		t.Fatalf("intervalo tras aplicar = %d, esperaba 30", a.checkItv)
	}
	if a.strategy != "fastest" {
		t.Fatalf("estrategia tras aplicar = %q, esperaba fastest", a.strategy)
	}

	// Valor invalido -> 400 y NO se aplica.
	body = strings.NewReader(`{"check_mode":"inventado"}`)
	req = httptest.NewRequest(http.MethodPost, "/settings", body)
	req.Header.Set("X-GW-Panel", "1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("modo invalido: HTTP %d, esperaba 400", rec.Code)
	}
	if a.checkScopeName() != "full" {
		t.Fatalf("un valor invalido cambio el modo: %q", a.checkScopeName())
	}
}

func TestSettingsGuardaEnDisco(t *testing.T) {
	// saveSettings escribe en settings.json junto al binario (en el test, el
	// binario de pruebas esta en un temporal): no toca ningun .txt del usuario.
	a := NewApp(nil, "round-robin", true, 0, "")
	s := appSettings{CheckMode: "full", Mode: "detalle"}
	if err := a.saveSettings(s); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
	p := settingsPath()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("no se escribio %s: %v", p, err)
	}
	defer os.Remove(p)
	back, ok := a.loadSettings()
	if !ok {
		t.Fatal("loadSettings no leyó el fichero")
	}
	if back.CheckMode != "full" || back.Mode != "detalle" {
		t.Fatalf("leido = %+v", back)
	}
}

func TestFlagsMandanSobreElFichero(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	// El usuario escribio --check-mode full en la linea de comandos: el
	// settings.json NO debe pisarlo.
	a.explicitFlags = map[string]bool{"check-mode": true}
	a.checkScope = "full" // lo que puso el flag
	if err := a.applySettings(appSettings{CheckMode: "alive"}); err != nil {
		t.Fatalf("applySettings: %v", err)
	}
	if a.checkScopeName() != "full" {
		t.Fatalf("el fichero pisó un flag explicito: %q", a.checkScopeName())
	}
	// Sin flag explicito, el fichero si manda.
	a.explicitFlags = nil
	if err := a.applySettings(appSettings{CheckMode: "alive"}); err != nil {
		t.Fatalf("applySettings: %v", err)
	}
	if a.checkScopeName() != "alive" {
		t.Fatalf("el fichero no se aplico: %q", a.checkScopeName())
	}
}

func TestStatsMetricasDelRail(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "socks5", Host: "10.0.0.1", Port: 1, Alive: true, Checked: true, PingMs: 100, Country: "US"},
		{Scheme: "socks5", Host: "10.0.0.2", Port: 2, Alive: true, Checked: true, PingMs: 200, Country: "US"},
		{Scheme: "http", Host: "10.0.0.3", Port: 3, Alive: true, Checked: true, PingMs: 300, Country: "DE"},
		{Scheme: "socks4", Host: "10.0.0.4", Port: 4, Alive: true, Checked: true, PingMs: 400, Country: "DE"},
		{Scheme: "socks5", Host: "10.0.0.6", Port: 6, Alive: true, Checked: true, PingMs: 500, Country: "US"},
		{Scheme: "http", Host: "10.0.0.5", Port: 5, Alive: false, Checked: true, PingMs: 0},
	}
	mux := a.APIMux(8080, "127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var st map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st["alive_socks5"].(float64) != 3 {
		t.Fatalf("alive_socks5 = %v, esperaba 3", st["alive_socks5"])
	}
	if st["alive_http"].(float64) != 1 {
		t.Fatalf("alive_http = %v, esperaba 1", st["alive_http"])
	}
	if st["alive_socks4"].(float64) != 1 {
		t.Fatalf("alive_socks4 = %v, esperaba 1", st["alive_socks4"])
	}
	if st["lat_p50"].(float64) != 300 {
		t.Fatalf("lat_p50 = %v, esperaba 300", st["lat_p50"])
	}
	if st["lat_p90"].(float64) != 500 {
		t.Fatalf("lat_p90 = %v, esperaba 500", st["lat_p90"])
	}
	geo, _ := st["geo_top"].([]interface{})
	if len(geo) == 0 {
		t.Fatal("geo_top vacio")
	}
	first, _ := geo[0].(map[string]interface{})
	if first["country"] != "US" || first["count"].(float64) != 3 {
		t.Fatalf("geo_top[0] = %v", first)
	}
	if st["check_retries"] == nil || st["check_kind"] == nil || st["check_mode"] == nil {
		t.Fatalf("faltan campos de modo en /stats: %v", st)
	}
}

func TestProxiesFichaCampos(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "10.0.0.1", Port: 8080, Alive: true, Checked: true,
			AltScheme: "socks5", ConnOK: true, ConnKnown: true, User: "u", Password: "p"},
	}
	a.enfriar[a.proxies[0].Key()] = 9999999999
	mux := a.APIMux(8080, "127.0.0.1")
	req := httptest.NewRequest(http.MethodGet, "/proxies", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var out []proxyJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("/proxies: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("proxies = %d", len(out))
	}
	p := out[0]
	if p.Effective != "socks5" {
		t.Fatalf("effective = %q, esperaba socks5", p.Effective)
	}
	if !p.ConnKnown || !p.ConnOK {
		t.Fatalf("conn_known/conn_ok = %v/%v", p.ConnKnown, p.ConnOK)
	}
	if p.CooldownS <= 0 {
		t.Fatalf("cooldown_s = %d, esperaba > 0", p.CooldownS)
	}
	if p.User != "u" || p.Password != "p" {
		t.Fatalf("credenciales = %q/%q", p.User, p.Password)
	}
	_ = filepath.Base(settingsPath())
}
