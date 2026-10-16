package main

// Tests de la validacion "estilo Proxy Checker by xRisky": Site + Success Key
// (contenido real, no solo linea HTTP), cascada en paralelo, contadores en
// vivo (Thread State / anonimato / IPv4-IPv6) y GeoIP offline por mmdb.
// Verificacion: go test -count=1 . y go test -race -count=1 .

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

/* ---------------- Site + Success Key ---------------- */

func TestMatchSuccessKey(t *testing.T) {
	casos := []struct {
		body, key string
		want      bool
	}{
		{"<html><title>Google</title></html>", "title>Google", true},
		{"<html><TITLE>GOOGLE</TITLE></html>", "title>google", true}, // sin distinguir mayusculas
		{"<html><title>Google</title></html>", "  title>Google  ", true},
		{"pagina de error 502", "title>Google", false},
		{"cualquier cosa", "", true}, // sin clave no se exige nada
		{"", "title>Google", false},
	}
	for _, c := range casos {
		if got := matchSuccessKey(c.body, c.key); got != c.want {
			t.Errorf("matchSuccessKey(%q,%q) = %v, esperaba %v", c.body, c.key, got, c.want)
		}
	}
}

// miniProxyConnect: proxy HTTP que atiende CONNECT (tunel) y reenvia a
// cualquier destino. Es lo que hace un proxy real para llegar a HTTPS.
func miniProxyConnect(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
					io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					return
				}
				for { // consume cabeceras
					h, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if h == "\r\n" || h == "\n" {
						break
					}
				}
				up, err := net.DialTimeout("tcp", fields[1], 3*time.Second)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				done := make(chan struct{}, 1)
				go func() { io.Copy(up, br); done <- struct{}{} }()
				io.Copy(c, up)
				<-done
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestHealthCheckSpecRamaRapidaSinKey(t *testing.T) {
	_, port := miniProxyHTTP(t, "<title>Google</title>")
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: port}
	// sin Success Key se mantiene la rama rapida (cualquier respuesta vale)
	ok, _, _, _ := healthCheckSpec(p, checkSpec{url: "http://juez.local/", timeout: 2 * time.Second})
	if !ok {
		t.Fatal("rama rapida: proxy bueno marcado como muerto")
	}
}

func TestHealthCheckSpecContenidoHTTP(t *testing.T) {
	_, port := miniProxyHTTP(t, "<html><head><title>Google</title></head></html>")
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: port}

	ok, ping, body, code := healthCheckSpec(p, checkSpec{
		url: "http://www.google.com/", successKey: "title>Google", timeout: 3 * time.Second,
	})
	if !ok || code != 200 || !strings.Contains(body, "title>Google") {
		t.Fatalf("contenido HTTP: ok=%v code=%d body=%q", ok, code, body)
	}
	if ping < 0 {
		t.Errorf("ping = %d", ping)
	}
	// clave ausente: el proxy no devuelve la pagina esperada -> invalido
	if ok, _, _, _ := healthCheckSpec(p, checkSpec{
		url: "http://www.google.com/", successKey: "Bing", timeout: 3 * time.Second,
	}); ok {
		t.Error("contenido HTTP: clave ausente aceptada")
	}
}

func TestHealthCheckSpecContenidoSocks5(t *testing.T) {
	site := miniJuez(t, "<html><title>Google</title></html>")
	port := miniSoloSOCKS5(t)
	p := &Proxy{Scheme: "socks5", Host: "127.0.0.1", Port: port}
	ok, _, body, code := healthCheckSpec(p, checkSpec{
		url: site.URL, successKey: "title>Google", timeout: 4 * time.Second,
	})
	if !ok || code != 200 || !strings.Contains(body, "Google") {
		t.Fatalf("contenido SOCKS5: ok=%v code=%d body=%q", ok, code, body)
	}
	if ok, _, _, _ := healthCheckSpec(p, checkSpec{
		url: site.URL, successKey: "no-esta", timeout: 4 * time.Second,
	}); ok {
		t.Error("contenido SOCKS5: clave ausente aceptada")
	}
}

func TestHealthCheckSpecContenidoHTTPS(t *testing.T) {
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><title>Google</title></html>")
	}))
	t.Cleanup(site.Close)
	port := miniProxyConnect(t)
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: port}
	// HTTPS de verdad: CONNECT + handshake TLS + GET
	ok, _, body, code := healthCheckSpec(p, checkSpec{
		url: site.URL, successKey: "title>Google", timeout: 5 * time.Second,
	})
	if !ok || code != 200 || !strings.Contains(body, "title>Google") {
		t.Fatalf("contenido HTTPS por CONNECT: ok=%v code=%d body=%q", ok, code, body)
	}
}

/* ---------------- Site + Success Key de punta a punta ---------------- */

func TestMassSiteConSuccessKey(t *testing.T) {
	a := newMassApp(t)
	_, port := miniProxyHTTP(t, `<html><head><title>Google</title></head></html>`)
	judge := miniJuez(t, "REMOTE_ADDR=1.2.3.4 HTTP_HOST=azenv.net").URL
	line := fmt.Sprintf("127.0.0.1:%d", port)

	// 1) el proxy devuelve la pagina esperada -> vivo
	if _, err := a.massStart(massCfg{
		text: line, site: "http://www.google.com/", successKey: "title>Google",
		judge: judge, threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	st := waitMassDone(t, a, 20*time.Second)
	if st.Alive != 1 || st.Bad != 0 {
		t.Fatalf("con clave correcta: alive=%d bad=%d (esperaba 1/0)", st.Alive, st.Bad)
	}
	if st.Site != "http://www.google.com/" || st.SuccessKey != "title>Google" {
		t.Errorf("status sin Site/SuccessKey: %+v", st)
	}
	if st.Remaining != 0 || st.Elapsed == "" || st.ElapsedS < 0 {
		t.Errorf("reloj del job: remaining=%d elapsed=%q", st.Remaining, st.Elapsed)
	}
	if st.CPM < 0 {
		t.Errorf("CPM = %d", st.CPM)
	}

	// 2) clave que no aparece -> muerto (y no "vivo por linea HTTP")
	if _, err := a.massStart(massCfg{
		text: line, site: "http://www.google.com/", successKey: "Bing",
		judge: judge, threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart 2: %v", err)
	}
	st2 := waitMassDone(t, a, 20*time.Second)
	if st2.Alive != 0 || st2.Bad != 1 {
		t.Fatalf("con clave incorrecta: alive=%d bad=%d (esperaba 0/1)", st2.Alive, st2.Bad)
	}
}

/* ---------------- anonimato Elite / High / Transparent ---------------- */

func TestMassAnonimatoNiveles(t *testing.T) {
	casos := []struct {
		nombre, cuerpo string
		want           int64 // 1 = elite, 2 = high, 3 = transparent
	}{
		{"elite", "REMOTE_ADDR=1.2.3.4 HTTP_HOST=juez HTTP_USER_AGENT=go", 1},
		{"high", "REMOTE_ADDR=1.2.3.4 HTTP_VIA=1.1 cache HTTP_HOST=juez", 2},
		{"transparent", "REMOTE_ADDR=1.2.3.4 HTTP_X_FORWARDED_FOR=9.9.9.9", 3},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			a := newMassApp(t)
			_, port := miniProxyHTTP(t, c.cuerpo)
			judge := miniJuez(t, c.cuerpo).URL
			if _, err := a.massStart(massCfg{
				text: fmt.Sprintf("127.0.0.1:%d", port), judge: judge, anon: true,
				threads: 2, timeoutMs: 1500, skipLocal: false,
			}); err != nil {
				t.Fatalf("massStart: %v", err)
			}
			st := waitMassDone(t, a, 20*time.Second)
			if st.Alive != 1 {
				t.Fatalf("alive = %d", st.Alive)
			}
			switch c.want {
			case 1:
				if st.Elite != 1 {
					t.Errorf("esperaba Elite, status: %+v", st)
				}
			case 2:
				if st.High != 1 {
					t.Errorf("esperaba High, status: %+v", st)
				}
			case 3:
				if st.Transparent != 1 {
					t.Errorf("esperaba Transparent, status: %+v", st)
				}
			}
			if hits := a.massHits("all", 10); len(hits) != 1 {
				t.Fatalf("hits = %+v", hits)
			} else if normalizeAnon(hits[0].Anon) != hitAnonEsperado(c.want) {
				t.Errorf("hit anon = %q", hits[0].Anon)
			}
		})
	}
}

func hitAnonEsperado(n int64) string {
	switch n {
	case 1:
		return "Elite"
	case 2:
		return "High"
	default:
		return "Transparent"
	}
}

/* ---------------- cascada en paralelo ---------------- */

func TestMassParaleloDetectaYContadoresVuelvenACero(t *testing.T) {
	a := newMassApp(t)
	port := miniProxyMixto(t) // habla SOCKS5 y HTTP
	judge := miniJuez(t, "OK").URL
	if _, err := a.massStart(massCfg{
		text: fmt.Sprintf("127.0.0.1:%d", port), judge: judge, parallel: true,
		threads: 3, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	st := waitMassDone(t, a, 20*time.Second)
	if st.Alive != 1 {
		t.Fatalf("paralelo: alive = %d (esperaba 1)", st.Alive)
	}
	if !st.Parallel {
		t.Error("status.Parallel = false")
	}
	if st.ActiveHTTP != 0 || st.ActiveS4 != 0 || st.ActiveS5 != 0 {
		t.Errorf("actividad residual: %d/%d/%d", st.ActiveHTTP, st.ActiveS4, st.ActiveS5)
	}
	if st.V4+st.V6 != 1 {
		t.Errorf("IPv4/IPv6 = %d/%d", st.V4, st.V6)
	}
}

func TestMassHitJSONFlags(t *testing.T) {
	h := massHit{Line: "[::1]:1080", Proto: "socks5", Ping: 12, Anon: "Elite",
		Country: "Testland", ISO: "TS", IP6: true}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"iso":"TS"`, `"ip6":true`, `"line":"[::1]:1080"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON del hit sin %s: %s", want, s)
		}
	}
	// un hit IPv4 normal no ensucia el JSON con campos vacios
	v4 := massHit{Line: "1.2.3.4:8080", Proto: "http", Ping: 20}
	b4, _ := json.Marshal(v4)
	if strings.Contains(string(b4), "ip6") || strings.Contains(string(b4), "iso") {
		t.Errorf("hit IPv4 con campos opcionales: %s", b4)
	}
}

/* ---------------- GeoIP offline (mmdb) en el checker ---------------- */

func TestMassGeoMMDBOffline(t *testing.T) {
	a := newMassApp(t)
	// base sintetica que ubica 127.0.0.1 en "Testland" (TS)
	raw := mmDBIPv4(t, "127.0.0.1", map[string]string{"en": "Testland"}, "TS")
	p := filepath.Join(t.TempDir(), "test.mmdb")
	if err := os.WriteFile(p, raw, 0644); err != nil {
		t.Fatal(err)
	}
	g, err := openGeoDB(p)
	if err != nil {
		t.Fatalf("openGeoDB: %v", err)
	}
	a.geoDB = g

	_, port := miniProxyHTTP(t, "ok")
	line := fmt.Sprintf("127.0.0.1:%d", port)

	// filtro que coincide (por nombre, sin juez de pais)
	if _, err := a.massStart(massCfg{
		text: line, geo: true, country: "Testland",
		threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart: %v", err)
	}
	st := waitMassDone(t, a, 20*time.Second)
	if st.Alive != 1 {
		t.Fatalf("pais por mmdb: alive = %d filtered = %d", st.Alive, st.Filtered)
	}
	hits := a.massHits("all", 10)
	if len(hits) != 1 || hits[0].Country != "Testland" || hits[0].ISO != "TS" {
		t.Fatalf("hits = %+v", hits)
	}

	// el filtro tambien acepta el ISO y descarta otros paises
	if _, err := a.massStart(massCfg{
		text: line, geo: true, country: "ts",
		threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart 2: %v", err)
	}
	if st2 := waitMassDone(t, a, 20*time.Second); st2.Alive != 1 {
		t.Fatalf("filtro por ISO: alive = %d", st2.Alive)
	}
	if _, err := a.massStart(massCfg{
		text: line, geo: true, country: "brasil",
		threads: 2, timeoutMs: 1500, skipLocal: false,
	}); err != nil {
		t.Fatalf("massStart 3: %v", err)
	}
	if st3 := waitMassDone(t, a, 20*time.Second); st3.Alive != 0 || st3.Filtered != 1 {
		t.Fatalf("filtro brasil: alive = %d filtered = %d", st3.Alive, st3.Filtered)
	}
}

/* ---------------- formato de tiempos ---------------- */

func TestFormatDuracion(t *testing.T) {
	casos := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{9 * time.Second, "9s"},
		{63 * time.Second, "1m03s"},
		{2*time.Hour + 3*time.Minute + 4*time.Second, "2h03m04s"},
		{-5 * time.Second, "0s"},
	}
	for _, c := range casos {
		if got := formatDuracion(c.d); got != c.want {
			t.Errorf("formatDuracion(%v) = %q, esperaba %q", c.d, got, c.want)
		}
	}
}
