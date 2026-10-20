package main

// Tests de las observaciones de la auditoria 17/10/2026 que se implementaron:
//
//  1. /proxy.txt?alive=1 exige proxy VALIDADO (Alive && Checked); el modo
//     optimista historico queda como opt-in (?include_unchecked=1).
//  2. scheme=socks4 agrupa socks4a (misma semantica que el checker/OB).
//  3. saveState no retiene a.mu durante el trabajo caro (mapa + JSON).
//  4. Tope global por peticion relayada (upTimeout): un upstream que responde
//     cabeceras y luego gotea el cuerpo ya no retiene la conexion.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// proxyTxtLines pide una ruta al mux y devuelve las lineas no vacias.
func proxyTxtLines(t *testing.T, mux *http.ServeMux, target string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d (%s)", target, rec.Code, rec.Body.String())
	}
	var out []string
	for _, l := range strings.Split(rec.Body.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// TestProxyTxtAliveSoloValidados: la promesa del README ("?alive=1 jamas
// entrega un proxy sin validar") ahora la cumple el codigo, no solo el
// harvester. Antes, una lista propia recien cargada marcaba Alive=true y
// /proxy.txt?alive=1 servia TODO sin verificar (12.376 en la verificacion
// real del 17/10/2026).
func TestProxyTxtAliveSoloValidados(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.proxies = []*Proxy{
		{Scheme: "http", Host: "10.0.0.1", Port: 8080, Alive: true, Checked: true},  // validado vivo
		{Scheme: "http", Host: "10.0.0.2", Port: 8080, Alive: true, Checked: false}, // nunca verificado
		{Scheme: "http", Host: "10.0.0.3", Port: 8080, Alive: false, Checked: true}, // validado muerto
	}
	mux := a.APIMux(8080, "127.0.0.1")

	// 1) estricto: solo el validado-vivo
	got := proxyTxtLines(t, mux, "/proxy.txt?alive=1")
	if len(got) != 1 || got[0] != "10.0.0.1:8080" {
		t.Fatalf("?alive=1 = %v, esperaba solo 10.0.0.1:8080", got)
	}

	// 2) opt-in explicito: el modo optimista historico sigue disponible
	got = proxyTxtLines(t, mux, "/proxy.txt?alive=1&include_unchecked=1")
	if len(got) != 2 {
		t.Fatalf("?alive=1&include_unchecked=1 = %v, esperaba 2", got)
	}
	// nunca debe incluir el validado-muerto
	for _, l := range got {
		if l == "10.0.0.3:8080" {
			t.Fatalf("se colo un proxy muerto: %v", got)
		}
	}

	// 3) sin ?alive (descarga/lista viva): comportamiento de siempre
	if got := proxyTxtLines(t, mux, "/proxy.txt"); len(got) != 2 {
		t.Fatalf("/proxy.txt = %v, esperaba 2 (los dos vivos)", got)
	}

	// 4) pool con SOLO no verificados: el fallback "si no hay vivos sirve
	//    todos" NO debe colarse por el filtro estricto (el fallback mira
	//    aliveIdx, que no esta vacio).
	b := NewApp(nil, "round-robin", true, 0, "")
	b.proxies = []*Proxy{
		{Scheme: "http", Host: "10.9.9.9", Port: 8080, Alive: true, Checked: false},
	}
	muxB := b.APIMux(8081, "127.0.0.1")
	if got := proxyTxtLines(t, muxB, "/proxy.txt?alive=1"); len(got) != 0 {
		t.Fatalf("?alive=1 con solo no-verificados = %v, esperaba vacio", got)
	}
	// ...pero el modo optimista lo devuelve cuando se pide
	if got := proxyTxtLines(t, muxB, "/proxy.txt?alive=1&include_unchecked=1"); len(got) != 1 {
		t.Fatalf("con include_unchecked = %v, esperaba 1", got)
	}
}

// TestSaveStateNoRetieneLock: con 130k proxies, construir el mapa entero bajo
// a.mu lo retenia ~40ms cada 1,5s durante un chequeo (micro-pausa en la
// rotacion). Ahora se copia por tandas y el mapa/JSON se arma fuera del lock.
// El hook de test se llama SIEMPRE con el lock libre: si en algun momento se
// retiene, TryLock falla y el test lo detecta.
func TestSaveStateNoRetieneLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "estado.json")
	a := NewApp(nil, "round-robin", true, 0, "")
	a.stateFile = path

	n := stateSaveChunk*2 + 100 // 3 tandas: hay llamadas al hook entre medias
	for i := 0; i < n; i++ {
		a.proxies = append(a.proxies, &Proxy{
			Scheme: "http", Host: "10.0.0.1", Port: 10000 + i,
			Alive: i%2 == 0, Checked: true, PingMs: i, LastCheck: 1700000000,
			Country: "US",
		})
	}

	var libre atomic.Bool
	libre.Store(true)
	old := stateSaveHook
	stateSaveHook = func() {
		if a.mu.TryLock() {
			a.mu.Unlock()
			return
		}
		libre.Store(false) // el lock estaba tomado: trabajo caro dentro del lock
	}
	defer func() { stateSaveHook = old }()

	a.saveState()

	if !libre.Load() {
		t.Fatalf("saveState retuvo a.mu durante el trabajo caro (mapa/JSON)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no se escribio el estado: %v", err)
	}
	var m map[string]stateEntry
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("estado invalido: %v", err)
	}
	if len(m) != n {
		t.Fatalf("estado con %d entradas, esperaba %d", len(m), n)
	}
	p0 := a.proxies[0]
	if st, ok := m[p0.Key()]; !ok || !st.Alive || !st.Checked || st.PingMs != 0 {
		t.Fatalf("entrada 0 mal guardada: %+v (ok=%v)", st, ok)
	}
	p1 := a.proxies[1]
	if st := m[p1.Key()]; st.Alive || st.PingMs != 1 {
		t.Fatalf("entrada 1 mal guardada: %+v", st)
	}
}

// TestUpstreamTimeoutCortaGoteo: un proxy/upstream que manda las cabeceras y
// despues gotea el cuerpo 1 byte/50ms no puede retener la conexion para
// siempre (antes solo habia ResponseHeaderTimeout: las cabeceras llegaban a
// tiempo y el cuerpo quedaba abierto indefinidamente).
func TestUpstreamTimeoutCortaGoteo(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for { // consume la peticion hasta la linea en blanco
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")); err != nil {
					return
				}
				for i := 0; i < 1000; i++ { // goteo deliberado
					if _, err := c.Write([]byte("x")); err != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	p := &Proxy{Scheme: "http", Host: host, Port: port}

	a := NewApp(nil, "round-robin", true, 0, "")
	a.upTimeout = 300 * time.Millisecond

	u, err := url.Parse("http://destino.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := a.roundTrip(p, http.MethodGet, u, map[string]string{"host": "destino.invalid"}, nil)
	if err != nil {
		t.Fatalf("las cabeceras llegan: no deberia fallar aqui: %v", err)
	}
	defer resp.Body.Close()

	start := time.Now()
	_, err = io.ReadAll(resp.Body)
	transcurrido := time.Since(start)
	if err == nil {
		t.Fatalf("el goteo deberia cortarse por el tope global (leyo el cuerpo entero)")
	}
	if transcurrido > 3*time.Second {
		t.Fatalf("el tope tardo demasiado en cortar: %v", transcurrido)
	}
}

// TestUpstreamTimeoutCeroSinTope: --upstream-timeout 0 deja el comportamiento
// clasico (sin tope total) y no rompe peticiones normales.
func TestUpstreamTimeoutCeroSinTope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	// proxy HTTP minimo que reenvia a srv
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	pu, _ := url.Parse(proxy.URL)
	p := &Proxy{Scheme: "http", Host: pu.Hostname(), Port: mustPort(t, pu.Port())}
	a := NewApp(nil, "round-robin", true, 0, "")
	a.upTimeout = 0

	u, _ := url.Parse(srv.URL)
	resp, err := a.roundTrip(p, http.MethodGet, u, map[string]string{"host": u.Host}, nil)
	if err != nil {
		t.Fatalf("roundTrip sin tope: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Fatalf("cuerpo = %q, esperaba %q", b, "ok")
	}
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("puerto %q: %v", s, err)
	}
	return n
}
