package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// splitBenchHost convierte "http://127.0.0.1:PORT" en ("127.0.0.1", PORT).
func splitBenchHost(srvURL string) (string, int) {
	hostPort := strings.TrimPrefix(srvURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		panic(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}
	return host, port
}

func TestTransporteParaCache(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	p1 := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 8888}
	tr1 := a.transportePara(p1)
	if tr1 == nil {
		t.Fatal("transportePara devolvio nil")
	}
	if tr2 := a.transportePara(p1); tr1 != tr2 {
		t.Error("el mismo proxy debe devolver el MISMO transport (cache)")
	}
	// esquema distinto = clave distinta = transport distinto
	p2 := &Proxy{Scheme: "socks5", Host: "127.0.0.1", Port: 1080}
	if tr3 := a.transportePara(p2); tr3 == tr1 {
		t.Error("proxies distintos deben devolver transports distintos")
	}
	// usuario distinto = credenciales distintas = transport distinto
	p3 := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 8888, User: "u", Password: "p"}
	if tr4 := a.transportePara(p3); tr4 == tr1 {
		t.Error("mismo host con otro user debe devolver transport distinto")
	}
}

// El transport cacheado debe tener keep-alive ON con la config de la
// cache (la clave del fix): sin ella cada request abriria conexion nueva
// contra el proxy (ver benchmark de referencia abajo).
func TestTransporteCacheadoKeepAlive(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 8888}
	tr := a.transportePara(p)
	if tr.Proxy == nil {
		t.Fatal("el transport de un proxy http debe tener Proxy configurado")
	}
	if tr.IdleConnTimeout != transporteTTL {
		t.Errorf("IdleConnTimeout = %v, esperaba %v", tr.IdleConnTimeout, transporteTTL)
	}
	if tr.MaxIdleConns == 0 || tr.MaxIdleConnsPerHost == 0 {
		t.Error("MaxIdleConns/PerHost deben ser > 0 (pool de conexiones activo)")
	}
}

func TestSweepTransportes(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.transportePara(&Proxy{Scheme: "http", Host: "127.0.0.1", Port: 8888})
	a.transportePara(&Proxy{Scheme: "socks5", Host: "127.0.0.2", Port: 1080})

	n := 0
	a.tp.Range(func(k, v any) bool { n++; return true })
	if n != 2 {
		t.Fatalf("esperaba 2 transports en cache, hay %d", n)
	}
	// marcar uno como usado hace 10 min (fuera del TTL)
	a.tp.Range(func(k, v any) bool {
		if k.(string) == (&Proxy{Scheme: "http", Host: "127.0.0.1", Port: 8888}).Key() {
			v.(*transporteEntry).lastUsed.Store(time.Now().Add(-10 * time.Minute).UnixNano())
		}
		return true
	})
	a.sweepTransportes(time.Now())
	n = 0
	a.tp.Range(func(k, v any) bool { n++; return true })
	if n != 1 {
		t.Errorf("tras el sweep debia quedar 1 transport, quedan %d", n)
	}
	// el recien usado debe sobrevivir aun con now adelantado dentro del TTL
	a.sweepTransportes(time.Now().Add(30 * time.Second))
	n = 0
	a.tp.Range(func(k, v any) bool { n++; return true })
	if n != 1 {
		t.Errorf("transport usado hace poco no debia barrerse, quedan %d", n)
	}
}

// BenchmarkTransportCacheado: relay HTTP por el MISMO proxy con transporte
// cacheado (comportamiento actual de roundTrip).
func BenchmarkTransportCacheado(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port := splitBenchHost(srv.URL)
	a := NewApp(nil, "round-robin", true, 0, "")
	p := &Proxy{Scheme: "http", Host: host, Port: port}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := a.transportePara(p)
		req, _ := http.NewRequest("GET", "http://example.com/x", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}
}

// BenchmarkTransportNuevoPorPeticion: el comportamiento ANTERIOR (un
// Transport con DisableKeepAlives por request). Sirve de referencia para
// ver la ganancia de la cache (ns/op y conexiones nuevas).
func BenchmarkTransportNuevoPorPeticion(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host, port := splitBenchHost(srv.URL)
	pu := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port))}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := &http.Transport{
			DisableKeepAlives:     true,
			DisableCompression:    true,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     false,
			Proxy:                 http.ProxyURL(pu),
		}
		req, _ := http.NewRequest("GET", "http://example.com/x", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
		tr.CloseIdleConnections()
	}
}
