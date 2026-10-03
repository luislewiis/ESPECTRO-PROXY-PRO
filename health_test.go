package main

// Sonda RED-02 (auditoria): un proxy HTTP que responde 407 (credenciales
// invalidas) NO debe clasificarse como vivo. Comparte ciclo con ARQ-01:
// 407 -> muerto en requests reales + vivo en health = oscilacion infinita.
// Verificacion: go test -count=1 ./...

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHealth407NotAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n")
			c.Close()
		}
	}()
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Alive: true}
	if healthCheck(p, "http://api.ipify.org/") {
		t.Errorf("RED-02: 407 clasificado como vivo")
	}
}

// TestRunChecksLimitaLogs: con N proxies que mueren, el log de detalle se
// limita a maxDetalle (5) lineas y el resto se resume (flood en consola con
// listas grandes).
func TestRunChecksLimitaLogs(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "http://api.ipify.org/")
	for i := 0; i < 10; i++ {
		a.proxies = append(a.proxies, &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: true})
	}
	a.RunChecks()

	detalle, resumen, check := 0, false, false
	for _, l := range a.logTail(500) {
		if strings.Contains(l, "muerto: http://") {
			detalle++
		}
		if strings.Contains(l, "5 proxies mas marcados muertos") {
			resumen = true
		}
		if strings.Contains(l, "health-check: 0/10 vivos") {
			check = true
		}
	}
	if detalle != 5 {
		t.Errorf("detalle de muertos = %d, esperaba 5 (maxDetalle)", detalle)
	}
	if !resumen {
		t.Errorf("falta el resumen '5 proxies mas marcados muertos'")
	}
	if !check {
		t.Errorf("falta el resumen final health-check")
	}
}

// TestRunChecksBatchRotativo: valida el batch sobre candidatos ordenados
// por LastCheck (rotacion self-service, sin indice posicional).
// checkBatch=6 sobre 10 proxies vivos-no-verificados (dial a puerto muerto
// = muere al instante): ciclo 1 chequea los 6 primeros -> 4 vivos; ciclo 2
// los pendientes (LastCheck=0) van primero -> 0 vivos. Con batch 0 o mayor
// que la lista se chequea todo de una.
func TestRunChecksBatchRotativo(t *testing.T) {
	nueve := func(n int) *App {
		a := NewApp(nil, "round-robin", true, 0, "http://127.0.0.1:1/")
		for i := 0; i < n; i++ {
			a.proxies = append(a.proxies, &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: true})
		}
		return a
	}

	a := nueve(10)
	a.checkBatch = 6

	a.RunChecks()
	if alive, _ := a.counts(); alive != 4 {
		t.Errorf("tras ciclo 1: vivos = %d, esperaba 4 (solo 6 candidatos por batch)", alive)
	}
	verificados1 := 0
	for _, p := range a.proxies {
		if p.Checked {
			verificados1++
		}
	}
	if verificados1 != 6 {
		t.Errorf("tras ciclo 1: verificados = %d, esperaba 6", verificados1)
	}

	a.RunChecks()
	if alive, _ := a.counts(); alive != 0 {
		t.Errorf("tras ciclo 2: vivos = %d, esperaba 0 (rotacion hasta el final)", alive)
	}
	for i, p := range a.proxies {
		if !p.Checked || p.LastCheck == 0 {
			t.Errorf("tras ciclo 2: proxy %d sin verificar (Checked=%v LastCheck=%d)", i, p.Checked, p.LastCheck)
		}
	}

	// batch 0 = todos de una vez
	b := nueve(10)
	b.checkBatch = 0
	b.RunChecks()
	if alive, _ := b.counts(); alive != 0 {
		t.Errorf("batch 0: vivos = %d, esperaba 0 (toda la lista)", alive)
	}

	// batch mayor que la lista: se limita a len(candidatos)
	c := nueve(10)
	c.checkBatch = 50
	c.RunChecks()
	if alive, _ := c.counts(); alive != 0 {
		t.Errorf("batch>len: vivos = %d, esperaba 0", alive)
	}
}

// TestScopeAliveExcluyeMuertosVerificados: el auto-loop (scope "alive")
// revisa vivos + sin verificar; un muerto YA verificado queda intacto
// (LastCheck no cambia) hasta un check manual (scope "all").
func TestScopeAliveExcluyeMuertosVerificados(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "http://127.0.0.1:1/")
	vivoCheckeado := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: true, Checked: true, LastCheck: 1000}
	muertoCheckeado := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: false, Checked: true, LastCheck: 1000}
	sinVerificar := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: 1, Alive: true, Checked: false}
	a.proxies = []*Proxy{vivoCheckeado, muertoCheckeado, sinVerificar}

	a.runChecksScope("alive")
	if muertoCheckeado.LastCheck != 1000 {
		t.Errorf("muerto verificado fue re-analizado: LastCheck = %d, esperaba 1000", muertoCheckeado.LastCheck)
	}
	if !sinVerificar.Checked || sinVerificar.LastCheck == 0 {
		t.Errorf("sin-verificar no fue analizado por el auto-scope")
	}
	if !vivoCheckeado.Checked || vivoCheckeado.LastCheck == 1000 {
		t.Errorf("vivo no fue re-analizado por el auto-scope")
	}

	// manual (all): tambien revisa los muertos verificados
	a.runChecksScope("all")
	if muertoCheckeado.LastCheck == 1000 {
		t.Errorf("scope all no re-analizo el muerto verificado")
	}
}

// TestHealthCheckReintentos: con --check-retries 1 (default), un intento
// fallido no marca muerto: se hace un segundo intento (contador de
// conexiones entrantes del listener). Tras ambos fallidos -> muerto.
func TestHealthCheckReintentos(t *testing.T) {
	var conns int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&conns, 1)
			c.Close() // acepta y corta sin datos: health-check falla
		}
	}()
	a := NewApp(nil, "round-robin", true, 0, "http://127.0.0.1:1/")
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Alive: true}
	a.proxies = []*Proxy{p}
	a.checkRetries = 1
	a.RunChecks()
	if n := atomic.LoadInt32(&conns); n != 2 {
		t.Errorf("conexiones = %d, esperaba 2 (intento + 1 reintento)", n)
	}
	if p.Alive {
		t.Errorf("tras 2 intentos fallidos el proxy sigue vivo")
	}
	if !p.Checked {
		t.Errorf("el proxy no quedo marcado como verificado")
	}
}

// TestHealthCheckMidePing: un proxy que responde 200 registra ping,
// Checked y LastCheck (columnas nuevas del panel y /proxies).
func TestHealthCheckMidePing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
				buf := make([]byte, 512)
				c.Read(buf)
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	a := NewApp(nil, "round-robin", true, 0, "http://127.0.0.1/")
	p := &Proxy{Scheme: "http", Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Alive: false}
	a.proxies = []*Proxy{p}
	a.RunChecks()
	if !p.Alive || !p.Checked || p.LastCheck == 0 {
		t.Errorf("vivo no registrado: alive=%v checked=%v last=%d", p.Alive, p.Checked, p.LastCheck)
	}
	if p.PingMs < 0 {
		t.Errorf("ping invalido: %d", p.PingMs)
	}
}

// TestLoadProxiesConservaEstadoDeAnalisis: tras un reload, Alive/Checked/
// LastCheck se preservan desde memoria (y el auto-scope sigue sabiendo que
// ya se analizaron).
func TestLoadProxiesConservaEstadoDeAnalisis(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "lista.txt")
	if err := os.WriteFile(f, []byte("127.0.0.1:1\n127.0.0.1:2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{f}, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.LoadProxies()
	a.mu.Lock()
	a.proxies[0].Alive = false
	a.proxies[0].Checked = true
	a.proxies[0].LastCheck = 1234
	a.mu.Unlock()
	a.LoadProxies()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.proxies[0].Alive || !a.proxies[0].Checked || a.proxies[0].LastCheck != 1234 {
		t.Errorf("reload perdio el estado: alive=%v checked=%v last=%d",
			a.proxies[0].Alive, a.proxies[0].Checked, a.proxies[0].LastCheck)
	}
}
