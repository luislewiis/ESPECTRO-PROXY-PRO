package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func basicToken(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// healthCheckFull intenta usar p contra testURL. Devuelve si el proxy
// responde (ok) y el ping en milisegundos (TTFB hasta la linea de estado,
// estilo EspectroProxy). timeout aplica a dial+lectura de cada intento.
func healthCheckFull(p *Proxy, testURL string, timeout time.Duration) (bool, int) {
	ok, ping, _ := healthCheckBody(p, testURL, timeout, 0)
	return ok, ping
}

// healthCheckBody es healthCheckFull con lectura opcional de cuerpo:
// maxBody > 0 consume headers y devuelve hasta maxBody bytes del body
// (el checker masivo los usa para extraer GeoIP/anonimato del juez).
func healthCheckBody(p *Proxy, testURL string, timeout time.Duration, maxBody int) (bool, int, string) {
	start := time.Now()
	u, err := url.Parse(testURL)
	if err != nil {
		return false, 0, ""
	}
	host := u.Hostname()
	if host == "" {
		return false, 0, ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	if p.Scheme == "http" {
		c, err := dialRaw(p.Addr(), timeout)
		if err != nil {
			return false, 0, ""
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(timeout))
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", testURL, u.Host)
		if p.User != "" {
			req += "Proxy-Authorization: Basic " + basicToken(p.User, p.Password) + "\r\n"
		}
		req += "\r\n"
		if _, err := io.WriteString(c, req); err != nil {
			return false, 0, ""
		}
		br := bufio.NewReader(c)
		line, err := readCappedLine(br, 8192)
		if err != nil || !strings.HasPrefix(line, "HTTP/") {
			return false, 0, ""
		}
		// 407 = credenciales invalidas: el proxy no es operativo y revive a
		// morir en requests reales (evita la oscilacion ARQ-01+RED-02).
		// Solo aplica a la rama http; en socks cualquier respuesta demuestra
		// que el tunel contra el proxy funciona.
		if f := strings.Fields(line); len(f) >= 2 && f[1] == "407" {
			return false, 0, ""
		}
		return true, int(time.Since(start).Milliseconds()), readBodyLimited(br, maxBody)
	}

	c, br, err := dialThrough(p, net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false, 0, ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	// Host con el puerto si la URL lo trae (u.Host): sin esto, un test-url
	// tipo http://ip:8080/ se testeaba contra el puerto 80 del Host header.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, u.Host)
	if _, err := io.WriteString(c, req); err != nil {
		return false, 0, ""
	}
	line, err := readCappedLine(br, 8192)
	if err != nil || !strings.HasPrefix(line, "HTTP/") {
		return false, 0, ""
	}
	return true, int(time.Since(start).Milliseconds()), readBodyLimited(br, maxBody)
}

// readBodyLimited consume los headers restantes (hasta la linea en blanco)
// y devuelve hasta max bytes del body ("" si max <= 0). Las lineas de
// cabecera van con tope: un proxy malicioso sin '\n' no debe inflar bufio
// (ReadString crece sin limite hasta el timeout del chequeo).
func readBodyLimited(br *bufio.Reader, max int) string {
	if max <= 0 {
		return ""
	}
	for {
		line, err := readCappedLine(br, maxHeadBytes)
		if err != nil {
			return ""
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	b, _ := io.ReadAll(io.LimitReader(br, int64(max)))
	return string(b)
}

// healthCheck: wrapper booleano (compat con tests y usos existentes).
func healthCheck(p *Proxy, testURL string) bool {
	ok, _ := healthCheckFull(p, testURL, 5*time.Second)
	return ok
}

// RunChecks = chequeo completo de TODA la lista (boton "Check ahora",
// POST /check, --check-now). Los muertos verificados se revisan aqui.
func (a *App) RunChecks() {
	a.runChecksScope("all")
}

// runChecksScope verifica un subconjunto:
//
//	scope "all"   -> todos los proxies (check manual)
//	scope "alive" -> solo vivos + nunca verificados (auto-loop): los
//	                 muertos ya verificados NO se re-analizan solos
//
// Los candidatos se ordenan por LastCheck ascendente (nunca verificados
// primero, luego los menos recientemente revisados): con estado
// persistido, un reinicio CONTINUA el escaneo donde quedo en vez de
// empezar de cero (rotacion self-service sin indice posicional).
func (a *App) runChecksScope(scope string) {
	// Snapshot bajo lock: LoadProxies sustituye a.proxies y leerlo sin mu
	// es un data race (detectado con go test -race, sonda C1).
	a.mu.Lock()
	var cand []*Proxy
	for _, p := range a.proxies {
		if scope == "all" || !p.Checked || p.Alive {
			cand = append(cand, p)
		}
	}
	sort.SliceStable(cand, func(i, j int) bool {
		return cand[i].LastCheck < cand[j].LastCheck
	})
	batch := a.checkBatch
	if batch <= 0 || batch > len(cand) {
		batch = len(cand)
	}
	checkPs := cand[:batch]
	timeout := a.checkTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	retries := a.checkRetries
	if retries < 0 {
		retries = 0
	}
	a.mu.Unlock()

	// Log de detalle limitado: con listas grandes (24k+) el flood de
	// "muerto:"/"revivido:" congelaba la consola; se loguean las primeras
	// maxDetalle transiciones y luego solo el resumen.
	const maxDetalle = 5
	var nMuertos, nRev atomic.Int32
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, p := range checkPs {
		wg.Add(1)
		go func(p *Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// Reintentos estilo Espectro: un intento extra antes de dar por
			// muerto (golpes de red no mueren proxies sanos).
			ok, ping := false, 0
			for attempt := 0; attempt <= retries; attempt++ {
				ok, ping = healthCheckFull(p, a.testURL, timeout)
				if ok {
					break
				}
			}
			now := time.Now().Unix()
			a.mu.Lock()
			p.Checked = true
			p.LastCheck = now
			p.PingMs = 0
			if ok {
				p.PingMs = ping
				switch {
				case !p.Alive:
					p.Alive = true
					p.Fails = 0
					a.aliveDirty = true
					a.mu.Unlock()
					if nRev.Add(1) <= maxDetalle {
						a.logf("revivido: %s", p.Tag())
					}
					return
				default:
					p.Fails = 0
				}
				a.mu.Unlock()
				return
			}
			if p.Alive {
				p.Alive = false
				a.aliveDirty = true
				a.mu.Unlock()
				if nMuertos.Add(1) <= maxDetalle {
					a.logf("muerto: %s", p.Tag())
				}
				return
			}
			a.mu.Unlock()
		}(p)
	}
	wg.Wait()
	if n := nMuertos.Load(); n > maxDetalle {
		a.logf("health-check: %d proxies mas marcados muertos (detalle omitido)", n-maxDetalle)
	}
	if n := nRev.Load(); n > maxDetalle {
		a.logf("health-check: %d proxies mas revividos (detalle omitido)", n-maxDetalle)
	}
	a.scheduleStateSave()
	alive, total := a.counts()
	a.logf("health-check: %d/%d vivos (revisados %d)", alive, total, len(checkPs))
}

func (a *App) CheckerLoop() {
	if a.checkItv <= 0 {
		a.logf("health-check desactivado (--check-interval 0)")
		return
	}
	scope := "alive"
	if a.checkAll {
		scope = "all"
	}
	for {
		// el primer check se DIFIERE hasta el intervalo: chequear la lista
		// completa al arrancar saturaba CPU/red y ralentizaba todo el equipo
		time.Sleep(time.Duration(a.checkItv) * time.Second)
		a.runChecksScope(scope)
	}
}
