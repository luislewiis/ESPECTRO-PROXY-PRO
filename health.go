package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
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
// checkConnect=true: usa CONNECT (tunel) en vez de GET para validar;
// detecta proxies que pasan GET pero devuelven 502 en CONNECT.
func healthCheckFull(p *Proxy, testURL string, timeout time.Duration, checkConnect bool) (bool, int) {
	ok, ping, _ := healthCheckBody(p, testURL, timeout, 0, checkConnect)
	return ok, ping
}

// schemeCascade devuelve el orden de protocolos a probar para un proxy:
// el declarado primero y despues los otros dos (socks5 -> socks4 -> http,
// el mismo criterio que el checker masivo). Motivo: en las listas publicas
// el puerto suele venir ROTULADO (un socks5 etiquetado como http, etc.), y
// probar la cascada completa recupera proxies que se perdian. El
// health-check usa esta cascada en los reintentos: cada reintento prueba un
// protocolo distinto.
func schemeCascade(own string) []string {
	own = strings.ToLower(strings.TrimSpace(own))
	base := []string{"socks5", "socks4", "http"}
	out := make([]string, 0, len(base))
	if own != "" {
		out = append(out, own)
	}
	for _, s := range base {
		if s == own {
			continue
		}
		out = append(out, s)
	}
	return out
}

// healthCheckBody es healthCheckFull con lectura opcional de cuerpo:
// maxBody > 0 consume headers y devuelve hasta maxBody bytes del body
// (el checker masivo los usa para extraer GeoIP/anonimato del juez).
// checkConnect=true: valida CONNECT en vez de GET (solo rama HTTP).
func healthCheckBody(p *Proxy, testURL string, timeout time.Duration, maxBody int, checkConnect bool) (bool, int, string) {
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

	if p.EffScheme() == "http" {
		c, err := dialRaw(p.Addr(), timeout)
		if err != nil {
			return false, 0, ""
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(timeout))

		if checkConnect {
			// Modo CONNECT: valida que el proxy pueda tunelizar (lo que usa OB M2).
			// Enviamos CONNECT al host:puerto del testURL y esperamos 200.
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", u.Host, u.Host)
			if p.User != "" {
				connectReq += "Proxy-Authorization: Basic " + basicToken(p.User, p.Password) + "\r\n"
			}
			connectReq += "\r\n"
			if _, err := io.WriteString(c, connectReq); err != nil {
				return false, 0, ""
			}
			br := bufio.NewReader(c)
			line, err := readCappedLine(br, 8192)
			if err != nil || !strings.HasPrefix(line, "HTTP/") {
				return false, 0, ""
			}
			f := strings.Fields(line)
			if len(f) < 2 || f[1] != "200" {
				// 407 = credenciales invalidas; otros !=200 = no tuneliza
				return false, 0, ""
			}
			// Consumir headers restantes
			for {
				h, err := readCappedLine(br, 8192)
				if err != nil || h == "\r\n" || h == "\n" {
					break
				}
			}
			return true, int(time.Since(start).Milliseconds()), ""
		}

		// Modo GET (default): compatible hacia atras, valida GET simple.
		// Se manda User-Agent de navegador: algunos sitios (y proxies)
		// responden 402/403 a las peticiones sin UA.
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n", testURL, u.Host, deepUserAgent)
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
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", path, u.Host, deepUserAgent)
	if _, err := io.WriteString(c, req); err != nil {
		return false, 0, ""
	}
	line, err := readCappedLine(br, 8192)
	if err != nil || !strings.HasPrefix(line, "HTTP/") {
		return false, 0, ""
	}
	return true, int(time.Since(start).Milliseconds()), readBodyLimited(br, maxBody)
}

// ==================== validacion de CONTENIDO (Site + Success Key) ====================
// Estilo "Proxy Checker by xRisky": no basta con que el proxy devuelva una
// linea HTTP (un portal cautivo, un 403 o una pagina de error pasan ese
// filtro y luego NO sirven para navegar). Con un Site (URL) y una Success
// Key (trozo de la respuesta esperada) se confirma que el proxy devuelve la
// pagina REAL. Es la diferencia entre "puerto abierto" y "proxy usable".

const deepBodyMax = 128 << 10 // tope de cuerpo leido en validacion de contenido

// deepUserAgent: UA neutro de navegador (muchos sitios responden 403 a UAs
// de bot y ese 403 no distingue proxy malo de proxy bueno).
const deepUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

// checkSpec agrupa los parametros de un chequeo.
//
//	successKey == "" -> rama RAPIDA (dial + linea de estado, como siempre)
//	successKey != "" -> rama CONTENIDO (peticion GET/HTTPS real por el proxy
//	                    y comprobacion del cuerpo)
type checkSpec struct {
	url        string
	timeout    time.Duration
	connect    bool   // rama rapida: valida CONNECT en vez de GET
	successKey string // substring exigido en el cuerpo ("" = sin validar contenido)
	maxBody    int    // bytes de cuerpo a devolver en la rama rapida (0 = no leer)
}

// deepCheck hace una peticion HTTP(S) REAL a traves del proxy usando los
// mismos primitivos de dial que el gateway (dialRaw/dialThrough + bufConn) y
// devuelve (no407, ping, cuerpo recortado, codigo). net/http se encarga del
// CONNECT+TLS para sitios https, del chunked y de los redirects (max 3).
// Cada intento usa su propio Transport con keep-alive OFF: en un chequeo
// masivo cada proxy se usa una vez y una cache de transports por proxy
// (a.tp) creceria sin limite.
func deepCheck(p *Proxy, sp checkSpec) (bool, int, string, int) {
	timeout := sp.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tr := &http.Transport{
		DisableKeepAlives:     true,
		DisableCompression:    true, // sin gzip: la Success Key se busca en texto plano
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     false,
		// Los proxies SSL-inspecting (y los tests con certificado propio)
		// presentan un certificado que no valida contra las CA del sistema.
		// Aqui NO se busca seguridad de transporte (la valida el navegador
		// del usuario), se busca saber si el proxy DEVUELVE la pagina real:
		// exigir una cadena valida descartaria proxies usables.
		// #nosec G402 -- a proposito: aqui no se busca seguridad de
		// transporte, sino saber si el proxy DEVUELVE la pagina real.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if p.EffScheme() == "http" {
		pu := &url.URL{Scheme: "http", Host: p.Addr()}
		if p.User != "" {
			pu.User = url.UserPassword(p.User, p.Password)
		}
		tr.Proxy = http.ProxyURL(pu)
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialRaw(addr, timeout)
		}
	} else {
		// socks: net/http cree que habla directo con el destino; el tunel lo
		// pone dialThrough. bufConn devuelve antes los bytes ya bufferizados
		// por el handshake (respuestas tempranas del destino).
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, br, err := dialThrough(p, addr, timeout)
			if err != nil {
				return nil, err
			}
			return &bufConn{Conn: c, r: br}, nil
		}
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, sp.url, nil)
	if err != nil {
		return false, 0, "", 0
	}
	req.Header.Set("User-Agent", deepUserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout, // cubre dial + handshake + headers + cuerpo
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil // sigue el redirect (http->https) pero sin bucle infinito
		},
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, "", 0
	}
	defer resp.Body.Close()
	ping := int(time.Since(start).Milliseconds())

	limit := sp.maxBody
	if limit <= 0 {
		limit = deepBodyMax
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	// 407 = el proxy pide credenciales que no tenemos: no es utilizable.
	return resp.StatusCode != http.StatusProxyAuthRequired, ping, string(body), resp.StatusCode
}

// matchSuccessKey: comparacion case-insensitive y por subcadenas (la clave
// se recorta: pegar " title>Google " no debe fallar).
func matchSuccessKey(body, key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return true
	}
	return strings.Contains(strings.ToLower(body), strings.ToLower(key))
}

// healthCheckSpec es el chequeo con Site + Success Key: la rama de contenido
// exige que el proxy devuelva la pagina esperada; sin Success Key se mantiene
// la rama rapida (compatibilidad y CPM alto).
func healthCheckSpec(p *Proxy, sp checkSpec) (bool, int, string, int) {
	if strings.TrimSpace(sp.successKey) != "" {
		ok, ping, body, code := deepCheck(p, sp)
		if !ok {
			return false, 0, "", code
		}
		if !matchSuccessKey(body, sp.successKey) {
			return false, 0, body, code
		}
		return true, ping, body, code
	}
	ok, ping, body := healthCheckBody(p, sp.url, sp.timeout, sp.maxBody, sp.connect)
	return ok, ping, body, 0
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
	ok, _ := healthCheckFull(p, testURL, 5*time.Second, false)
	return ok
}

// checkWithProtocolRotation prueba un proxy con la CASCADA de protocolos:
// el primer intento usa el esquema declarado y cada reintento prueba otro
// distinto (socks5 -> socks4 -> http). Cuando se agotan los protocolos
// distintos, el ultimo reintento repite el declarado (golpe de red / proxy
// lento, al estilo de "Proxy Checker by xRisky", que reintenta 3 veces).
// Devuelve si respondio, su ping, el esquema con el que respondio y el
// cuerpo de la respuesta (para clasificar el anonimato).
func (a *App) checkWithProtocolRotation(p *Proxy, sp checkSpec, retries int) (bool, int, string, string) {
	if retries < 0 {
		retries = 0
	}
	casc := schemeCascade(p.Scheme)
	for attempt := 0; attempt <= retries; attempt++ {
		sch := p.Scheme
		if attempt < len(casc) {
			sch = casc[attempt]
		}
		trial := *p
		trial.Scheme = sch
		trial.AltScheme = ""
		ok, ping, body, _ := healthCheckSpec(&trial, sp)
		if ok {
			return true, ping, sch, body
		}
		if attempt > 0 {
			// Reintento aplicado (el panel lo muestra como "reintentos").
			a.checkRetriesUsed.Add(1)
		}
	}
	return false, 0, p.Scheme, ""
}

// getRealIP: la IP publica de esta maquina (directo, sin proxy). Se cachea
// 10 minutos: sirve para saber si un proxy esta siendo TRANSPARENTE (si
// devuelve nuestra propia IP, nos esta delatando).
func (a *App) getRealIP() string {
	a.mu.Lock()
	ip, at := a.realIP, a.realIPAt
	a.mu.Unlock()
	if ip != "" && time.Now().Unix()-at < 600 {
		return ip
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get("https://api.ipify.org/")
	if err != nil {
		return ip
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	v := strings.TrimSpace(string(b))
	if v == "" || !strings.Contains(v, ".") {
		return ip
	}
	a.mu.Lock()
	a.realIP, a.realIPAt = v, time.Now().Unix()
	a.mu.Unlock()
	return v
}

// clasificaAnon: nivel de anonimato a partir del cuerpo que devuelve el
// proxy. Si aparece NUESTRA IP, el proxy es transparente; si devuelve otra,
// oculta nuestra IP (High). Sin juez no se puede distinguir Elite de High.
func clasificaAnon(body, realIP string) string {
	body = strings.TrimSpace(body)
	if body == "" || realIP == "" {
		return ""
	}
	if strings.Contains(body, realIP) {
		return "Transparent"
	}
	// el cuerpo deberia ser una IP (o un HTML con la IP)
	if strings.Contains(body, ".") || strings.Contains(body, ":") {
		return "High"
	}
	return ""
}

// anonFromBody: nivel de anonimato de un proxy a partir del cuerpo que
// devolvio. Si el cuerpo es un ECO de cabeceras (juez), se usa la
// clasificacion fina (Elite/High/Transparent) teniendo en cuenta nuestra IP
// real; si no, la comparacion de IPs.
func (a *App) anonFromBody(scheme, body, realIP string) string {
	if bodyLooksLikeEcho(body) {
		return anonLevelFor(scheme, body, realIP)
	}
	return clasificaAnon(body, realIP)
}

// checkThreads: comprobaciones simultaneas del health-check (el panel lo
// muestra como "hilos activos / total").
const checkThreads = 64

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
	checkConnect := a.checkConnect
	a.mu.Unlock()
	// Contadores del panel: hilos en vuelo y reintentos del ciclo.
	a.checkRetriesUsed.Store(0)
	// Para clasificar el anonimato hace falta leer el cuerpo de la respuesta
	// (y saber nuestra IP real). Solo en modo GET: con CONNECT no hay cuerpo.
	realIP := ""
	maxBody := 0
	if !checkConnect {
		maxBody = 256
		realIP = a.getRealIP()
	}

	// Log de detalle limitado: con listas grandes (24k+) el flood de
	// "muerto:"/"revivido:" congelaba la consola; se loguean las primeras
	// maxDetalle transiciones y luego solo el resumen.
	const maxDetalle = 5
	var nMuertos, nRev, nReclas atomic.Int32
	sp := checkSpec{
		url:        a.testURL,
		timeout:    timeout,
		connect:    checkConnect,
		successKey: a.checkKey,
		maxBody:    maxBody,
	}
	sem := make(chan struct{}, checkThreads)
	var wg sync.WaitGroup
	for _, p := range checkPs {
		wg.Add(1)
		go func(p *Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			a.checkActive.Add(1)
			defer a.checkActive.Add(-1)
			// Reintentos estilo xRisky con ROTACION DE PROTOCOLO: el primer
			// intento usa el esquema declarado y cada reintento prueba otro
			// protocolo distinto (socks5 -> socks4 -> http). Motivo: en las
			// listas publicas el puerto suele venir rotulado, y un proxy
			// "http" que en realidad es socks5 se pierde con un solo intento.
			// Si uno de los protocolos responde, se recuerda en AltScheme y
			// el trafico real pasa por el (EffScheme) sin tocar el .txt.
			ok, ping, usedScheme, body := a.checkWithProtocolRotation(p, sp, retries)
			now := time.Now().Unix()
			a.mu.Lock()
			p.Checked = true
			p.LastCheck = now
			p.PingMs = 0
			// "Â¿Tuneliza CONNECT?" para la ficha del proxy:
			//  - socks: el chequeo YA es un tunel real -> se sabe seguro.
			//  - http con --check-connect: el chequeo ES un CONNECT -> se sabe.
			//  - http con GET: un GET ok no demuestra que tunelice -> desconocido.
			tunelProbado := usedScheme != "http" || checkConnect
			if tunelProbado {
				p.ConnKnown = true
				p.ConnOK = ok
			} else {
				p.ConnKnown = false
				p.ConnOK = false
			}
			if ok {
				p.PingMs = ping
				// Anonimato: si el cuerpo es un ECO de las cabeceras (un
				// juez tipo httpbin/azenv) se clasifica al detalle (Elite /
				// High / Transparent). Si no, se compara la IP que devuelve
				// el proxy con la NUESTRA: si coincide, es transparente; si
				// no, oculta nuestra IP (High).
				if lvl := a.anonFromBody(usedScheme, body, realIP); lvl != "" {
					p.Anon = lvl
				}
				// Protocolo real detectado: si el proxy declaraba otro, se
				// guarda (persistido en el state) para que el relay lo use.
				if usedScheme != p.Scheme && p.AltScheme != usedScheme {
					p.AltScheme = usedScheme
					if nReclas.Add(1) <= maxDetalle {
						a.logf("reclasificado: %s responde como %s", p.Tag(), usedScheme)
					}
				}
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
	if n := nReclas.Load(); n > maxDetalle {
		a.logf("health-check: %d proxies reclasificados por protocolo (detalle omitido)", n-maxDetalle)
	}
	if n := nReclas.Load(); n > 0 {
		a.logf("health-check: %d proxies responden con otro protocolo (usando el real)", n)
	}
	// Sonda de capacidad (TLS 1.3 / HTTP2 / DNS remoto) de los vivos que
	// todavia no la tienen. Es un handshake TLS por proxy, con tope por
	// ciclo para no generar una avalancha.
	a.probeCapsPool(40)
	a.scheduleStateSave()
	alive, total := a.counts()
	a.logf("health-check: %d/%d vivos (revisados %d)", alive, total, len(checkPs))
}

func (a *App) CheckerLoop() {
	if a.checkItv <= 0 {
		a.logf("health-check desactivado (--check-interval 0)")
		return
	}
	// Dos modos (--check-mode):
	//   "alive" -> solo vivos + nunca verificados (barato, por defecto)
	//   "full"  -> chequeo COMPLETO de la lista en cada ciclo (mas caro,
	//              pero es el que "revisa el estado" de todo, estilo xRisky)
	scope := a.checkScope
	if scope == "" {
		scope = "alive"
	}
	if a.checkAll {
		scope = "all"
	}
	a.logf("health-check: modo %s (reintentos %d, %s)", scope, a.checkRetries, map[bool]string{true: "CONNECT", false: "GET"}[a.checkConnect])
	for {
		// el primer check se DIFIERE hasta el intervalo: chequear la lista
		// completa al arrancar saturaba CPU/red y ralentizaba todo el equipo
		time.Sleep(time.Duration(a.checkItv) * time.Second)
		a.runChecksScope(scope)
	}
}
