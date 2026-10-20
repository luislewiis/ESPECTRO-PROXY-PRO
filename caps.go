package main

// Sondas de CAPACIDAD del proxy: TLS 1.3, HTTP/2 y resolucion de DNS.
//
// Que el proxy "responda" no es lo mismo que "pueda con tu trafico real":
//  - TLS 1.3: algunos proxies/tuneles se quedan en TLS 1.2 y sitios WAF
//    bloquean la huella.
//  - HTTP/2 (ALPN "h2"): muchos sitios migran a h2 y con h1 van peor.
//  - DNS: si el destino se resuelve aqui, tu DNS se delata (fuera del proxy).
//
// Las sondas se hacen ATRAVES del propio proxy (CONNECT o SOCKS) con el
// mismo transporte que usa el trafico real, asi que miden exactamente lo que
// el proxy puede hacer por nosotros. El resultado se cachea (cambia muy
// poco) y se persiste con el resto del estado.

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// version negociada y el ALPN.
func probeTLS(p *Proxy, hostport string, timeout time.Duration) (tls13 bool, h2 bool, dnsRemote bool, dnsMode string, err error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return false, false, false, "", fmt.Errorf("host invalido: %s", hostport)
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return false, false, false, "", fmt.Errorf("puerto invalido: %s", hostport)
	}

	// El destino se manda como NOMBRE: el proxy lo resuelve (DNS remoto).
	// Solo si ya es una IP, el DNS no interviene (no hay nada que filtrar).
	esIP := net.ParseIP(host) != nil
	dnsRemote = !esIP
	switch p.EffScheme() {
	case "socks5":
		dnsMode = "SOCKS5 (DNS remoto)"
	case "socks4", "socks4a":
		dnsMode = "SOCKS4a (DNS remoto)"
	case "http":
		dnsMode = "CONNECT (DNS remoto)"
	default:
		dnsMode = "desconocido"
	}
	if esIP {
		dnsRemote = false
		dnsMode = "IP local (DNS local)"
	}

	c, _, err := dialThrough(p, hostport, timeout)
	if err != nil {
		return false, false, dnsRemote, dnsMode, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	// #nosec G402 -- aqui NO se valida el certificado a proposito: solo
	// queremos la VERSION de TLS y el ALPN negociados. La validez del
	// certificado la comprueba el navegador del usuario, no el proxy.
	tc := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         host,
	})
	if err := tc.Handshake(); err != nil {
		return false, false, dnsRemote, dnsMode, err
	}
	st := tc.ConnectionState()
	tls13 = st.Version == tls.VersionTLS13
	h2 = st.NegotiatedProtocol == "h2"
	return tls13, h2, dnsRemote, dnsMode, nil
}

// probeAnon: mide el anonimato de un proxy con UNA peticion GET al JUEZ
// (un "proxy judge" que devuelve las cabeceras que recibio). Con el juez,
// el cuerpo trae "HTTP_X = ..." / "REMOTE_ADDR = ..." y se puede clasificar
// al detalle (Elite / High / Transparent). Sin juez, se usa la URL de
// validacion y se compara la IP devuelta con la nuestra.
// El cuerpo se lee completo (4 KB): el eco del juez viene tras el <head> HTML.
func (a *App) probeAnon(p *Proxy) (string, error) {
	timeout := a.checkTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	u := strings.TrimSpace(a.anonURL)
	if u == "" {
		u = strings.TrimSpace(a.testURL)
	}
	if u == "" {
		return "", nil
	}
	sp := checkSpec{url: u, timeout: timeout, maxBody: 4096}
	ok, _, body, _ := healthCheckSpec(p, sp)
	if !ok {
		return "", fmt.Errorf("el proxy no respondio al juez")
	}
	real := a.getRealIP()
	lvl := a.anonFromBody(p.EffScheme(), body, real)
	if lvl == "" {
		return "", fmt.Errorf("cuerpo no recognizedo como eco (%d bytes)", len(body))
	}
	return lvl, nil
}

// invalidateCaps: marca el pool vivo como "sin medir" para que el proximo
// ciclo del health-check vuelva a medir TLS 1.3 / HTTP2 / DNS y el anonimato.
// Devuelve cuantos proxies quedan pendientes.
func (a *App) invalidateCaps() int {
	a.mu.Lock()
	n := 0
	for _, p := range a.proxies {
		if p.Alive {
			p.CapsKnown = false
			p.CapsAt = 0
			p.Anon = ""
			n++
		}
	}
	a.aliveDirty = true
	a.mu.Unlock()
	a.scheduleStateSave()
	return n
}

// capsHostFor: el host que se usa para la sonda TLS. Si el test-url es
// https se usa ese mismo host; si no, el mismo host por 443. Si el usuario
// lo fija con --caps-host, manda el suyo.
func (a *App) capsHostFor() string {
	a.mu.Lock()
	host := a.capsHost
	a.mu.Unlock()
	if host != "" {
		return host
	}
	u := strings.TrimSpace(a.testURL)
	if u == "" {
		return "api.ipify.org:443"
	}
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "api.ipify.org:443"
	}
	if !strings.Contains(rest, ":") {
		rest += ":443"
	}
	return rest
}

// probeCapsPool: mide las capacidades de los proxies VIVOS que todavia no
// las tienen (o hace mas de capsMaxAge). Limita el numero por ciclo para
// no generar una avalancha de handshakes TLS.
func (a *App) probeCapsPool(maxPerCycle int) {
	if maxPerCycle <= 0 {
		maxPerCycle = 40
	}
	hostport := a.capsHostFor()
	timeout := a.checkTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	now := time.Now().Unix()

	var targets []*Proxy
	a.mu.Lock()
	for _, p := range a.proxies {
		if !p.Alive {
			continue
		}
		if p.CapsKnown && now-p.CapsAt < capsMaxAge {
			continue
		}
		targets = append(targets, p)
		if len(targets) >= maxPerCycle*4 {
			break
		}
	}
	a.mu.Unlock()
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var nAnonErr atomic.Int64
	for _, p := range targets {
		if maxPerCycle <= 0 {
			break
		}
		maxPerCycle--
		wg.Add(1)
		go func(p *Proxy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			tls13, h2, dnsRemote, dnsMode, err := probeTLS(p, hostport, timeout)
			// El anonimato se mide aparte (una peticion GET al eco de IP):
			// asi tambien se mide en modo CONNECT, donde el health-check
			// no lee cuerpo.
			anon := ""
			var anonErr error
			a.mu.Lock()
			needAnon := p.Anon == "" || a.anonURL != ""
			a.mu.Unlock()
			if needAnon {
				anon, anonErr = a.probeAnon(p)
			}
			a.mu.Lock()
			p.CapsKnown = true
			p.CapsAt = now
			if err != nil {
				// No se ha podido medir (el proxy no llega al host): se
				// deja como "desconocido" pero se marca como medido para no
				// reintentar cada ciclo.
				p.TLS13, p.H2 = false, false
				p.DNSRemote, p.DNSMode = dnsRemote, dnsMode
			} else {
				p.TLS13, p.H2 = tls13, h2
				p.DNSRemote, p.DNSMode = dnsRemote, dnsMode
			}
			if anon != "" {
				p.Anon = anon
			}
			a.aliveDirty = true
			a.mu.Unlock()
			if anonErr != nil && nAnonErr.Add(1) <= 5 {
				a.logf("sonda de anonimato: %s (%v)", p.Tag(), anonErr)
			}
		}(p)
	}
	wg.Wait()
	a.scheduleStateSave()
}

// capsMaxAge: cada cuanto se vuelve a medir (un dia es de sobra: la
// capacidad de un proxy no cambia cada hora).
const capsMaxAge = 24 * 3600

// anonLevelFor: nivel de anonimato fino usando el cuerpo del juez Y nuestra
// IP real. Funciona con los dos formatos de juez:
//   - azenv.net (clasico): "HTTP_X_FORWARDED_FOR = 1.2.3.4"
//   - httpbingo/httpbin (JSON): {"headers":{"X-Forwarded-For":["1.2.3.4"]}}
//
// Regla:
//   - nuestra IP aparece en el cuerpo -> Transparent (nos ven),
//   - hay cadena de reenvio pero no nuestra IP -> High (el proxy se ve,
//     nuestra IP no),
//   - no hay cabeceras de proxy -> Elite.
func anonLevelFor(scheme, body, realIP string) string {
	if realIP != "" && strings.Contains(body, realIP) {
		return "Transparent"
	}
	low := strings.ToLower(body)
	tiene := func(names ...string) bool {
		for _, n := range names {
			if strings.Contains(low, n) {
				return true
			}
		}
		return false
	}
	exponeIP := tiene("x-forwarded-for", "x_forwarded_for", "x-real-ip", "x_real_ip",
		"client-ip", "client_ip", "forwarded-for", "forwarded_for")
	if exponeIP {
		return "High"
	}
	proxyVisible := tiene("\"via\"", "http_via", "proxy-connection", "proxy_connection",
		"x-proxy-id", "proxy-authorization", "\"forwarded\"")
	if proxyVisible {
		return "High"
	}
	// sin eco de juez: un SOCKS no anade cabeceras HTTP -> Elite; un HTTP
	// puede estar devolviendo una pagina cacheada/suplantada.
	if bodyLooksLikeEcho(body) {
		return "Elite"
	}
	if scheme == "http" {
		return "Unknown"
	}
	return "Elite"
}

// bodyLooksLikeEcho: el cuerpo de la respuesta parece un eco de las
// cabeceras de la peticion (juez tipo azenv.net, httpbingo.org/headers o
// httpbin.org/get). Si es asi, se puede clasificar el anonimato al detalle
// (Elite/High/Transparent) sin pedir nada mas.
func bodyLooksLikeEcho(body string) bool {
	up := strings.ToUpper(body)
	if strings.Contains(up, "REQUEST_METHOD") ||
		strings.Contains(up, "HTTP_") ||
		strings.Contains(up, "REMOTE_ADDR") {
		return true
	}
	// formato JSON: {"headers": {...}}
	low := strings.ToLower(body)
	return strings.Contains(low, "\"headers\"") && (strings.Contains(low, "\"user-agent\"") ||
		strings.Contains(low, "\"host\"") || strings.Contains(low, "\"via\""))
}
