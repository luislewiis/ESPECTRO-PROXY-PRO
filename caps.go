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

// probeAnon: mide el anonimato de un proxy con UNA peticion GET a la URL de
// validacion (que suele ser un echo de IP). Si el cuerpo trae nuestra IP, el
// proxy es transparente; si trae otra, oculta nuestra IP (High). Si el
// destino es un juez (eco de cabeceras), la clasificacion es fina
// (Elite/High/Transparent). Se hace una vez por proxy y se cachea.
func (a *App) probeAnon(p *Proxy) string {
	timeout := a.checkTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	u := strings.TrimSpace(a.testURL)
	if u == "" {
		return ""
	}
	sp := checkSpec{url: u, timeout: timeout, maxBody: 256}
	ok, _, body, _ := healthCheckSpec(p, sp)
	if !ok {
		return ""
	}
	real := a.getRealIP()
	return a.anonFromBody(p.EffScheme(), body, real)
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
			a.mu.Lock()
			needAnon := p.Anon == ""
			a.mu.Unlock()
			if needAnon {
				anon = a.probeAnon(p)
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
		}(p)
	}
	wg.Wait()
	a.scheduleStateSave()
}

// capsMaxAge: cada cuanto se vuelve a medir (un dia es de sobra: la
// capacidad de un proxy no cambia cada hora).
const capsMaxAge = 24 * 3600

// anonLevelFor: nivel de anonymity fino usando la cuerpo del juez Y nuestra
// IP real. Mejora sobre anonLevel (que es conservadora: cualquier cabecera de
// reenvio la daba por "Transparent"):
//   - si nuestra IP aparece en la cadena de reenvio -> Transparent (nos
//     ven),
//   - si hay cadena pero nuestra IP NO esta -> High (el proxy se ve, pero
//     nuestra IP no),
//   - si no hay cabeceras de proxy -> Elite.
//
// Si no hay juez (eco), el nivel Unknown en http y Elite en socks.
func anonLevelFor(scheme, body, realIP string) string {
	if realIP != "" && strings.Contains(body, realIP) {
		return "Transparent"
	}
	up := strings.ToUpper(body)
	espejo := strings.Contains(up, "REQUEST_METHOD") || strings.Contains(up, "HTTP_") ||
		strings.Contains(up, "REMOTE_ADDR")
	if espejo {
		ipExpuesta := strings.Contains(up, "HTTP_X_FORWARDED_FOR") ||
			strings.Contains(up, "HTTP_CLIENT_IP") || strings.Contains(up, "HTTP_X_REAL_IP") ||
			strings.Contains(up, "HTTP_FORWARDED_FOR") || strings.Contains(up, "HTTP_X_CLIENT_IP")
		if ipExpuesta {
			return "High"
		}
		proxyVisible := strings.Contains(up, "HTTP_VIA") || strings.Contains(up, "PROXY_CONNECTION") ||
			strings.Contains(up, "HTTP_FORWARDED") || strings.Contains(up, "HTTP_X_PROXY_ID") ||
			strings.Contains(up, "HTTP_PROXY_AUTHORIZATION") || strings.Contains(up, "HTTP_X_FORWARDED")
		if proxyVisible {
			return "High"
		}
		return "Elite"
	}
	if scheme == "http" {
		return "Unknown"
	}
	return "Elite"
}

// bodyLooksLikeEcho: el cuerpo de la respuesta parece un eco de las
// cabeceras de la peticion (lo que devuelve un juez tipo httpbin/azenv).
// Si es asi, se puede clasificar el anonimato al detalle (Elite/High/
// Transparent) sin pedir nada mas.
func bodyLooksLikeEcho(body string) bool {
	up := strings.ToUpper(body)
	return strings.Contains(up, "REQUEST_METHOD") ||
		strings.Contains(up, "HTTP_") ||
		strings.Contains(up, "REMOTE_ADDR")
}
