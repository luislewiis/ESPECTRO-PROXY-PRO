package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxHeadBytes = 64 * 1024
	bodyCap      = 20 * 1024 * 1024

	// dialUpTimeout: timeout para conectar+negociar contra un upstream.
	// Bajando de 10s a 4s: en pools de proxies publicos abundan los que
	// aceptan SYN y nunca responden (i/o timeout). Con 10s, 4 reintentos
	// podian congelar un bot de checker 40s (la corrida "se pausaba");
	// con 4s un upstream sano (handshake < 1-2s) no se ve afectado y los
	// muertos se descartan 2.5x mas rapido.
	dialUpTimeout = 4 * time.Second
)

type countingWriter struct {
	w  io.Writer
	up bool
	st *Stats
	// mov: opcional. Cuenta los bytes transferidos para el watchdog de
	// "tunel vivo" (si en X segundos no se movio un byte en ningun
	// sentido, el proxy esta zombi y se corta).
	mov *atomic.Int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		if c.up {
			c.st.BytesUp.Add(int64(n))
		} else {
			c.st.BytesDown.Add(int64(n))
		}
		if c.mov != nil {
			c.mov.Add(int64(n))
		}
	}
	return n, err
}

// redactURL elimina la query antes de loguearla (SEC-03: tokens/claves
// viajan en el query string de las URLs).
func redactURL(s string) string {
	if i := strings.Index(s, "?"); i >= 0 {
		return s[:i] + "?[redact]"
	}
	return s
}

// idleConn refresca el deadline en cada Read/Write: si pasa el tiempo idle
// sin actividad, la operacion falla y el tunel se cierra (watchdog RED-01).
type idleConn struct {
	net.Conn
	d time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if c.d > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.d))
	}
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	if c.d > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.d))
	}
	return c.Conn.Write(p)
}

// CloseWrite propaga el cierre de escritura a la conexion TCP subyacente
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// idleReader aplica el mismo watchdog sobre un bufio.Reader existente
// (respeta bytes ya bufferizados tras el handshake).
type idleReader struct {
	br *bufio.Reader
	c  net.Conn
	d  time.Duration
}

func (r *idleReader) Read(p []byte) (int, error) {
	if r.d > 0 {
		r.c.SetReadDeadline(time.Now().Add(r.d))
	}
	return r.br.Read(p)
}

// bufConn entrega primero los bytes ya bufferizados por el handshake SOCKS
// (respuestas tempranas del destino) antes de leer de la conexion.
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func readHead(br *bufio.Reader) (string, string, map[string]string, error) {
	var total int
	first, err := br.ReadString('\n')
	if err != nil {
		return "", "", nil, err
	}
	total += len(first)
	// la linea de peticion tambien cuenta para el cap: un cliente que envia
	// megas sin '\n' inflaria bufio hasta el deadline de 30s (hardening)
	if total > maxHeadBytes*8 {
		return "", "", nil, fmt.Errorf("linea de peticion demasiado larga")
	}
	fields := strings.Fields(strings.TrimRight(first, "\r\n"))
	if len(fields) < 3 {
		return "", "", nil, fmt.Errorf("linea de peticion invalida")
	}
	h := make(map[string]string)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", nil, err
		}
		total += len(line)
		if total > maxHeadBytes*8 {
			return "", "", nil, fmt.Errorf("cabecera demasiado grande")
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if i := strings.IndexByte(trimmed, ':'); i > 0 {
			key := strings.ToLower(strings.TrimSpace(trimmed[:i]))
			// " ::" deja i>0 pero key vacia tras trim: field-name vacio
			// viola RFC 7230 y el upstream recibiria ": valor" (fuzz crasher).
			if key == "" {
				return "", "", nil, fmt.Errorf("cabecera invalida")
			}
			h[key] = strings.TrimSpace(trimmed[i+1:])
		}
	}
	return fields[0], fields[1], h, nil
}

// errLineTooLong marca una linea que supera el tope permitido.
var errLineTooLong = errors.New("linea demasiado larga")

// readCappedLine lee hasta '\n' con tope de longitud. Usa ReadSlice (buffer
// fijo de bufio) en lugar de ReadString, que crece sin limite si el peer
// nunca envia '\n' (DoS de memoria en la fase de cuerpo: readHead lo acota
// con byteCap, pero readBody se leia con cap desactivado).
func readCappedLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		frag, err := br.ReadSlice('\n')
		if len(frag) > 0 {
			if sb.Len()+len(frag) > max {
				return "", errLineTooLong
			}
			sb.Write(frag)
		}
		if err == nil {
			return sb.String(), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return "", err
	}
}

func readBody(br *bufio.Reader, h map[string]string) ([]byte, error) {
	if strings.EqualFold(h["transfer-encoding"], "chunked") {
		var buf bytes.Buffer
		for {
			sizeLine, err := readCappedLine(br, 4096)
			if err != nil {
				if err == errLineTooLong {
					return nil, err
				}
				return nil, fmt.Errorf("chunked truncado: %w", err)
			}
			sz := strings.TrimSpace(sizeLine)
			if i := strings.IndexByte(sz, ';'); i >= 0 {
				sz = sz[:i]
			}
			size, err := strconv.ParseInt(sz, 16, 64)
			if err != nil || size < 0 {
				return nil, fmt.Errorf("chunk invalido")
			}
			if size == 0 {
				// trailers: tope total de memoria (una sequencia infinita de
				// lineas sin fin de bloque tambien inflaria bufio)
				budget := maxHeadBytes
				for {
					ln, err := readCappedLine(br, budget)
					if err != nil {
						if err == errLineTooLong {
							return nil, err
						}
						break // EOF o error de red: fin tolerante (como antes)
					}
					budget -= len(ln)
					if ln == "\r\n" || ln == "\n" {
						break
					}
				}
				break
			}
			if size > bodyCap || int64(buf.Len()) > bodyCap-size {
				return nil, fmt.Errorf("cuerpo demasiado grande")
			}
			chunk := make([]byte, size+2)
			if _, err := io.ReadFull(br, chunk); err != nil {
				return nil, err
			}
			buf.Write(chunk[:size])
		}
		return buf.Bytes(), nil
	}
	if cl := h["content-length"]; cl != "" {
		n, err := strconv.ParseInt(cl, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("content-length invalido")
		}
		if n > bodyCap {
			return nil, fmt.Errorf("cuerpo demasiado grande")
		}
		if n > 0 {
			body := make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				return nil, err
			}
			return body, nil
		}
	}
	return nil, nil
}

var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true,
	"trailers": true, "upgrade": true, "transfer-encoding": true,
	"content-length": true, "expect": true,
}

// stripHeaders contiene cabeceras que delatan proxies a Cloudflare, Akamai,
// Datadome y otros sistemas anti-bot (P1.3 Stealth).
var stripHeaders = map[string]bool{
	"via":                true,
	"x-forwarded-for":    true,
	"x-real-ip":          true,
	"forwarded":          true,
	"x-proxy-id":         true,
	"x-forwarded-host":   true,
	"x-forwarded-proto":  true,
	"x-forwarded-server": true,
	"client-ip":          true,
	"true-client-ip":     true,
}

func isStrippedHeader(k string) bool {
	lk := strings.ToLower(k)
	if hopHeaders[lk] || stripHeaders[lk] || strings.HasPrefix(lk, "x-gateway-") {
		return true
	}
	return false
}

func (a *App) ServeGateway(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			// salir solo con el listener cerrado: un error transitorio de
			// Accept (p. ej. recursos agotados) no debe tumbar el gateway
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go a.handleConn(c)
	}
}

// byteCap limita los bytes leidos de una conexion durante la fase de
// cabecera: sin esto, una sola linea sin '\n' inflaba bufio durante los 30s
// del deadline (DoS de memoria). Se desactiva (cap=0) al terminar la cabecera
// para que el cuerpo/tunel no tengan limite.
type byteCap struct {
	net.Conn
	used int
	cap  int // 0 = sin limite
}

func (c *byteCap) Read(p []byte) (int, error) {
	if c.cap > 0 {
		if c.used >= c.cap {
			return 0, fmt.Errorf("cabecera demasiado grande")
		}
		if len(p) > c.cap-c.used {
			p = p[:c.cap-c.used]
		}
	}
	n, err := c.Conn.Read(p)
	c.used += n
	return n, err
}

func (a *App) handleConn(client net.Conn) {
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(30 * time.Second))
	bc := &byteCap{Conn: client, cap: maxHeadBytes * 8}
	br := bufio.NewReader(bc)
	method, target, h, err := readHead(br)
	if err != nil {
		return
	}
	bc.cap = 0 // cabecera completa: cuerpo y tunel sin limite
	client.SetDeadline(time.Time{})
	a.stats.Requests.Add(1)

	if method == "CONNECT" {
		a.handleConnect(client, br, target, h)
		return
	}
	a.handlePlain(client, br, method, target, h)
}

func (a *App) handleConnect(client net.Conn, clientBr *bufio.Reader, target string, h map[string]string) {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			target = u.Host
		}
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	if strings.Contains(target, "/") {
		if host := h["host"]; host != "" {
			target = host
			if !strings.Contains(target, ":") {
				target += ":443"
			}
		}
	}
	// Igual que en handlePlain: CONNECT contra el propio gateway no se
	// relaya (seria un tunel hacia uno mismo); se rechaza rapido.
	if a.esAutoSolicitud(target) {
		client.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"))
		a.logf("CONNECT al propio gateway (%s) rechazado", target)
		return
	}
	session, country, rotate := parseUserParams(SessionFromHeaders(h))
	if h["x-proxy-rotate"] == "1" || rotate {
		if session != "" {
			a.deleteSession(session)
		}
		if rotate {
			session = ""
		}
	}
	delete(h, "x-proxy-rotate")
	exclude := make(map[*Proxy]bool)
	var lastErr error
	for i := 0; i < 4; i++ {
		p := a.pickWithCountry(session, country, exclude)
		if p == nil {
			break
		}
		up, upBr, err := dialThrough(p, target, dialUpTimeout)
		if err != nil {
			lastErr = err
			exclude[p] = true
			if isUpstreamErr(err) {
				a.markFail(p)
				a.logf("falla upstream %s CONNECT %s: %v", p.Tag(), target, err)
			} else {
				a.logf("destino inaccesible via %s CONNECT %s: %v", p.Tag(), target, err)
			}
			continue
		}
		a.markOK(p)
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			up.Close()
			return
		}
		// Watchdog de "tunel vivo" (auditoria 21/10/2026): hay proxies
		// "zombi" que aceptan el CONNECT y luego no transportan. El bot (o el
		// motor uTLS) se queda colgado hasta el watchdog de inactividad
		// (600 s). Se cierran tres casos:
		//   1) no se movio NINGUN byte en 8 s  -> el proxy esta muerto.
		//   2) el cliente hablo pero el destino NO respondio en 12 s -> el
		//      tunel no transporta (el caso tipico del proxy zombi).
		// En ambos casos se corta el tunel y el proxy se marca como fallido
		// para que el siguiente CONNECT use otro.
		var subidos, bajados atomic.Int64
		finWatch := make(chan struct{})
		go func() {
			t8 := time.NewTimer(8 * time.Second)
			t12 := time.NewTimer(12 * time.Second)
			defer t8.Stop()
			defer t12.Stop()
			for {
				select {
				case <-finWatch:
					return
				case <-t8.C:
					if subidos.Load() == 0 && bajados.Load() == 0 {
						a.tunelMuerto(p, target, "no se movio ningun byte")
						client.Close()
						up.Close()
						return
					}
				case <-t12.C:
					if bajados.Load() == 0 {
						a.tunelMuerto(p, target, "el destino no respondio")
						client.Close()
						up.Close()
						return
					}
				}
			}
		}()
		// El trafico por CONNECT (https de OB/SilverBullet) es REAL: se cuenta
		// como peticion para que las metricas del panel no mientan.
		a.stats.Requests.Add(1)
		if !a.quiet {
			a.logf("CONNECT %s via %s", target, p.Tag())
		}
		a.tunnel(client, clientBr, up, upBr, &subidos, &bajados)
		close(finWatch)
		return
	}
	a.stats.Errors.Add(1)
	client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
	a.logf("502 CONNECT %s: sin proxy util (%v)", target, lastErr)
}

// esAutoSolicitud indica si el destino host:puerto es uno de los puertos
// propios del gateway en loopback (p. ej. 127.0.0.1:8082 o 127.0.0.1:823
// cuando escucha en ambos). El caso real: el proxy-check de OpenBullet
// (y SilverBullet) comprueba el proxy pidiendole a el mismo un "GET /".
func (a *App) esAutoSolicitud(hostPuerto string) bool {
	host, puerto, err := net.SplitHostPort(hostPuerto)
	if err != nil {
		return false
	}
	// cualquier puerto propio (multi-puerto) o el primario (compatibilidad)
	if !a.gwPorts[puerto] && puerto != strconv.Itoa(a.gwPort) {
		return false
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
}

// respondeAuto contesta en local a una auto-solicitud con un 200: los
// checkers de proxy (OpenBullet, SilverBullet y similares) lo interpretan
// como "proxy vivo" y dejan de marcarlo como muerto. Aprovecha para
// explicar en el cuerpo que este puerto es la entrada del proxy y donde
// esta el panel.
func (a *App) respondeAuto(client net.Conn, method string, puerto string) {
	if puerto == "" {
		puerto = strconv.Itoa(a.gwPort)
	}
	if method == "HEAD" {
		client.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"))
	} else {
		// El panel se menciona con "localhost" a proposito: con la IP
		// (127.0.0.1:8081) este cuerpo coincidia con la regex tipica de
		// scraping de proxies (IP:PUERTO) y OB M2 importaba el puerto de la
		// API como "proxy" (muerto al instante: es la API, no un proxy).
		body := fmt.Sprintf("ESPECTRO PROXY PRO: proxy activo (check OK, puerto %s)\r\n"+
			"Este puerto es la ENTRADA del proxy, no una pagina web.\r\n"+
			"Panel: http://localhost:%d/panel\r\n", puerto, a.apiPort)
		client.Write([]byte(fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body), body)))
	}
	a.logf("auto-check: respondido 200 a %s (checker de proxy en el puerto %s)", method, puerto)
}

// tunelMuerto: marca el proxy como fallido y avisa (el tunel se corta).
func (a *App) tunelMuerto(p *Proxy, target, motivo string) {
	a.markFail(p)
	a.logf("tunel roto via %s (CONNECT %s): %s", p.Tag(), target, motivo)
}

// connectFirstByte: segundos que se espera el primer byte del destino tras
// un CONNECT. Si no llega, el proxy esta muerto (acepta el CONNECT pero no
// transporta) y se cambia al siguiente en vez de dejar al bot colgado.
const connectFirstByte = 15 * time.Second

// tunnelBufPool: buffers de 64 KB para los tuneles CONNECT. io.Copy usa
// 32 KB por defecto; con 64 KB se reducen los syscalls a la mitad en
// transferencias largas (descargas por el proxy), sin mantener memoria
// residente (el buffer se devuelve al pool al terminar la copia).
var tunnelBufPool = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

func (a *App) tunnel(client net.Conn, clientBr *bufio.Reader, up net.Conn, upBr *bufio.Reader, subidos, bajados *atomic.Int64) {
	defer client.Close()
	defer up.Close()
	// watchdog de inactividad (RED-01): cierra tuneles muertos sin matar
	// flujos activos (el deadline se refresca en cada Read/Write)
	var csrc io.Reader = client
	if clientBr != nil {
		csrc = clientBr
	}
	var cdst io.Writer = client
	var upsrc io.Reader = up
	if upBr != nil {
		upsrc = upBr
	}
	var updst io.Writer = up
	if a.idle > 0 {
		if clientBr != nil {
			csrc = &idleReader{br: clientBr, c: client, d: a.idle}
		} else {
			csrc = &idleConn{Conn: client, d: a.idle}
		}
		cdst = &idleConn{Conn: client, d: a.idle}
		if upBr != nil {
			upsrc = &idleReader{br: upBr, c: up, d: a.idle}
		} else {
			upsrc = &idleConn{Conn: up, d: a.idle}
		}
		updst = &idleConn{Conn: up, d: a.idle}
	}
	done1 := make(chan error, 1)
	done2 := make(chan error, 1)
	go func() {
		bp, _ := tunnelBufPool.Get().(*[]byte)
		if bp == nil {
			done1 <- nil
			return
		}
		_, err := io.CopyBuffer(&countingWriter{w: updst, up: true, st: &a.stats, mov: subidos}, csrc, *bp)
		tunnelBufPool.Put(bp)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done1 <- err
	}()
	go func() {
		bp, _ := tunnelBufPool.Get().(*[]byte)
		if bp == nil {
			done2 <- nil
			return
		}
		_, err := io.CopyBuffer(&countingWriter{w: cdst, st: &a.stats, mov: bajados}, upsrc, *bp)
		tunnelBufPool.Put(bp)
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done2 <- err
	}()

	select {
	case <-done2:
		// El upstream terminó de enviar la respuesta (o falló): salimos y cerramos
	case err := <-done1:
		// Si el cliente tuvo error de red anormal (no EOF), cerramos de inmediato.
		// Si fue EOF limpio (half-close), dejamos que el upstream termine de responder en done2.
		if err != nil {
			return
		}
		<-done2
	}
}

func (a *App) handlePlain(client net.Conn, br *bufio.Reader, method, target string, h map[string]string) {
	var rawURL string
	if strings.Contains(target, "://") {
		rawURL = target
	} else {
		hostHdrVal := h["host"]
		if hostHdrVal == "" {
			client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
			return
		}
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		rawURL = "http://" + hostHdrVal + target
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return
	}
	// Auto-solicitud: el destino es el propio puerto del gateway. El
	// proxy-check de OpenBullet (y similares) manda "GET /" al proxy para
	// ver si responde; relayarlo hacia el exterior lo dejaria pidiendo su
	// propio localhost via proxies remotos (inalcanzable -> 502 y el
	// checker lo marcaria muerto). Se contesta 200 en local.
	if a.esAutoSolicitud(u.Host) {
		a.respondeAuto(client, method, u.Port())
		return
	}
	// cuerpo del request: deadline de inactividad para no colgarse con
	// un cliente lento/muerto (RED-01)
	if a.idle > 0 {
		client.SetReadDeadline(time.Now().Add(a.idle))
	}
	body, err := readBody(br, h)
	if err != nil {
		a.stats.Errors.Add(1)
		client.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return
	}

	session, country, rotate := parseUserParams(SessionFromHeaders(h))
	if h["x-proxy-rotate"] == "1" || rotate {
		if session != "" {
			a.deleteSession(session)
		}
		if rotate {
			session = ""
		}
	}
	delete(h, "x-proxy-rotate")
	// Modo uTLS: si hay motor TLS externo configurado, la peticion se delega
	// en el (huella TLS de navegador) y el motor sale por NUESTRO pool. Solo
	// aplica a la via HTTP en forma absoluta: el CONNECT (https) lo hace
	// el propio cliente y no se puede delegar sin terminar su TLS aqui.
	if a.tlsEngineURL != "" {
		a.tlsEngineSessions++
		if a.handleViaEngine(client, method, u, h, body, session, country, rotate) {
			return
		}
		// El motor fallo (timeout, sin pool que tunelice 443, motor parado):
		// se sigue por el relay normal para no dejar al bot sin respuesta.
		a.logf("motor uTLS no pudo servir la peticion; se reintenta por el pool")
	}
	exclude := make(map[*Proxy]bool)
	var lastErr error
	maxRetries := 4
	for i := 0; i <= maxRetries; i++ {
		p := a.pickWithCountry(session, country, exclude)
		if p == nil {
			break
		}
		resp, err := a.roundTrip(p, method, u, h, body)
		if err != nil {
			lastErr = err
			exclude[p] = true
			if isUpstreamErr(err) {
				a.markFail(p)
				a.logf("falla upstream %s %s %s: %v", p.Tag(), method, u.Host, err)
			} else {
				a.logf("destino inaccesible via %s %s %s: %v", p.Tag(), method, u.Host, err)
			}
			continue
		}
		a.markOK(p)
		if !a.quiet {
			a.logf("%s %s via %s", method, redactURL(truncate(rawURL, 90)), p.Tag())
		}
		resp.Header.Del("Proxy-Connection")
		resp.Header.Del("Connection")
		resp.Header.Del("Via")
		resp.Header.Del("X-Forwarded-For")
		resp.Header.Del("X-Real-IP")
		for k := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-gateway-") {
				resp.Header.Del(k)
			}
		}
		resp.Close = true
		if body != nil {
			a.stats.BytesUp.Add(int64(len(body)))
		}
		var wout io.Writer = client
		if a.idle > 0 {
			// escrituras con watchdog: un cliente que deja de leer no cuelga
			// el writer para siempre (RED-01)
			wout = &idleConn{Conn: client, d: a.idle}
		}
		if err := resp.Write(&countingWriter{w: wout, st: &a.stats}); err != nil {
			a.stats.Errors.Add(1)
			a.logf("relay cortado %s %s: %v", method, u.Host, err)
		}
		resp.Body.Close()
		return
	}
	a.stats.Errors.Add(1)
	client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
	a.logf("502 %s %s: sin proxy util (%v)", method, redactURL(truncate(rawURL, 90)), lastErr)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (a *App) roundTrip(p *Proxy, method string, u *url.URL, h map[string]string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	for k, v := range h {
		if isStrippedHeader(k) || strings.EqualFold(k, "host") {
			continue
		}
		req.Header.Set(k, v)
	}
	if hv := h["host"]; hv != "" {
		req.Host = hv
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}

	// Transport cacheado por proxy (transport.go): reutiliza la conexion al
	// mismo upstream; el anterior creaba uno nuevo por peticion con
	// DisableKeepAlives=true -> conexion TCP nueva en cada request.
	tr := a.transportePara(p)
	if a.upTimeout <= 0 {
		return tr.RoundTrip(req)
	}
	// Tope total (cabeceras + cuerpo): ResponseHeaderTimeout solo cubre las
	// cabeceras, asi que un upstream que responde 200 y luego gotea el cuerpo
	// retenia la conexion para siempre (auditoria 17/10/2026). El cancel va
	// atado al cuerpo (no a la vuelta de RoundTrip, que solo espera cabeceras).
	ctx, cancel := context.WithTimeout(req.Context(), a.upTimeout)
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelBody libera el contexto del tope global cuando el cuerpo se cierra
// (resp.Write y el resto de rutas siempre cierran el body).
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelBody) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// jsonOut helper
func jsonOut(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
