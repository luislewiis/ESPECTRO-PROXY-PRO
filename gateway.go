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
	"time"
)

const (
	maxHeadBytes = 64 * 1024
	bodyCap      = 20 * 1024 * 1024
)

type countingWriter struct {
	w  io.Writer
	up bool
	st *Stats
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		if c.up {
			c.st.BytesUp.Add(int64(n))
		} else {
			c.st.BytesDown.Add(int64(n))
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
		a.handleConnect(client, target, h)
		return
	}
	a.handlePlain(client, br, method, target, h)
}

func (a *App) handleConnect(client net.Conn, target string, h map[string]string) {
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
	session := SessionFromHeaders(h)
	exclude := make(map[*Proxy]bool)
	var lastErr error
	for i := 0; i < 4; i++ {
		p := a.pick(session, exclude)
		if p == nil {
			break
		}
		up, upBr, err := dialThrough(p, target, 10*time.Second)
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
		if !a.quiet {
			a.logf("CONNECT %s via %s", target, p.Tag())
		}
		a.tunnel(client, up, upBr)
		return
	}
	a.stats.Errors.Add(1)
	client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
	a.logf("502 CONNECT %s: sin proxy util (%v)", target, lastErr)
}

// esAutoSolicitud indica si el destino host:puerto es el propio puerto del
// gateway en loopback (p. ej. 127.0.0.1:8082 cuando el gateway escucha en
// 8082). El caso real: el proxy-check de OpenBullet comprueba el proxy
// pidiendole a el mismo un "GET /".
func (a *App) esAutoSolicitud(hostPuerto string) bool {
	if a.gwPort <= 0 {
		return false
	}
	host, puerto, err := net.SplitHostPort(hostPuerto)
	if err != nil {
		return false
	}
	if puerto != strconv.Itoa(a.gwPort) {
		return false
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.")
}

// respondeAuto contesta en local a una auto-solicitud con un 200: los
// checkers de proxy (OpenBullet y similares) lo interpretan como "proxy
// vivo" y dejan de marcarlo como muerto. Aprovecha para explicar en el
// cuerpo que este puerto es la entrada del proxy y donde esta el panel.
func (a *App) respondeAuto(client net.Conn, method string) {
	if method == "HEAD" {
		client.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"))
	} else {
		body := fmt.Sprintf("ESPECTRO PROXY PRO: proxy activo (check OK, puerto %d)\r\n"+
			"Este puerto es la ENTRADA del proxy, no una pagina web.\r\n"+
			"Panel: http://127.0.0.1:%d/panel\r\n", a.gwPort, a.apiPort)
		client.Write([]byte(fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(body), body)))
	}
	a.logf("auto-check: respondido 200 a %s (checker de proxy en el puerto %d)", method, a.gwPort)
}

func (a *App) tunnel(client, up net.Conn, upBr *bufio.Reader) {
	defer client.Close()
	defer up.Close()
	// watchdog de inactividad (RED-01): cierra tuneles muertos sin matar
	// flujos activos (el deadline se refresca en cada Read/Write)
	var csrc io.Reader = client
	var cdst io.Writer = client
	var upsrc io.Reader = upBr
	var updst io.Writer = up
	if a.idle > 0 {
		csrc = &idleConn{Conn: client, d: a.idle}
		cdst = &idleConn{Conn: client, d: a.idle}
		upsrc = &idleReader{br: upBr, c: up, d: a.idle}
		updst = &idleConn{Conn: up, d: a.idle}
	}
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(&countingWriter{w: updst, up: true, st: &a.stats}, csrc)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(&countingWriter{w: cdst, st: &a.stats}, upsrc)
		done <- struct{}{}
	}()
	<-done
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
		a.respondeAuto(client, method)
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

	session := SessionFromHeaders(h)
	exclude := make(map[*Proxy]bool)
	var lastErr error
	for i := 0; i < 4; i++ {
		p := a.pick(session, exclude)
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
		if hopHeaders[k] || k == "host" {
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

	tr := &http.Transport{
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	if p.Scheme == "http" {
		pu := &url.URL{Scheme: "http", Host: p.Addr()}
		if p.User != "" {
			pu.User = url.UserPassword(p.User, p.Password)
		}
		tr.Proxy = http.ProxyURL(pu)
		// marcar el dial al PROXY como upstream; los errores post-CONNECT
		// (timeout del destino) quedan sin envolver -> sin markFail
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			timeout := 10 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				timeout = time.Until(dl)
			}
			c, err := dialRaw(addr, timeout)
			if err != nil {
				return nil, &upstreamError{err}
			}
			return c, nil
		}
	} else {
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			timeout := 10 * time.Second
			if dl, ok := ctx.Deadline(); ok {
				timeout = time.Until(dl)
			}
			// bufConn: entrega primero los bytes ya bufferizados por el
			// handshake (respuestas tempranas del destino), que si no se
			// descartarian junto al bufio de dialThrough.
			c, br, err := dialThrough(p, addr, timeout)
			if err != nil {
				return nil, err
			}
			return &bufConn{Conn: c, r: br}, nil
		}
	}
	defer tr.CloseIdleConnections()
	return tr.RoundTrip(req)
}

// jsonOut helper
func jsonOut(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
