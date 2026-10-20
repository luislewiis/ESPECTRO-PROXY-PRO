package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// upstreamError marca fallos atribuibles al PROXY (dial, protocolo, auth,
// y respuestas que demuestran que el proxy NO sirve trafico: CONNECT http
// con status != 200 y socks5 REP 01/02/07/08 o socks4 5C/5D). Los errores
// sin envutar significan "el proxy respondio, fallo del destino" y NO
// deben contar para marcar muerto al proxy (ARQ-01): una web caida no
// apaga el pool. Autoridades de muerte: el health-check y esta via de
// relay (ver evidencia A/B del 12/10/2026 en upstream_test.go).
type upstreamError struct{ err error }

func (e *upstreamError) Error() string { return "upstream: " + e.err.Error() }
func (e *upstreamError) Unwrap() error { return e.err }

func isUpstreamErr(err error) bool {
	var u *upstreamError
	return errors.As(err, &u)
}

func dialRaw(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}

// dialThrough conecta al target A TRAVES del upstream p.
// Devuelve la conexion y un bufio.Reader (por si el handshake HTTP dejo bytes en buffer).
// Usa el esquema EFECTIVO (EffScheme): si el health-check detecto que el puerto
// responde con otro protocolo (p.ej. socks5 rotulado como http), el trafico
// real va por el que funciona.
func dialThrough(p *Proxy, target string, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	switch p.EffScheme() {
	case "http":
		return httpConnect(p, target, timeout)
	case "socks5":
		c, err := dialRaw(p.Addr(), timeout)
		if err != nil {
			return nil, nil, &upstreamError{err}
		}
		c.SetDeadline(time.Now().Add(timeout))
		if err := socks5Connect(c, p, target); err != nil {
			c.Close()
			return nil, nil, err
		}
		c.SetDeadline(time.Time{})
		return c, bufio.NewReader(c), nil
	case "socks4", "socks4a":
		c, err := dialRaw(p.Addr(), timeout)
		if err != nil {
			return nil, nil, &upstreamError{err}
		}
		c.SetDeadline(time.Now().Add(timeout))
		if err := socks4Connect(c, p, target); err != nil {
			c.Close()
			return nil, nil, err
		}
		c.SetDeadline(time.Time{})
		return c, bufio.NewReader(c), nil
	default:
		return nil, nil, fmt.Errorf("esquema desconocido %s", p.EffScheme())
	}
}

// httpConnect negocia CONNECT contra el proxy HTTP: la respuesta se lee con
// readCappedLine (buffer fijo, tope DURANTE la lectura). Un proxy malicioso
// que enviara datos sin '\n' durante el timeout no debe inflar bufio
// (ReadString crece sin limite; era el antiguo readLineTimeout).
func httpConnect(p *Proxy, target string, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	c, err := dialRaw(p.Addr(), timeout)
	if err != nil {
		return nil, nil, &upstreamError{err}
	}
	c.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n", target, target)
	if p.User != "" {
		tok := base64.StdEncoding.EncodeToString([]byte(p.User + ":" + p.Password))
		req += "Proxy-Authorization: Basic " + tok + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		c.Close()
		return nil, nil, &upstreamError{err}
	}

	br := bufio.NewReader(c)
	status, err := readCappedLine(br, 8192)
	if err != nil {
		c.Close()
		return nil, nil, &upstreamError{err}
	}
	fields := strings.Fields(status)
	code := 0
	if len(fields) >= 2 {
		code, _ = strconv.Atoi(fields[1])
	}
	for {
		line, err := readCappedLine(br, 65536)
		if err != nil {
			c.Close()
			return nil, nil, &upstreamError{err}
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if code != 200 {
		c.Close()
		if code == 407 {
			// credenciales invalidas: problema del proxy, no del destino
			return nil, nil, &upstreamError{fmt.Errorf("upstream CONNECT devolvio 407 (credenciales)")}
		}
		if code == 0 {
			// respuesta sin codigo parseable: protocolo roto
			return nil, nil, &upstreamError{fmt.Errorf("upstream CONNECT respondio status invalido: %q", status)}
		}
		// 502/503/504...: el proxy acepto la conexion pero NO pudo tunelizar.
		// Se cuenta como fallo DEL PROXY (no del destino): en pools de
		// proxies publicos hay muchos que superan el health-check (que solo
		// exige una respuesta HTTP cualquiera) y luego no tunelizan nada; si
		// no se marcaran, la rotacion los reelegiria sin fin y cada bot
		// pagaria el timeout completo -> la corrida "se pausa".
		return nil, nil, &upstreamError{fmt.Errorf("upstream CONNECT devolvio %d", code)}
	}
	c.SetDeadline(time.Time{})
	return c, br, nil
}

func socks5Connect(c net.Conn, p *Proxy, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("target invalido: %s", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("puerto invalido: %s", portStr)
	}

	if p.User != "" {
		if _, err := c.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return &upstreamError{err}
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(c, resp); err != nil {
			return &upstreamError{err}
		}
		if resp[1] == 0xFF {
			return &upstreamError{fmt.Errorf("socks5: sin metodos aceptables")}
		}
		if resp[1] == 0x02 {
			ub := []byte(p.User)
			if len(ub) > 255 {
				ub = ub[:255]
			}
			pb := []byte(p.Password)
			if len(pb) > 255 {
				pb = pb[:255]
			}
			auth := append([]byte{0x01, byte(len(ub))}, ub...)
			auth = append(auth, byte(len(pb)))
			auth = append(auth, pb...)
			if _, err := c.Write(auth); err != nil {
				return &upstreamError{err}
			}
			if _, err := io.ReadFull(c, resp); err != nil {
				return &upstreamError{err}
			}
			if resp[1] != 0x00 {
				return &upstreamError{fmt.Errorf("socks5: autenticacion rechazada")}
			}
		} else if resp[1] != 0x00 {
			return &upstreamError{fmt.Errorf("socks5: metodo inesperado %d", resp[1])}
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return &upstreamError{err}
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(c, resp); err != nil {
			return &upstreamError{err}
		}
		if resp[1] != 0x00 {
			return &upstreamError{fmt.Errorf("socks5: servidor pidio metodo %d", resp[1])}
		}
	}

	hb := []byte(host)
	if len(hb) > 255 {
		return fmt.Errorf("host demasiado largo")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hb))}
	req = append(req, hb...)
	req = append(req, byte(port>>8), byte(port&0xFF))
	if _, err := c.Write(req); err != nil {
		return &upstreamError{err}
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return &upstreamError{err}
	}
	if hdr[1] != 0x00 {
		rep := hdr[1]
		// REP = culpa del PROXY (RFC 1928): 01 fallo general, 02 no
		// permitido por ruleset, 07 comando no soportado (junk que no
		// tuneliza), 08 tipo de direccion no soportado. Un proxy SOCKS
		// que siempre devuelve estos nunca marcaba fallo (mismo bug que
		// el 502 del CONNECT http, rama SOCKS) y la rotacion lo
		// reelegia sin fin -> la corrida "se pausa". Los REP 03-06
		// (red/destino inalcanzable, rechazado, TTL) son fallo del
		// destino y NO matan al pool (ARQ-01).
		if rep == 0x01 || rep == 0x02 || rep == 0x07 || rep == 0x08 {
			return &upstreamError{fmt.Errorf("socks5: connect rechazado por el proxy rep=%d", rep)}
		}
		return fmt.Errorf("socks5: connect fallo rep=%d", rep)
	}
	switch hdr[3] {
	case 0x01:
		if _, err := io.ReadFull(c, make([]byte, 6)); err != nil {
			return &upstreamError{err}
		}
	case 0x04:
		if _, err := io.ReadFull(c, make([]byte, 18)); err != nil {
			return &upstreamError{err}
		}
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(c, ln); err != nil {
			return &upstreamError{err}
		}
		if _, err := io.ReadFull(c, make([]byte, int(ln[0])+2)); err != nil {
			return &upstreamError{err}
		}
	default:
		return &upstreamError{fmt.Errorf("socks5: atyp raro %d", hdr[3])}
	}
	return nil
}

func socks4Connect(c net.Conn, p *Proxy, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("target invalido: %s", target)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("puerto invalido: %s", portStr)
	}

	userid := p.User
	if userid == "" {
		userid = "ob"
	}
	if len(userid) > 255 {
		userid = userid[:255]
	}

	ip := net.ParseIP(host)
	useSocks4a := ip == nil || ip.To4() == nil

	req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xFF)}
	if useSocks4a {
		req = append(req, 0x00, 0x00, 0x00, 0x01) // SOCKS4a (Zero DNS Leak: el proxy remoto resuelve el dominio)
	} else {
		req = append(req, ip.To4()...)
	}
	req = append(req, []byte(userid)...)
	req = append(req, 0x00)
	if useSocks4a {
		req = append(req, []byte(host)...)
		req = append(req, 0x00)
	}
	if _, err := c.Write(req); err != nil {
		return &upstreamError{err}
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(c, resp); err != nil {
		return &upstreamError{err}
	}
	if resp[1] != 0x5A {
		rep := resp[1]
		// 5C/5D: el PROXY no pudo verificar al cliente (identd) — es un
		// fallo operativo del proxy respecto a NUESTRO trafico, no del
		// destino: sin markFail el proxy jamas moria en la rotacion.
		// 5B ("rejected or failed" generico) queda como fallo del
		// destino (ARQ-01, conservador).
		if rep == 0x5C || rep == 0x5D {
			return &upstreamError{fmt.Errorf("socks4: rechazado por identd rep=%d", rep)}
		}
		return fmt.Errorf("socks4: rep=%d", rep)
	}
	return nil
}
