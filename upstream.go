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

// upstreamError marca fallos atribuibles al PROXY (dial, protocolo, auth).
// Los errores sin envolver significan "el proxy respondio, fallo del destino"
// y NO deben contar para marcar muerto al proxy (ARQ-01): una web caida no
// apaga el pool. La autoridad de muerte sigue siendo el health-check.
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
func dialThrough(p *Proxy, target string, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	switch p.Scheme {
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
		return nil, nil, fmt.Errorf("esquema desconocido %s", p.Scheme)
	}
}

func readLineTimeout(br *bufio.Reader, limit int) (string, error) {
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		sb.WriteString(line)
		if sb.Len() > limit {
			return "", fmt.Errorf("cabecera demasiado larga")
		}
		if strings.HasSuffix(line, "\n") {
			return sb.String(), nil
		}
	}
}

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
	status, err := readLineTimeout(br, 8192)
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
		line, err := readLineTimeout(br, 65536)
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
		// 502/504/etc: el proxy esta vivo y respondio; fallo del destino
		return nil, nil, fmt.Errorf("upstream CONNECT devolvio %d", code)
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
		// el proxy respondio: el destino rechazo/no responde -> sin markFail
		return fmt.Errorf("socks5: connect fallo rep=%d", hdr[1])
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

	req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xFF)}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 0x00, 0x00, 0x00, 0x01) // socks4a
	}
	req = append(req, []byte(userid)...)
	req = append(req, 0x00)
	if net.ParseIP(host) == nil || net.ParseIP(host).To4() == nil {
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
		// el proxy respondio con rechazo -> fallo del destino, no del proxy
		return fmt.Errorf("socks4: rep=%d", resp[1])
	}
	return nil
}
