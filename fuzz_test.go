package main

// Fuzzing de las tres puertas de entrada de datos no confiables:
//   - FuzzParseProxyDef: lineas de listas/importaciones (el parser es la
//     superficie de ataque mas grande: formatos OB, URL, IPv6, credenciales).
//   - FuzzReadHead: primera linea + cabeceras del gateway (históricamente
//     con bugs de panic/DoS en esta casa).
//   - FuzzReadBody: cuerpo chunked/content-length (invariante: nunca
//     devuelve mas de bodyCap y nunca panica).
// Ejecucion: go test -fuzz=FuzzParseProxyDef -fuzztime=20s .  (cada uno)
// Los seeds f.Add corren tambien como tests normales en `go test`.

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func FuzzParseProxyDef(f *testing.F) {
	seeds := []string{
		"", "#", "1.2.3.4:80", "socks5://u:p@1.2.3.4:1080", "[::1]:8080",
		"0:1.2.3.4:8080::", "2:1.2.3.4:1080:u:p", "1.2.3.4:8080:u",
		"1.2.3.4:8080:u:p", "\ufeff1.2.3.4:80\r\n", "http://", "://",
		"@@@@", "[]:", "1.2.3.4:99999", "socks5://[::1]", "u:p@[::1]:70000",
		"1.2.3.4:" + strings.Repeat("9", 100), strings.Repeat("a", 4096),
		"socks5://u:p@[2001:db8::1]:1080", "http://user:pa%00ss@1.2.3.4:80",
		"1.2.3.4:80:", ":", "::", "[::1]", "host:65535", "host:1",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		for _, def := range []string{"", "http", "socks5"} {
			p := ParseProxyDef(line, def)
			if p == nil {
				continue
			}
			if p.Port < 1 || p.Port > 65535 {
				t.Fatalf("puerto fuera de rango para %q/%q: %+v", line, def, p)
			}
			if p.Scheme == "" {
				t.Fatalf("esquema vacio para %q/%q", line, def)
			}
			_ = p.Key()
			_ = p.Tag()
			_ = p.OB()
			_ = p.Plain()
			_ = p.Addr()
			_ = p.LineaCanon()
		}
	})
}

func FuzzReadHead(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("CONNECT host:443 HTTP/1.1\r\nHost: host:443\r\n\r\n"),
		[]byte("POST http://x/ HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"),
		[]byte("GET"),
		[]byte("\r\n"),
		[]byte("GET / HTTP/1.1\n"),
		append([]byte("GET / HTTP/1.1\r\n"), bytes.Repeat([]byte("X: y\r\n"), 5000)...),
		append([]byte("GET / HTTP/1.1\r\n"), bytes.Repeat([]byte("a"), 100000)...),
		[]byte("GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		method, target, h, err := readHead(bufio.NewReader(bytes.NewReader(b)))
		if err != nil {
			return
		}
		if method == "" || target == "" {
			t.Fatalf("cabecera aceptada con method/target vacio: %q %q", method, target)
		}
		for k, v := range h {
			if k == "" {
				t.Fatalf("header con clave vacia: %q=%q", k, v)
			}
		}
	})
}

func FuzzReadBody(f *testing.F) {
	type caso struct {
		body []byte
		te   string
		cl   string
	}
	seeds := []caso{
		{[]byte("5\r\nhello\r\n0\r\n\r\n"), "chunked", ""},
		{[]byte("0\r\n\r\n"), "chunked", ""},
		{[]byte("hello"), "", "5"},
		{[]byte(""), "", "0"},
		{[]byte("-1\r\nxx\r\n0\r\n\r\n"), "chunked", ""},
		{[]byte("7FFFFFFFFFFFFFFF\r\n"), "chunked", ""},
		{[]byte("5\r\nhello"), "chunked", ""},
		{[]byte("-5"), "", "-5"},
		{[]byte("abc"), "", "notanumber"},
		{bytes.Repeat([]byte("A"), 100000), "chunked", ""},
	}
	for i, s := range seeds {
		f.Add(s.body, s.te, s.cl, i)
	}
	f.Fuzz(func(t *testing.T, body []byte, te, cl string, _ int) {
		h := map[string]string{}
		if te != "" {
			h["transfer-encoding"] = te
		}
		if cl != "" {
			h["content-length"] = cl
		}
		got, err := readBody(bufio.NewReader(bytes.NewReader(body)), h)
		if err != nil {
			return
		}
		if len(got) > bodyCap {
			t.Fatalf("cuerpo de %d bytes supera bodyCap=%d", len(got), bodyCap)
		}
	})
}
