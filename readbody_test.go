package main

// Sondas de auditoría sobre readBody (gateway.go):
//   - SEC-01  : chunk con tamaño negativo -> panic (crash del proceso).
//   - SEC-01b : chunk con desbordamiento int64 -> panic en makeslice.
//   - A1      : EOF sin terminador "0" tratado como exito (body parcial).
// Los tres fallan hasta aplicar el fix en readBody (Fase 1 del plan).
// Verificación: go test -count=1 ./...   (y con -race ./...)

import (
	"bufio"
	"strings"
	"testing"
)

func readBodyChunked(raw string) (body []byte, err error, panicked interface{}) {
	defer func() { panicked = recover() }()
	h := map[string]string{"transfer-encoding": "chunked"}
	body, err = readBody(bufio.NewReader(strings.NewReader(raw)), h)
	return
}

func TestReadBodyNegativeChunkRejected(t *testing.T) {
	_, err, pan := readBodyChunked("-1\r\n" + strings.Repeat("A", 16) + "\r\n0\r\n\r\n")
	if pan != nil {
		t.Fatalf("SEC-01: panic con chunk negativo: %v", pan)
	}
	if err == nil {
		t.Fatalf("SEC-01: chunk negativo aceptado, se esperaba error")
	}
}

func TestReadBodyOverflowChunkRejected(t *testing.T) {
	_, err, pan := readBodyChunked("1\r\nA\r\n7FFFFFFFFFFFFFFF\r\nBBBBBBBB")
	if pan != nil {
		t.Fatalf("SEC-01b: panic por desbordamiento: %v", pan)
	}
	if err == nil {
		t.Fatalf("SEC-01b: chunk gigante aceptado, se esperaba error")
	}
}

func TestReadBodyTruncatedStreamRejected(t *testing.T) {
	body, err, pan := readBodyChunked("5\r\nhello\r\n")
	if pan != nil {
		t.Fatalf("panic inesperado: %v", pan)
	}
	if err == nil {
		t.Fatalf("A1: stream truncado aceptado como exito (body=%q)", body)
	}
}

func TestReadBodyValidChunkedStillWorks(t *testing.T) {
	body, err, pan := readBodyChunked("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	if pan != nil {
		t.Fatalf("panic inesperado: %v", pan)
	}
	if err != nil {
		t.Fatalf("chunked valido fallo: %v", err)
	}
	if string(body) != "hello world" {
		t.Fatalf("body = %q, se esperaba %q", body, "hello world")
	}
}
