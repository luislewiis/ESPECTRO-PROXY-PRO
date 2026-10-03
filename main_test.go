package main

import (
	"os"
	"strings"
	"testing"
)

// TestReorderArgs: los flags con valor (--check-batch, --idle-timeout, etc.)
// consumen su argumento aunque vayan detras de un archivo posicional; sin
// esto, "ProxyGateway.exe lista.txt --check-batch 1000" moria al parsear.
func TestReorderArgs(t *testing.T) {
	casos := []struct {
		nombre string
		args   []string
		want   []string // sufijo tras argv[0]
	}{
		{"flag con valor tras archivo", []string{"lista.txt", "--check-batch", "500", "--check-now"},
			[]string{"--check-batch", "500", "--check-now", "lista.txt"}},
		{"idle-timeout tras archivo", []string{"lista.txt", "--idle-timeout", "300"},
			[]string{"--idle-timeout", "300", "lista.txt"}},
		{"valor con signo igual", []string{"lista.txt", "--check-batch=500"},
			[]string{"--check-batch=500", "lista.txt"}},
		{"flag booleano no consume valor", []string{"lista.txt", "--quiet", "otra.txt"},
			[]string{"--quiet", "lista.txt", "otra.txt"}},
		{"todo delante", []string{"--check-batch", "1000", "lista.txt"},
			[]string{"--check-batch", "1000", "lista.txt"}},
		{"nuevos flags de valor tras archivo", []string{"lista.txt", "--state-file", "zz_s.json", "--check-timeout", "3000", "--check-retries", "2"},
			[]string{"--state-file", "zz_s.json", "--check-timeout", "3000", "--check-retries", "2", "lista.txt"}},
		{"flags nuevos booleanos no consumen valor", []string{"lista.txt", "--no-state", "--check-all"},
			[]string{"--no-state", "--check-all", "lista.txt"}},
	}
	// Se restaura al salir: el coordinator de `go test -fuzz` reutiliza este
	// mismo proceso tras los tests y toma os.Args[0] como binPath de los
	// workers; si queda "exe", el spawn falla con exec: "exe": not found.
	defer func(old []string) { os.Args = old }(os.Args)
	for _, c := range casos {
		os.Args = append([]string{"exe"}, c.args...)
		reorderArgs()
		got := os.Args[1:]
		if strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("%s: got %q, esperaba %q", c.nombre, got, c.want)
		}
	}
}

// TestDebeOcultarConsola: la consola se oculta solo en doble-click con panel;
// --console / --no-browser / --check-now o ausencia de consola la mantienen.
func TestDebeOcultarConsola(t *testing.T) {
	casos := []struct {
		nombre               string
		showConsole, consola bool
		noBrowser, checkNow  bool
		want                 bool
	}{
		{"doble-click con panel", false, true, false, false, true},
		{"--console", true, true, false, false, false},
		{"--no-browser", false, true, true, false, false},
		{"--check-now", false, true, false, true, false},
		{"sin consola (tests/servicios)", false, false, false, false, false},
	}
	for _, c := range casos {
		got := debeOcultarConsola(c.showConsole, c.noBrowser, c.checkNow, c.consola)
		if got != c.want {
			t.Errorf("%s: debeOcultarConsola = %v, esperaba %v", c.nombre, got, c.want)
		}
	}
}
