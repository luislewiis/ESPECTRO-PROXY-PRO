package main

import (
	"flag"
	"net"
	"os"
	"strings"
	"testing"
)

// TestReorderArgs: los flags con valor (--check-batch, --idle-timeout, etc.)
// consumen su argumento aunque vayan detras de un archivo posicional; sin
// esto, "ProxyGateway.exe lista.txt --check-batch 1000" moria al parsear.
//
// Los flags que toman valor se detectan preguntando al paquete flag, asi que
// el test usa un FlagSet propio con esos flags definidos.
func TestReorderArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("check-batch", "1000", "")
	fs.String("idle-timeout", "600", "")
	fs.String("state-file", "", "")
	fs.String("check-timeout", "5000", "")
	fs.String("check-retries", "3", "")
	fs.Bool("check-now", false, "")
	fs.Bool("quiet", false, "")
	fs.Bool("no-state", false, "")
	fs.Bool("check-all", false, "")

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
		reorderArgsWith(fs)
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

// TestBuscarPuertoLibre: con el puerto inicial ocupado y otro excluido (el
// de la API), devuelve un puerto distinto a ambos con el listener ya abierto.
func TestBuscarPuertoLibre(t *testing.T) {
	ocupado, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ocupado.Close()
	pOcupado := ocupado.Addr().(*net.TCPAddr).Port
	if pOcupado > 65400 {
		t.Skip("puerto efimero demasiado alto para el rango de busqueda")
	}

	otro, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	pExcluido := otro.Addr().(*net.TCPAddr).Port
	defer otro.Close()

	p, ln, err := buscarPuertoLibre("127.0.0.1", pOcupado, pExcluido)
	if err != nil {
		t.Fatalf("buscarPuertoLibre: %v", err)
	}
	defer ln.Close()
	if p == pOcupado || p == pExcluido {
		t.Fatalf("devolvio puerto ocupado/excluido: %d (ocupado=%d, excluido=%d)",
			p, pOcupado, pExcluido)
	}
	if ln == nil {
		t.Fatal("listener nil")
	}
	// el listener devuelto debe ser funcional en ese puerto
	if _, err := net.Dial("tcp", ln.Addr().String()); err != nil {
		t.Fatalf("dial al listener devuelto (%s): %v", ln.Addr(), err)
	}
}

// TestEsAutoSolicitud: el proxy-check de OpenBullet pide el propio puerto
// del gateway ("GET /" a 127.0.0.1:8082). Eso debe detectarse como
// auto-solicitud y responderse 200 en local; el resto se relaya con normalidad.
func TestEsAutoSolicitud(t *testing.T) {
	a := &App{gwPort: 8082}
	casos := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:8082", true},
		{"localhost:8082", true},
		{"[::1]:8082", true},
		{"127.5.5.5:8082", true},
		{"127.0.0.1:8081", false}, // el puerto de la API no es el gateway
		{"8.8.8.8:8082", false},   // destino externo en el mismo numero de puerto
		{"example.com:8082", false},
		{"127.0.0.1", false}, // sin puerto
		{"basura", false},
	}
	for _, c := range casos {
		if got := a.esAutoSolicitud(c.host); got != c.want {
			t.Errorf("esAutoSolicitud(%q) = %v, esperaba %v", c.host, got, c.want)
		}
	}
	// gwPort sin setear (0) jamas detecta auto-solicitudes
	b := &App{}
	if b.esAutoSolicitud("127.0.0.1:80") {
		t.Error("con gwPort=0 no debe detectar auto-solicitud")
	}
}

// TestEsAutoSolicitudMultiPuerto: con el gateway escuchando en varios
// puertos (estilo DataImpulse 80/8080/823), el proxy-check de CUALQUIERA de
// ellos debe detectarse como auto-solicitud y responderse 200 en local.
func TestEsAutoSolicitudMultiPuerto(t *testing.T) {
	a := &App{
		gwPort:  8082,
		gwPorts: map[string]bool{"8082": true, "823": true, "8084": true},
	}
	for _, hp := range []string{"127.0.0.1:8082", "127.0.0.1:823", "127.0.0.1:8084", "localhost:823"} {
		if !a.esAutoSolicitud(hp) {
			t.Errorf("esAutoSolicitud(%q) = false, esperaba true (puerto propio)", hp)
		}
	}
	for _, hp := range []string{"127.0.0.1:9090", "8.8.8.8:823", "example.com:823"} {
		if a.esAutoSolicitud(hp) {
			t.Errorf("esAutoSolicitud(%q) = true, esperaba false", hp)
		}
	}
}

// TestParsePuertos: --http-port acepta uno o varios separados por comas.
func TestParsePuertos(t *testing.T) {
	casos := []struct {
		in   string
		want []int
	}{
		{"8080", []int{8080}},
		{"8082,823", []int{8082, 823}},
		{" 8082 , 823 , 8084 ", []int{8082, 823, 8084}},
		{"8082,823,8082", []int{8082, 823}},        // repetido: una sola vez
		{"823,abc,8084,0,70000", []int{823, 8084}}, // invalidos: fuera
		{"", nil},
		{"   ", nil},
		{"bichos", nil},
	}
	for _, c := range casos {
		got := parsePuertos(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parsePuertos(%q) = %v, esperaba %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parsePuertos(%q) = %v, esperaba %v", c.in, got, c.want)
				break
			}
		}
	}
}
