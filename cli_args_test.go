package main

// Test del parser de la linea de comandos (auditoria 20/10/2026).
//
// El reorderArgs tenia una lista HARDCODEADA de los flags que toman valor.
// Cualquier flag nuevo que no estuviera en esa lista se comia el ARGUMENTO
// siguiente: "--anon-url http://azenv.net/" acababa con la lista de proxies
// como valor del flag, y el fichero de proxies se perdia (o se cargaba una
// URL como si fuera una lista). Ahora los flags se detectan preguntando al
// propio paquete flag.

import (
	"flag"
	"os"
	"strings"
	"testing"
)

func TestReorderArgsSeparaFlagsConValor(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("anon-url", "http://azenv.net/", "")
	fs.String("success-key", "", "")
	fs.String("http-port", "8082", "")
	fs.Bool("check-connect", false, "")
	fs.Bool("no-settings", false, "")

	antes := os.Args
	defer func() { os.Args = antes }()
	os.Args = []string{"ProxyGateway.exe", "proxies.txt",
		"--anon-url", "http://azenv.net/",
		"--success-key", "title>Google",
		"--check-connect",
		"--http-port", "8082"}

	reorderArgsWith(fs)

	// Los flags con su valor van delante; los archivos detras.
	resto := strings.Join(os.Args[1:], " ")
	if !strings.Contains(resto, "--anon-url http://azenv.net/") {
		t.Fatalf("el valor de --anon-url no se movio con el flag: %s", resto)
	}
	if !strings.Contains(resto, "--success-key title>Google") {
		t.Fatalf("el valor de --success-key no se movio con el flag: %s", resto)
	}
	if !strings.Contains(resto, "--check-connect") {
		t.Fatalf("se perdio el flag bool: %s", resto)
	}
	// "proxies.txt" debe seguir siendo un ARCHIVO, no el valor de un flag.
	idx := strings.Index(resto, "proxies.txt")
	if idx < 0 {
		t.Fatalf("se perdio el archivo de proxies: %s", resto)
	}
	// Y el valor de --anon-url no puede ser el archivo.
	if strings.Contains(resto, "--anon-url proxies.txt") {
		t.Fatalf("el flag se comio el archivo: %s", resto)
	}

	// Lo que queda tras los flags son los archivos.
	fs.Parse(os.Args[1:])
	ficheros := fs.Args()
	if len(ficheros) != 1 || ficheros[0] != "proxies.txt" {
		t.Fatalf("archivos = %v, esperaba solo proxies.txt", ficheros)
	}
	if fs.Lookup("anon-url").Value.String() != "http://azenv.net/" {
		t.Fatalf("anon-url = %q", fs.Lookup("anon-url").Value.String())
	}
	if fs.Lookup("success-key").Value.String() != "title>Google" {
		t.Fatalf("success-key = %q", fs.Lookup("success-key").Value.String())
	}
}

func TestReorderArgsConIgual(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("anon-url", "", "")

	antes := os.Args
	defer func() { os.Args = antes }()
	os.Args = []string{"ProxyGateway.exe", "lista.txt", "--anon-url=http://x/"}

	reorderArgsWith(fs)
	fs.Parse(os.Args[1:])
	if fs.Args()[0] != "lista.txt" {
		t.Fatalf("archivos = %v", fs.Args())
	}
	if fs.Lookup("anon-url").Value.String() != "http://x/" {
		t.Fatalf("anon-url = %q", fs.Lookup("anon-url").Value.String())
	}
}
