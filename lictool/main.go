// lictool: herramienta de licencias ESPECTRO PROXY PRO (uso del vendedor).
//
// La clave privada NUNCA se comparte con los clientes ni entra en el repo
// del producto: vive en licencias/priv.key (gitignored) y solo pasa por
// este binario. El programa solo embebe la clave publica.
//
//	go build -o lictool.exe ./lictool
//	lictool genkey  -out licencias\priv.key
//	lictool pubkey  -key licencias\priv.key      (pegar en licensing.go)
//	lictool machine                                (id del equipo cliente)
//	lictool issue -key licencias\priv.key -machine <GUID> \
//	              -edition pro -licensee "ACME SL" -days 365 -out espectro.lic
//	lictool verify -lic espectro.lic               (en la maquina del cliente)
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"proxygateway/internal/lic"
)

func main() {
	if len(os.Args) < 2 {
		uso()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = cmdGenkey(os.Args[2:])
	case "pubkey":
		err = cmdPubkey(os.Args[2:])
	case "machine":
		err = cmdMachine(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	default:
		uso()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func uso() {
	fmt.Fprintln(os.Stderr, `lictool - licencias ESPECTRO PROXY PRO

  genkey  -out ruta\priv.key                    generar par Ed25519
  pubkey  -key ruta\priv.key                    imprimir clave publica (Go snippet)
  machine                                        id y fingerprint de ESTA maquina
  issue   -key ruta\priv.key -machine ID -edition pro|business
          -licensee "Nombre" -dias 365 -out espectro.lic
  verify  -lic espectro.lic                     verificar en la maquina cliente`)
	os.Exit(2)
}

func cmdGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "licencias/priv.key", "archivo de la clave privada")
	fs.Parse(args)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if dir := dirDe(*out); dir != "" {
		os.MkdirAll(dir, 0o750)
	}
	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("clave privada escrita en %s (NO subirla al repo)\n", *out)
	fmt.Printf("clave publica para licensing.go:\n  licPubKey = %q\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("snippet: var licPubKey = %q\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	key := fs.String("key", "licencias/priv.key", "clave privada")
	fs.Parse(args)
	priv, err := leerPriv(*key)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("var licPubKey = %q\n", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func cmdMachine(args []string) error {
	fs := flag.NewFlagSet("machine", flag.ExitOnError)
	fs.Parse(args)
	id, err := lic.MachineID()
	if err != nil {
		return err
	}
	fmt.Printf("machine id:  %s\nfingerprint: %s\n", id, lic.Fingerprint(id))
	return nil
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	key := fs.String("key", "licencias/priv.key", "clave privada")
	machine := fs.String("machine", "", "machine id del cliente (lictool machine)")
	edicion := fs.String("edition", "pro", "pro | business")
	licensee := fs.String("licensee", "", "titular de la licencia")
	dias := fs.Int("dias", 365, "dias de vigencia (0 = perpetua)")
	out := fs.String("out", "espectro.lic", "archivo de salida")
	fs.Parse(args)
	if *machine == "" {
		return fmt.Errorf("-machine es obligatorio (el cliente manda el resultado de 'lictool machine')")
	}
	priv, err := leerPriv(*key)
	if err != nil {
		return err
	}
	p := &lic.Payload{
		Edition:  *edicion,
		Licensee: *licensee,
		Features: []string{},
	}
	if *dias > 0 {
		p.Expires = time.Now().UTC().Add(time.Duration(*dias) * 24 * time.Hour).Format(time.RFC3339)
	}
	blob, err := lic.Seal(priv, p, *machine)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, []byte(lic.EncodeFile(blob)), 0o644); err != nil {
		return err
	}
	fmt.Printf("licencia escrita en %s (edicion=%s, licenciatario=%q, dias=%d)\n",
		*out, *edicion, *licensee, *dias)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	licPath := fs.String("lic", "espectro.lic", "archivo de licencia")
	pubB64 := fs.String("pub", "", "clave publica base64 (la de licensing.go)")
	fs.Parse(args)
	raw, err := os.ReadFile(*licPath)
	if err != nil {
		return err
	}
	blob, err := lic.DecodeFile(raw)
	if err != nil {
		return err
	}
	id, err := lic.MachineID()
	if err != nil {
		return err
	}
	if *pubB64 == "" {
		return fmt.Errorf("-pub con la clave publica (ver licensing.go)")
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil {
		return err
	}
	p, err := lic.Unseal(pub, blob, id)
	if err != nil {
		return err
	}
	if err := p.Valid(time.Now()); err != nil {
		return err
	}
	j, _ := json.MarshalIndent(p, "", "  ")
	fmt.Printf("LICENCIA VALIDA en esta maquina:\n%s\n", j)
	return nil
}

func leerPriv(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(string(trimEspacios(raw)))
	if err != nil {
		return nil, fmt.Errorf("clave privada: formato base64 invalido: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("clave privada: tamaño %d, esperado %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func trimEspacios(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r' || b[j-1] == '\n') {
		j--
	}
	return b[i:j]
}

func dirDe(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return ""
}
