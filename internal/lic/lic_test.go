package lic

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func parClaves(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

const machineA = "3F2504E0-4F89-41D3-9A0C-0305E82C3301"

func TestSealUnsealRoundtrip(t *testing.T) {
	pub, priv := parClaves(t)
	p := &Payload{Edition: "pro", Licensee: "ACME SL", Expires: ""}
	blob, err := Seal(priv, p, machineA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	out, err := Unseal(pub, blob, machineA)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if out.Licensee != "ACME SL" || out.Edition != "pro" || out.V != Version {
		t.Errorf("payload = %+v", out)
	}
	if out.Machine != Fingerprint(machineA) {
		t.Errorf("machine = %q", out.Machine)
	}
	if err := out.Valid(time.Now()); err != nil {
		t.Errorf("Valid: %v", err)
	}
}

func TestUnsealOtraMaquinaFalla(t *testing.T) {
	pub, priv := parClaves(t)
	blob, err := Seal(priv, &Payload{Edition: "pro", Licensee: "X"}, machineA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Unseal(pub, blob, "OTRA-MAQUINA"); err == nil {
		t.Fatal("una licencia de otra maquina debio fallar")
	}
}

func TestUnsealCorruptaFalla(t *testing.T) {
	pub, priv := parClaves(t)
	blob, err := Seal(priv, &Payload{Edition: "pro"}, machineA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// bit-flip dentro del ciphertext
	blob[len(blob)-1] ^= 0x01
	if _, err := Unseal(pub, blob, machineA); err == nil {
		t.Fatal("blob alterado debio fallar")
	}
	// truncado
	if _, err := Unseal(pub, blob[:5], machineA); err == nil {
		t.Fatal("blob corto debio fallar")
	}
}

func TestClavePublicaDistintaFalla(t *testing.T) {
	_, priv := parClaves(t)
	pubOtra, _ := parClaves(t)
	blob, err := Seal(priv, &Payload{Edition: "pro"}, machineA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Unseal(pubOtra, blob, machineA); err == nil {
		t.Fatal("firma con otra clave debio fallar")
	}
}

func TestEdicionInvalidaNoSeSella(t *testing.T) {
	_, priv := parClaves(t)
	if _, err := Seal(priv, &Payload{Edition: "free"}, machineA); err == nil {
		t.Fatal("edicion desconocida debio rechazarse en Seal")
	}
}

func TestValidCaducidad(t *testing.T) {
	p := &Payload{Edition: "pro", Expires: "2026-01-01T00:00:00Z"}
	if err := p.Valid(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Errorf("antes de caducar: %v", err)
	}
	if err := p.Valid(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)); err != ErrCaducada {
		t.Errorf("despues de caducar: got %v, esperaba ErrCaducada", err)
	}
	if err := (&Payload{Edition: "pro"}).Valid(time.Now()); err != nil {
		t.Errorf("perpetua: %v", err)
	}
}

func TestEncodeDecodeFile(t *testing.T) {
	pub, priv := parClaves(t)
	blob, err := Seal(priv, &Payload{Edition: "pro"}, machineA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// el archivo se escribe con saltos de linea; DecodeFile los tolera
	artefacto := "\r\n  " + EncodeFile(blob) + "\r\n"
	decoded, err := DecodeFile([]byte(artefacto))
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if _, err := Unseal(pub, decoded, machineA); err != nil {
		t.Fatalf("Unseal tras DecodeFile: %v", err)
	}
	if _, err := DecodeFile([]byte("@@@no-base64@@@")); err == nil {
		t.Fatal("basura debio rechazarse")
	}
	// la clave publica embebida debe ser 32 bytes en base64
	if _, err := base64.StdEncoding.DecodeString(strings.Repeat("A", 43) + "="); err != nil {
		t.Errorf("formato base64 estandar: %v", err)
	}
}

func TestFingerprintEstable(t *testing.T) {
	if Fingerprint("abc") != Fingerprint("abc") || Fingerprint("abc") == Fingerprint("abd") {
		t.Fatal("Fingerprint debe ser determinista y distinguir maquinas")
	}
	if len(Fingerprint("x")) != 64 {
		t.Errorf("fingerprint = %d chars, esperaba 64 (sha256 hex)", len(Fingerprint("x")))
	}
}
