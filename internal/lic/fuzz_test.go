package lic

import (
	"crypto/ed25519"
	"testing"
)

// FuzzUnseal: la puerta de entrada de una licencia es un archivo de disco
// (posiblemente manipulado). Invariante: nunca panica, siempre devuelve
// error tipado o un payload valido.
func FuzzUnseal(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatalf("GenerateKey: %v", err)
	}
	blob, err := Seal(priv, &Payload{Edition: "pro", Licensee: "fuzz"}, machineFuzz)
	if err != nil {
		f.Fatalf("Seal: %v", err)
	}
	f.Add(blob)
	f.Add([]byte{})
	f.Add([]byte("basura"))
	f.Add(blob[:len(blob)/2])
	f.Add(append([]byte(nil), blob...))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Unseal(pub, data, machineFuzz)
		if err != nil {
			return
		}
		if p.V != Version || (p.Edition != "pro" && p.Edition != "business") {
			t.Fatalf("payload con campos invalidos: %+v", p)
		}
	})
}

const machineFuzz = "FUZZ-MACHINE-0001"
