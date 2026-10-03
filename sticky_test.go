package main

// Sonda ARQ-02 (auditoría): la sesion sticky debe sobrevivir a LoadProxies
// (/reload o el reload automatico tras /import). Falla hasta cambiar
// a.sessions a claves canonicas (Key()) en vez de punteros *Proxy.
// Verificacion: go test -count=1 ./...

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStickySurvivesReload(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(f, []byte("127.0.0.1:1\n127.0.0.1:2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{f}, "sticky", true, 0, "http://127.0.0.1:1/")
	a.LoadProxies()
	p1 := a.pick("sess1", nil)
	if p1 == nil {
		t.Fatal("pick devolvio nil")
	}
	a.LoadProxies()
	p2 := a.pick("sess1", nil)
	if p2 == nil {
		t.Fatal("pick devolvio nil tras reload")
	}
	if p1.Tag() != p2.Tag() {
		t.Errorf("ARQ-02: la sesion cambio tras reload: %s -> %s", p1.Tag(), p2.Tag())
	}
}
