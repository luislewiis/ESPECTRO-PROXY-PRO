package main

// Sonda C1 (auditoria): data race entre RunChecks (range a.proxies SIN mu)
// y LoadProxies (swap del slice CON mu) + lectura de old[p.Key()].Alive
// sin mu en LoadProxies. Detectada con el race detector oficial.
// Verificar SIEMPRE con:  go test -race -count=1 ./...
// Debe pasar con y sin -race tras aplicar el fix (Fase 1).

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRaceRunChecksVsLoad(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "list.txt")
	var b []byte
	for i := 0; i < 50; i++ {
		b = append(b, fmt.Sprintf("127.0.0.1:%d\n", 1+i%2)...)
	}
	if err := os.WriteFile(f, b, 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp([]string{f}, "round-robin", true, 0, "http://127.0.0.1:1/")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			a.LoadProxies()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			a.RunChecks()
		}
	}()
	wg.Wait()
}
