package main

// Tests del estado persistente (state.go): <lista>.state.json sobrevive a
// reinicios/reloads; la memoria manda sobre el disco; --no-state no escribe.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func listaTemporal(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "lista.txt")
	if err := os.WriteFile(f, []byte("127.0.0.1:1\n127.0.0.1:2\n127.0.0.1:3\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return f, []string{f}
}

// Roundtrip: app1 guarda estado (vivo verificado, muerto verificado) y
// app2 (reinicio simulado) lo restaura SIN re-analizar.
func TestEstadoPersistenteRoundtrip(t *testing.T) {
	f, files := listaTemporal(t)
	a := NewApp(files, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.LoadProxies()
	a.mu.Lock()
	a.proxies[0].Alive = true
	a.proxies[0].Checked = true
	a.proxies[0].PingMs = 42
	a.proxies[0].LastCheck = 111
	a.proxies[1].Alive = false
	a.proxies[1].Checked = true
	a.proxies[1].LastCheck = 222
	a.proxies[2].Alive = true // sin verificar
	a.mu.Unlock()
	a.saveState()

	if _, err := os.Stat(f + ".state.json"); err != nil {
		t.Fatalf("no se creo el archivo de estado: %v", err)
	}

	b := NewApp(files, "round-robin", true, 0, "http://127.0.0.1:1/")
	b.loadState()
	b.LoadProxies()
	b.mu.Lock()
	defer b.mu.Unlock()
	p0, p1, p2 := b.proxies[0], b.proxies[1], b.proxies[2]
	if !p0.Alive || !p0.Checked || p0.PingMs != 42 || p0.LastCheck != 111 {
		t.Errorf("vivo verificado perdido: %+v", *p0)
	}
	if p1.Alive || !p1.Checked || p1.LastCheck != 222 {
		t.Errorf("muerto verificado perdido (re-analizaria): %+v", *p1)
	}
	if p2.Checked {
		t.Errorf("el sin-verificar heredo checked: %+v", *p2)
	}
}

// La memoria (estado en vivo de la sesion) manda sobre un disco desactualizado.
func TestEstadoMemoriaMandaSobreDisco(t *testing.T) {
	f, files := listaTemporal(t)
	// disco dice: proxies[0] muerto
	os.WriteFile(f+".state.json", []byte(`{"http|127.0.0.1|1|":{"alive":false,"fails":0,"checked":true,"ping_ms":0,"last_check":5}}`), 0644)

	a := NewApp(files, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.loadState()
	a.LoadProxies()
	a.mu.Lock()
	if a.proxies[0].Alive {
		t.Errorf("arranque: debia heredar muerto del disco")
	}
	// la sesion lo revivio (check manual) -> memoria manda en el reload
	a.proxies[0].Alive = true
	a.mu.Unlock()
	a.LoadProxies()
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.proxies[0].Alive {
		t.Errorf("reload: la memoria debe mandar sobre el disco (se perdio el revive)")
	}
}

// --no-state: ni carga ni escribe.
func TestEstadoDesactivadoNoEscribe(t *testing.T) {
	f, files := listaTemporal(t)
	a := NewApp(files, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.stateDisabled = true
	a.loadState()
	a.LoadProxies()
	a.mu.Lock()
	a.proxies[0].Alive = false
	a.proxies[0].Checked = true
	a.mu.Unlock()
	a.saveState()
	if _, err := os.Stat(f + ".state.json"); err == nil {
		t.Errorf("--no-state creo un archivo de estado igualmente")
	}
}

// Al guardar se podan las claves que ya no estan en la lista (import que
// elimina proxies no deja fantasmas en el JSON).
func TestEstadoPodaClavesAusentes(t *testing.T) {
	f, files := listaTemporal(t)
	os.WriteFile(f+".state.json", []byte(`{
"http|127.0.0.1|1|":{"alive":false,"fails":0,"checked":true,"ping_ms":0,"last_check":5},
"http|9.9.9.9|8080|":{"alive":true,"fails":0,"checked":true,"ping_ms":9,"last_check":9}
}`), 0644)

	a := NewApp(files, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.loadState()
	a.LoadProxies()
	a.saveState()

	data, err := os.ReadFile(f + ".state.json")
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]stateEntry)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json invalido tras guardar: %v", err)
	}
	if _, ok := m["http|9.9.9.9|8080|"]; ok {
		t.Errorf("la clave ausente de la lista no fue podada")
	}
	if _, ok := m["http|127.0.0.1|1|"]; !ok {
		t.Errorf("la clave presente desaparecio del estado")
	}
}

// Estado corrupto: se ignora silenciosamente y la app arranca normal.
func TestEstadoCorruptoSeIgnora(t *testing.T) {
	f, files := listaTemporal(t)
	os.WriteFile(f+".state.json", []byte("{esto no es json"), 0644)
	a := NewApp(files, "round-robin", true, 0, "http://127.0.0.1:1/")
	a.loadState()
	a.LoadProxies()
	alive, total := a.counts()
	if total != 3 || alive != 3 {
		t.Errorf("estado corrupto dejo la lista en %d/%d (esperaba 3/3)", alive, total)
	}
}
