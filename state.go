package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Estado persistente de proxies (auditoria "subida no re-analiza"):
// cada proxy recuerda alive/fails/checked/ping/last_check en
// <lista>.state.json (junto al primer archivo de la lista).
// Así, un reload o reinicio NO vuelve a analizar desde cero: los muertos
// siguen muertos, los vivos siguen vivos, y solo se auto-escanean los
// vivos + los nunca verificados (los muertos se revisan solo a mano).
type stateEntry struct {
	Alive     bool  `json:"alive"`
	Fails     int   `json:"fails"`
	Checked   bool  `json:"checked"`
	PingMs    int   `json:"ping_ms"`
	LastCheck int64 `json:"last_check"` // unix seg, 0 = nunca
}

// statePathFor devuelve la ruta del archivo de estado ("" = desactivado).
func (a *App) statePathFor() string {
	if a.stateDisabled {
		return ""
	}
	if a.stateFile != "" {
		return a.stateFile
	}
	files := append([]string(nil), a.files...)
	if len(files) == 0 || files[0] == "" {
		return ""
	}
	abs, err := filepath.Abs(files[0])
	if err != nil {
		return ""
	}
	return abs + ".state.json"
}

// loadState lee el estado persistido a disco (una sola vez, en arranque).
// Cualquier error es silencioso: no hay archivo la primera vez.
func (a *App) loadState() {
	a.mu.Lock()
	path := a.statePathFor()
	a.mu.Unlock()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	m := make(map[string]stateEntry)
	if err := json.Unmarshal(data, &m); err != nil {
		return // archivo corrupto: se ignora (estado en memoria manda)
	}
	a.mu.Lock()
	a.diskState = m
	a.mu.Unlock()
	a.logf("estado cargado: %d proxies desde %s", len(m), filepath.Base(path))
}

// saveState serializa el estado actual de la lista a disco (atomico:
// escribe .tmp y renombra). Silencioso ante errores (disco lleno, etc.).
func (a *App) saveState() {
	a.mu.Lock()
	path := a.statePathFor()
	if path == "" || len(a.proxies) == 0 {
		a.mu.Unlock()
		return
	}
	m := make(map[string]stateEntry, len(a.proxies))
	for _, p := range a.proxies {
		m[p.Key()] = stateEntry{
			Alive: p.Alive, Fails: p.Fails, Checked: p.Checked,
			PingMs: p.PingMs, LastCheck: p.LastCheck,
		}
	}
	a.mu.Unlock()

	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

// scheduleStateSave: guardado diferido (trailing 1.5s) para no escribir en
// disco por cada transicion durante un check de 24k proxies.
func (a *App) scheduleStateSave() {
	if a.stateDisabled {
		return
	}
	a.stateTimerMu.Lock()
	defer a.stateTimerMu.Unlock()
	if a.stateTimer == nil {
		a.stateTimer = time.AfterFunc(1500*time.Millisecond, func() { a.saveState() })
		return
	}
	a.stateTimer.Reset(1500 * time.Millisecond)
}

// waitStateSave (tests): fuerza la espera del guardado diferido.
func (a *App) waitStateSave() {
	a.stateTimerMu.Lock()
	t := a.stateTimer
	a.stateTimerMu.Unlock()
	if t != nil {
		t.Stop()
	}
	a.saveState()
}
