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
	Alive     bool   `json:"alive"`
	Fails     int    `json:"fails"`
	Checked   bool   `json:"checked"`
	PingMs    int    `json:"ping_ms"`
	LastCheck int64  `json:"last_check"` // unix seg, 0 = nunca
	Country   string `json:"country,omitempty"`
	// Alt: protocolo real detectado (el declarado no funcionaba). Se
	// persiste para que el trafico siga usando el bueno tras reiniciar.
	Alt string `json:"alt,omitempty"`
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
// stateSaveChunk: entradas que se copian por tanda con a.mu tomado. Con 130k
// proxies, construir el mapa entero bajo el lock lo mantenia tomado ~40ms
// cada 1,5s durante un chequeo (micro-pausa en la rotacion de OB). Copiando
// por tandas cada bloqueo baja a ~1ms y el mapa+JSON se arma FUERA del lock
// (auditoria 17/10/2026).
const stateSaveChunk = 4096

// stateSaveHook (tests): se invoca siempre con a.mu LIBRE (entre tandas y
// antes de serializar) para poder fijar que el lock no se retiene durante el
// trabajo caro.
var stateSaveHook func()

type stateKV struct {
	key string
	st  stateEntry
}

func (a *App) saveState() {
	a.mu.Lock()
	path := a.statePathFor()
	n := len(a.proxies)
	a.mu.Unlock()
	if path == "" || n == 0 {
		return
	}

	kv := make([]stateKV, 0, n)
	for start := 0; start < n; start += stateSaveChunk {
		a.mu.Lock()
		end := start + stateSaveChunk
		if end > len(a.proxies) {
			end = len(a.proxies)
		}
		for i := start; i < end; i++ {
			p := a.proxies[i]
			kv = append(kv, stateKV{key: p.Key(), st: stateEntry{
				Alive: p.Alive, Fails: p.Fails, Checked: p.Checked,
				PingMs: p.PingMs, LastCheck: p.LastCheck, Country: p.Country,
				Alt: p.AltScheme,
			}})
		}
		encogio := end < start+stateSaveChunk // el pool se sustituyo a mitad
		a.mu.Unlock()
		if stateSaveHook != nil {
			stateSaveHook()
		}
		if encogio {
			break
		}
	}

	m := make(map[string]stateEntry, len(kv))
	for _, x := range kv {
		m[x.key] = x.st
	}
	if stateSaveHook != nil {
		stateSaveHook()
	}
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
