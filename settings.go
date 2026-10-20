package main

// Ajustes del panel (settings.json, junto al ejecutable).
//
// Aqui viven TODO lo que se puede cambiar en caliente desde la pestana
// "Configuracion": modo del chequeo, tipo de validacion (GET o CONNECT),
// reintentos, intervalo, estrategia, URL de validacion, success key,
// GeoIP, Auto-Fuentes y la densidad del panel (resumen/detalle).
//
// NO se guardan secretos: el token de la API sigue siendo solo de CLI.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type appSettings struct {
	// CheckMode: "alive" (solo vivos + sin verificar) | "full" (completo).
	CheckMode string `json:"check_mode"`
	// CheckConnect: validar por tunel CONNECT (lo que necesita OB).
	CheckConnect *bool `json:"check_connect,omitempty"`
	// CheckRetries: reintentos por proxy (cada uno con otro protocolo).
	CheckRetries *int `json:"check_retries,omitempty"`
	// CheckInterval: segundos entre ciclos de health-check (0 = off).
	CheckInterval *int `json:"check_interval,omitempty"`
	// Strategy: round-robin | random | sticky | fastest.
	Strategy string `json:"strategy,omitempty"`
	// TestURL: URL de validacion.
	TestURL string `json:"test_url,omitempty"`
	// SuccessKey: texto exigido en el cuerpo (validacion de contenido).
	SuccessKey string `json:"success_key,omitempty"`
	// GeoMMDB: base MaxMind offline.
	GeoMMDB string `json:"geo_mmdb,omitempty"`
	// Harvest: Auto-Fuentes on/off.
	Harvest *bool `json:"harvest,omitempty"`
	// HarvestInterval: minutos entre pasadas del Auto-Fuentes.
	HarvestInterval *int `json:"harvest_interval,omitempty"`
	// Mode: densidad del panel "resumen" (default) | "detalle".
	Mode string `json:"mode,omitempty"`
	// CheckKind: "GET" | "CONNECT" (como lo ve el usuario).
	CheckKind string `json:"check_kind,omitempty"`
}

var settingsMu sync.Mutex

// settingsPath: settings.json en la carpeta del ejecutable (o el cwd si
// no se puede resolver). Es un archivo PROPIO: nunca toca proxies.txt.
func settingsPath() string {
	exe, err := os.Executable()
	if err == nil {
		if p, err := filepath.Abs(exe); err == nil {
			return filepath.Join(filepath.Dir(p), "settings.json")
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return "settings.json"
	}
	return filepath.Join(wd, "settings.json")
}

// currentSettings: los valores vigentes (no los del fichero).
func (a *App) currentSettings() appSettings {
	a.mu.Lock()
	mode := a.checkScope
	conn := a.checkConnect
	retries := a.checkRetries
	itv := a.checkItv
	strategy := a.strategy
	a.mu.Unlock()
	if mode != "full" {
		mode = "alive"
	}
	return appSettings{
		CheckMode:       mode,
		CheckConnect:    &conn,
		CheckRetries:    &retries,
		CheckInterval:   &itv,
		Strategy:        strategy,
		TestURL:         a.testURL,
		SuccessKey:      a.checkKey,
		GeoMMDB:         a.geoPath,
		Harvest:         &a.harvestOn,
		HarvestInterval: &a.harvestItv,
		CheckKind:       map[bool]string{true: "CONNECT", false: "GET"}[conn],
		Mode:            a.uiMode,
	}
}

// mergeSettings: mezcla un parche sobre la base (el fichero) SOLO en los
// campos presentes en la peticion. Asi los valores que vienen de la linea
// comandos (--harvest, --check-mode...) NO se persisten: si arrancas con
// "--harvest-interval 9999", eso no debe acabar guardado en settings.json
// (si no, el siguiente arranque normal heredaria el valor del test).
func mergeSettings(base, patch appSettings, keys map[string]bool) appSettings {
	if keys == nil {
		return patch
	}
	if keys["check_mode"] {
		base.CheckMode = patch.CheckMode
	}
	if keys["check_connect"] {
		base.CheckConnect = patch.CheckConnect
	}
	if keys["check_retries"] {
		base.CheckRetries = patch.CheckRetries
	}
	if keys["check_interval"] {
		base.CheckInterval = patch.CheckInterval
	}
	if keys["strategy"] {
		base.Strategy = patch.Strategy
	}
	if keys["test_url"] {
		base.TestURL = patch.TestURL
	}
	if keys["success_key"] {
		base.SuccessKey = patch.SuccessKey
	}
	if keys["geo_mmdb"] {
		base.GeoMMDB = patch.GeoMMDB
	}
	if keys["harvest"] {
		base.Harvest = patch.Harvest
	}
	if keys["harvest_interval"] {
		base.HarvestInterval = patch.HarvestInterval
	}
	if keys["mode"] {
		base.Mode = patch.Mode
	}
	return base
}

// applyAndSave: aplica el parche en caliente y guarda en settings.json solo
// los campos que venian en la peticion (sobre lo que ya habia en el
// fichero). Devuelve los ajustes resultantes.
func (a *App) applyAndSave(raw []byte) (appSettings, error) {
	var patch appSettings
	if err := json.Unmarshal(raw, &patch); err != nil {
		return appSettings{}, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return appSettings{}, err
	}
	present := make(map[string]bool, len(keys))
	for k := range keys {
		present[k] = true
	}
	if err := a.applySettings(patch); err != nil {
		return appSettings{}, err
	}
	base, ok := a.loadSettings()
	if !ok {
		base = appSettings{}
	}
	merged := mergeSettings(base, patch, present)
	if !a.settingsOff {
		if err := a.saveSettings(merged); err != nil {
			a.logf("no se pudieron guardar los ajustes: %v", err)
		}
	}
	return normSettings(a.currentSettings()), nil
}

// applySettings aplica los ajustes en caliente (lo que llega del panel).
// Devuelve error si algun valor no es valido.
//
// Los flags de la linea de comandos MANDAN sobre el fichero: si el usuario
// escribio --check-mode full en el arranque, el settings.json no lo pisa.
func (a *App) applySettings(s appSettings) error {
	skip := a.explicitFlags
	set := func(flag string) bool { return skip != nil && skip[flag] }
	a.mu.Lock()
	if s.CheckMode != "" && !set("check-mode") && !set("check-all") {
		if s.CheckMode != "alive" && s.CheckMode != "full" && s.CheckMode != "all" {
			a.mu.Unlock()
			return errSettings("check_mode invalido (alive|full)")
		}
		if s.CheckMode == "all" {
			s.CheckMode = "full"
		}
		a.checkScope = s.CheckMode
		a.checkAll = s.CheckMode == "full"
	}
	if s.CheckConnect != nil && !set("check-connect") {
		a.checkConnect = *s.CheckConnect
	}
	if s.CheckRetries != nil && !set("check-retries") {
		if *s.CheckRetries < 0 || *s.CheckRetries > 10 {
			a.mu.Unlock()
			return errSettings("check_retries fuera de rango (0-10)")
		}
		a.checkRetries = *s.CheckRetries
	}
	if s.CheckInterval != nil && !set("check-interval") {
		if *s.CheckInterval < 0 {
			a.mu.Unlock()
			return errSettings("check_interval negativo")
		}
		a.checkItv = *s.CheckInterval
	}
	if s.Strategy != "" && !set("strategy") {
		switch s.Strategy {
		case "round-robin", "random", "sticky", "fastest":
			a.strategy = s.Strategy
		default:
			a.mu.Unlock()
			return errSettings("strategy invalida")
		}
	}
	if s.TestURL != "" && !set("test-url") {
		a.testURL = s.TestURL
	}
	if s.SuccessKey != "" && !set("success-key") {
		a.checkKey = s.SuccessKey
	}
	if s.GeoMMDB != "" && !set("geo-mmdb") {
		a.geoPath = s.GeoMMDB
	}
	if s.Harvest != nil && !set("harvest") {
		a.harvestOn = *s.Harvest
	}
	if s.HarvestInterval != nil && !set("harvest-interval") {
		if *s.HarvestInterval < 1 {
			a.mu.Unlock()
			return errSettings("harvest_interval < 1")
		}
		a.harvestItv = *s.HarvestInterval
	}
	if s.Mode != "" {
		if s.Mode != "resumen" && s.Mode != "detalle" {
			a.mu.Unlock()
			return errSettings("mode invalido (resumen|detalle)")
		}
		a.uiMode = s.Mode
	}
	a.mu.Unlock()
	a.syncHarvester()
	return nil
}

// syncHarvester: arranca, para o reinicia el Auto-Fuentes segun los
// ajustes vigentes (encendido/apagado e intervalo).
func (a *App) syncHarvester() {
	a.mu.Lock()
	on := a.harvestOn
	itv := a.harvestItv
	out := a.harvestOutPath
	max := a.harvestMax
	cur := a.harv
	a.mu.Unlock()
	if out == "" {
		return
	}
	if !on {
		if cur != nil {
			cur.Stop()
			a.mu.Lock()
			a.harv = nil
			a.mu.Unlock()
			a.logf("auto-fuentes: detenido")
		}
		return
	}
	if cur != nil {
		// Si cambia el intervalo, se reinicia el recolector.
		if cur.itv == time.Duration(itv)*time.Minute {
			return
		}
		cur.Stop()
		a.mu.Lock()
		a.harv = nil
		a.mu.Unlock()
	}
	h := newHarvester(a, out, itv)
	h.maxLines = max
	a.mu.Lock()
	a.harv = h
	a.mu.Unlock()
	go h.Loop()
}

// errSettings: error de ajuste con mensaje legible para el panel.
type errSettings string

func (e errSettings) Error() string { return string(e) }

// saveSettings guarda el fichero de ajustes (atomico: .tmp + rename).
func (a *App) saveSettings(s appSettings) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	path := settingsPath()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadSettings lee settings.json (silencioso si no existe o esta roto).
func (a *App) loadSettings() (appSettings, bool) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	data, err := os.ReadFile(settingsPath())
	if err != nil {
		return appSettings{}, false
	}
	var s appSettings
	if err := json.Unmarshal(data, &s); err != nil {
		return appSettings{}, false
	}
	return s, true
}

// applySettingsFile: carga el fichero y lo aplica (arranque).
func (a *App) applySettingsFile() {
	s, ok := a.loadSettings()
	if !ok {
		return
	}
	if err := a.applySettings(s); err != nil {
		a.logf("ajustes ignorados: %v", err)
		return
	}
	a.logf("ajustes cargados desde %s", filepath.Base(settingsPath()))
}

// normSettings: normaliza para respuestas y comparaciones.
func normSettings(s appSettings) appSettings {
	if s.CheckMode == "all" {
		s.CheckMode = "full"
	}
	if s.CheckMode == "" {
		s.CheckMode = "alive"
	}
	s.TestURL = strings.TrimSpace(s.TestURL)
	s.SuccessKey = strings.TrimSpace(s.SuccessKey)
	return s
}
