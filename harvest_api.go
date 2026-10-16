package main

// harvest_api.go — endpoints del Auto-Fuentes (harvest.go).
//
// Lecturas (/harvest/status, /harvest/sources, /harvest/export): exigen el
// token SOLO si --api-token esta configurado (leerOK).
// Mutantes (/harvest/run|discover|purge|source): POST + X-GW-Panel + token,
// igual que el resto del panel (allowPanel => anti-CSRF).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (a *App) registerHarvest(mux *http.ServeMux) {
	// Estado + contadores
	mux.HandleFunc("/harvest/status", func(w http.ResponseWriter, r *http.Request) {
		if !a.leerOK(w, r) {
			return
		}
		a.mu.Lock()
		h := a.harv
		a.mu.Unlock()
		if h == nil {
			jsonOut(w, map[string]interface{}{"enabled": false})
			return
		}
		st := h.Stats()
		jsonOut(w, map[string]interface{}{"enabled": true, "stats": st})
	})

	// Lista de fuentes (sin exponer nada sensible: son URLs publicas)
	mux.HandleFunc("/harvest/sources", func(w http.ResponseWriter, r *http.Request) {
		if !a.leerOK(w, r) {
			return
		}
		a.mu.Lock()
		h := a.harv
		a.mu.Unlock()
		if h == nil {
			jsonOut(w, map[string]interface{}{"ok": false, "enabled": false, "sources": []HarvestSource{}})
			return
		}
		jsonOut(w, map[string]interface{}{"ok": true, "enabled": true, "sources": h.ListSources()})
	})

	// Recoger ahora
	mux.HandleFunc("/harvest/run", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		h := a.harvester()
		if h == nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "Auto-Fuentes desactivado (arranca con --harvest)"})
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := h.RunOnce(ctx); err != nil {
				a.logf("auto-fuentes: %v", err)
			}
		}()
		jsonOut(w, map[string]interface{}{"ok": true, "started": true})
	})

	// Descubrir fuentes nuevas (meta-harvesting)
	mux.HandleFunc("/harvest/discover", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		h := a.harvester()
		if h == nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "Auto-Fuentes desactivado (arranca con --harvest)"})
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			if _, err := h.Discover(ctx); err != nil {
				a.logf("auto-fuentes: descubrimiento fallo: %v", err)
			}
		}()
		jsonOut(w, map[string]interface{}{"ok": true, "started": true})
	})

	// Agregar / habilitar fuente propia
	mux.HandleFunc("/harvest/source", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		h := a.harvester()
		if h == nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "Auto-Fuentes desactivado (arranca con --harvest)"})
			return
		}
		var req HarvestSource
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "JSON invalido"})
			return
		}
		if err := h.SetSource(req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		h.saveSources()
		a.logf("auto-fuentes: fuente guardada -> %s", req.URL)
		jsonOut(w, map[string]interface{}{"ok": true, "sources": h.ListSources()})
	})

	// Quitar fuente
	mux.HandleFunc("/harvest/source/remove", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		h := a.harvester()
		if h == nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "Auto-Fuentes desactivado (arranca con --harvest)"})
			return
		}
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.URL == "" {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "url obligatoria"})
			return
		}
		ok := h.RemoveSource(req.URL)
		if ok {
			h.saveSources()
			a.logf("auto-fuentes: fuente quitada -> %s", req.URL)
		}
		jsonOut(w, map[string]interface{}{"ok": ok, "sources": h.ListSources()})
	})

	// Purgar muertos del archivo recolectado
	mux.HandleFunc("/harvest/purge", func(w http.ResponseWriter, r *http.Request) {
		if !a.allowPanel(w, r) {
			return
		}
		h := a.harvester()
		if h == nil {
			w.WriteHeader(http.StatusBadRequest)
			jsonOut(w, map[string]interface{}{"ok": false, "error": "Auto-Fuentes desactivado (arranca con --harvest)"})
			return
		}
		n, err := h.Purge()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			jsonOut(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		a.logf("auto-fuentes: purgados %d proxies muertos del archivo recolectado", n)
		jsonOut(w, map[string]interface{}{"ok": true, "removed": n})
	})

	// Descargar lo recolectado
	mux.HandleFunc("/harvest/export", func(w http.ResponseWriter, r *http.Request) {
		if !a.leerOK(w, r) {
			return
		}
		h := a.harvester()
		if h == nil {
			http.Error(w, "Auto-Fuentes desactivado", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", baseName(h.out)))
		http.ServeFile(w, r, h.out)
	})
}

// harvester devuelve el recolector activo (nil si --harvest no esta puesto).
func (a *App) harvester() *Harvester {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.harv
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[i+1:]
		}
	}
	return p
}
