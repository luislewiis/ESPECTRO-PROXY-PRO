package main

// Tests del gestor de la lista: removeProxies/editProxy y los endpoints
// /proxy-remove y /proxy-edit (borrado/edicion, persistencia en disco de
// keys/dead/alive, scope "all" SOLO en memoria sin tocar el .txt, y
// validacion de payload y cabeceras anti-CSRF).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// listaOps crea una lista con comentarios, vivos, muertos y credenciales.
// Devuelve la ruta y la linea original para comparaciones.
func listaOps(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "lista.txt")
	datos := "# comentario que se conserva\n" +
		"1.1.1.1:8080\n" +
		"2.2.2.2:8080\n" +
		"user:pass@3.3.3.3:1080\n" +
		"4.4.4.4:8080\n"
	if err := os.WriteFile(f, []byte(datos), 0644); err != nil {
		t.Fatal(err)
	}
	return f, []string{f}
}

// marcaEstado pone un proxy concreto como vivo verificado (para poder
// distinguir vivos/muertos en los tests de alcance).
func marcaEstado(a *App, host string, alive bool) {
	a.mu.Lock()
	for _, p := range a.proxies {
		if p.Host == host {
			p.Alive = alive
			p.Checked = true
			p.PingMs = 33
			p.LastCheck = 1000
		}
	}
	a.aliveDirty = true
	a.mu.Unlock()
}

func TestBorradoScopeMuertos(t *testing.T) {
	f, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	marcaEstado(a, "1.1.1.1", true)  // vivo
	marcaEstado(a, "2.2.2.2", false) // muerto verificado
	marcaEstado(a, "4.4.4.4", false) // muerto verificado
	// 3.3.3.3 queda sin verificar (Alive=true, Checked=false)

	n, written, err := a.removeProxies(nil, "dead")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("scope dead debio borrar 2 (solo los verificados muertos), got %d", n)
	}
	if len(written) != 1 || written[0] != f {
		t.Fatalf("no se reescribio la lista de origen: %v", written)
	}
	_, total := a.counts()
	if total != 2 {
		t.Fatalf("quedaron %d proxies, esperaba 2 (vivo + sin verificar)", total)
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	txt := string(data)
	if !strings.Contains(txt, "# comentario que se conserva") {
		t.Error("el comentario desaparecio de la lista")
	}
	if !strings.Contains(txt, "1.1.1.1:8080") || !strings.Contains(txt, "3.3.3.3:1080") {
		t.Error("el vivo y el sin-verificar debieron conservarse en disco")
	}
	if strings.Contains(txt, "2.2.2.2:8080") || strings.Contains(txt, "4.4.4.4:8080") {
		t.Error("los muertos debieron borrarse del fichero")
	}
}

func TestBorradoScopeVivosYAll(t *testing.T) {
	f, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	marcaEstado(a, "2.2.2.2", false) // unico muerto

	n, _, err := a.removeProxies(nil, "alive")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // 1.1.1.1 vivo + 3.3.3.3/4.4.4.4 sin verificar (Alive=true)
		t.Fatalf("scope alive debio borrar 3, got %d", n)
	}
	_, total := a.counts()
	if total != 1 {
		t.Fatalf("quedaron %d, esperaba 1 (el muerto)", total)
	}

	n, written, err := a.removeProxies(nil, "all")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("scope all debio borrar 1, got %d", n)
	}
	if len(written) != 0 {
		t.Fatalf("vaciar todo NO debe reescribir nada en disco, listas tocadas: %v", written)
	}
	_, total = a.counts()
	if total != 0 {
		t.Fatalf("lista debio quedar vacia, quedan %d", total)
	}
	// el .txt de origen queda INTACTO (lo que habia tras el borrado de vivos)
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), "2.2.2.2:8080") {
		t.Error("vaciar todo debio dejar el .txt intacto (sigue el muerto)")
	}
	if !strings.Contains(string(data), "# comentario que se conserva") {
		t.Error("el comentario debio seguir en el .txt (no se toco)")
	}
	// recargar desde el disco trae la lista de vuelta
	a.LoadProxies()
	_, total = a.counts()
	if total != 1 {
		t.Fatalf("tras recargar desde el disco debio volver 1 proxy, got %d", total)
	}
}

func TestBorradoPorClaves(t *testing.T) {
	_, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	marcaEstado(a, "2.2.2.2", false) // muerto

	var keys []string
	a.mu.Lock()
	for _, p := range a.proxies {
		if p.Host == "2.2.2.2" {
			keys = append(keys, p.Key())
		}
	}
	a.mu.Unlock()
	if len(keys) != 1 {
		t.Fatalf("no encontre 2.2.2.2, got %v", keys)
	}

	n, _, err := a.removeProxies(map[string]bool{keys[0]: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("borrado por claves debio ser 1, got %d", n)
	}
	alive, total := a.counts()
	if total != 3 || alive != 3 {
		t.Fatalf("esperaba 3 vivos de 3 (solo se borro la clave pedida), got %d/%d", alive, total)
	}
	// clave inexistente: no borra nada ni reescribe
	n, written, err := a.removeProxies(map[string]bool{"http|9.9.9.9|1|": true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(written) != 0 {
		t.Fatalf("clave fantasma debio dar 0/0, got %d/%v", n, written)
	}
}

func TestBorradoNoResucitaConReload(t *testing.T) {
	f, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.loadState()
	a.LoadProxies()
	marcaEstado(a, "1.1.1.1", true)
	marcaEstado(a, "2.2.2.2", false)
	marcaEstado(a, "4.4.4.4", false)
	a.waitStateSave() // persiste estado de los que quedan

	if n, _, err := a.removeProxies(nil, "dead"); err != nil || n != 2 {
		t.Fatalf("borrado de muertos: n=%d err=%v", n, err)
	}
	a.waitStateSave() // el estado poda las claves ausentes

	// reinicio simulado
	b := NewApp(files, "round-robin", true, 0, "")
	b.loadState()
	b.LoadProxies()
	_, total := b.counts()
	if total != 2 {
		t.Fatalf("tras reload debio quedar 2 proxies, got %d", total)
	}
	// el estado del vivo sobrevive y el borrado no aparece en el state.json
	data, err := os.ReadFile(f + ".state.json")
	if err != nil {
		t.Fatalf("falta el archivo de estado: %v", err)
	}
	if strings.Contains(string(data), "2.2.2.2") {
		t.Error("el estado del proxy borrado no se podo")
	}
	if !strings.Contains(string(data), "1.1.1.1") {
		t.Error("se perdio el estado del vivo que queda")
	}
}

func TestEditProxyCredencialesConservaEstado(t *testing.T) {
	f, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	marcaEstado(a, "3.3.3.3", true) // user:pass@3.3.3.3:1080 (vivo verificado)

	var key string
	a.mu.Lock()
	for _, p := range a.proxies {
		if p.Host == "3.3.3.3" {
			key = p.Key()
		}
	}
	a.mu.Unlock()

	newKey, err := a.editProxy(key, "user:nueva@3.3.3.3:1080")
	if err != nil {
		t.Fatal(err)
	}
	// la clave es scheme|host|puerto|user: la password NO cambia la clave
	if newKey != key {
		t.Errorf("la clave no debio cambiar solo por la password: %s -> %s", key, newKey)
	}
	a.mu.Lock()
	var got *Proxy
	for _, p := range a.proxies {
		if p.Host == "3.3.3.3" {
			got = p
		}
	}
	a.mu.Unlock()
	if got == nil || got.Password != "nueva" {
		t.Fatalf("password no aplicada: %+v", got)
	}
	if !got.Alive || !got.Checked || got.PingMs != 33 {
		t.Errorf("el estado debio conservarse (mismo host:puerto): %+v", *got)
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), "user:nueva@3.3.3.3:1080") {
		t.Errorf("la lista en disco no se actualizo: %s", string(data))
	}
	if strings.Contains(string(data), "user:pass@3.3.3.3:1080") {
		t.Error("quedo la linea vieja en disco")
	}
	// la sesion vieja se re-apunta a la clave nueva
	a.mu.Lock()
	reapuntada := false
	for _, si := range a.sessions {
		if si.key == newKey {
			reapuntada = true
		}
	}
	a.mu.Unlock()
	_ = reapuntada // sin sesiones creadas no hay nada que comprobar aqui
}

func TestEditProxyCambiaAddrReseteaEstado(t *testing.T) {
	_, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	marcaEstado(a, "1.1.1.1", true)

	var key string
	a.mu.Lock()
	for _, p := range a.proxies {
		if p.Host == "1.1.1.1" {
			key = p.Key()
		}
	}
	a.mu.Unlock()

	if _, err := a.editProxy(key, "9.9.9.9:9090"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.proxies {
		if p.Host == "9.9.9.9" {
			if p.Alive || p.Checked || p.PingMs != 0 {
				t.Errorf("al cambiar host:puerto el estado debio reiniciarse: %+v", *p)
			}
			return
		}
	}
	t.Fatal("el proxy editado no esta en la lista")
}

func TestEditProxyErrores(t *testing.T) {
	_, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()

	if _, err := a.editProxy("http|1.1.1.1|8080|", "basura!!"); err == nil {
		t.Error("linea invalida debio dar error")
	}
	if _, err := a.editProxy("http|0.0.0.0|1|", "5.5.5.5:8080"); err == nil {
		t.Error("clave inexistente debio dar error")
	}
	if _, err := a.editProxy("http|1.1.1.1|8080|", "2.2.2.2:8080"); err == nil {
		t.Error("editar a un host duplicado debio dar error")
	}
}

// ---- endpoints -----------------------------------------------------------

func panelPost(t *testing.T, url, body string) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GW-Panel", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestProxyRemoveEndpoint(t *testing.T) {
	f, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	marcaEstado(a, "1.1.1.1", true)
	marcaEstado(a, "2.2.2.2", false)
	marcaEstado(a, "4.4.4.4", false)
	ts := httptest.NewServer(a.APIMux(18080, "127.0.0.1"))
	defer ts.Close()

	// metodo distinto de POST -> 405
	resp, err := http.Get(ts.URL + "/proxy-remove")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET debio dar 405, got %d", resp.StatusCode)
	}

	// sin cabecera X-GW-Panel -> 403
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/proxy-remove", strings.NewReader(`{"scope":"all"}`))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("sin cabecera panel debio dar 403, got %d", resp2.StatusCode)
	}

	// scope desconocido -> 400
	code, m := panelPost(t, ts.URL+"/proxy-remove", `{"scope":"zombie"}`)
	if code != http.StatusBadRequest || m["error"] == nil {
		t.Errorf("scope invalido: %d %v", code, m)
	}
	// sin keys ni scope -> 400
	code, m = panelPost(t, ts.URL+"/proxy-remove", `{}`)
	if code != http.StatusBadRequest {
		t.Errorf("payload vacio: %d %v", code, m)
	}
	// JSON corrupto -> 400
	code, _ = panelPost(t, ts.URL+"/proxy-remove", `no-json`)
	if code != http.StatusBadRequest {
		t.Errorf("JSON corrupto debio dar 400, got %d", code)
	}

	// borrado real por scope dead
	code, m = panelPost(t, ts.URL+"/proxy-remove", `{"scope":"dead"}`)
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("borrado: %d %v", code, m)
	}
	if removed := int(m["removed"].(float64)); removed != 2 {
		t.Errorf("removed esperaba 2, got %d", removed)
	}
	if total := int(m["total"].(float64)); total != 2 {
		t.Errorf("total esperaba 2, got %d", total)
	}
	if files, ok := m["files"].([]interface{}); !ok || len(files) != 1 {
		t.Errorf("files debia apuntar a la lista reescrita: %v", m["files"])
	}
	if p, ok := m["persist"].(bool); !ok || !p {
		t.Errorf("scope dead debio responder persist=true: %v", m["persist"])
	}

	// scope=all: SOLO memoria (no toca el .txt, ni el state)
	code, m = panelPost(t, ts.URL+"/proxy-remove", `{"scope":"all"}`)
	if code != http.StatusOK || m["ok"] != true {
		t.Fatalf("vaciar todo: %d %v", code, m)
	}
	if removed := int(m["removed"].(float64)); removed != 2 {
		t.Errorf("removed esperaba 2 (los que quedaban), got %d", removed)
	}
	if total := int(m["total"].(float64)); total != 0 {
		t.Errorf("total esperaba 0, got %d", total)
	}
	if files, ok := m["files"].([]interface{}); !ok || len(files) != 0 {
		t.Errorf("vaciar todo no debe reportar ficheros reescritos: %v", m["files"])
	}
	if p, ok := m["persist"].(bool); !ok || p {
		t.Errorf("scope all debio responder persist=false: %v", m["persist"])
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "1.1.1.1:8080") ||
		!strings.Contains(string(data), "# comentario que se conserva") {
		t.Errorf("vaciar todo debio dejar el .txt intacto: %s", string(data))
	}
}

func TestProxyEditEndpoint(t *testing.T) {
	f, files := listaOps(t)
	a := NewApp(files, "round-robin", true, 0, "")
	a.LoadProxies()
	ts := httptest.NewServer(a.APIMux(18080, "127.0.0.1"))
	defer ts.Close()

	// GET -> 405
	resp, _ := http.Get(ts.URL + "/proxy-edit")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET debio dar 405, got %d", resp.StatusCode)
	}

	// sin cabecera panel -> 403
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/proxy-edit", strings.NewReader(`{"key":"x","line":"1.1.1.1:1"}`))
	resp2, _ := http.DefaultClient.Do(req)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("403 esperado, got %d", resp2.StatusCode)
	}

	// campos obligatorios
	code, m := panelPost(t, ts.URL+"/proxy-edit", `{"key":"","line":""}`)
	if code != http.StatusBadRequest || m["error"] == nil {
		t.Errorf("campos vacios: %d %v", code, m)
	}
	// linea invalida
	code, m = panelPost(t, ts.URL+"/proxy-edit", `{"key":"http|1.1.1.1|8080|","line":"???"}`)
	if code != http.StatusBadRequest || m["error"] == nil {
		t.Errorf("linea invalida: %d %v", code, m)
	}
	// edicion correcta
	code, m = panelPost(t, ts.URL+"/proxy-edit", `{"key":"http|1.1.1.1|8080|","line":"1.1.1.1:9999"}`)
	if code != http.StatusOK || m["ok"] != true || m["key"] != "http|1.1.1.1|9999|" {
		t.Fatalf("edicion: %d %v", code, m)
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "1.1.1.1:9999") {
		t.Errorf("el fichero no se actualizo: %s", string(data))
	}
	if strings.Contains(string(data), "\n1.1.1.1:8080\n") {
		t.Error("la linea vieja sigue en el fichero")
	}
}
