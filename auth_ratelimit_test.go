package main

// Tests de la fase "token en lecturas + rate-limit" (02/10/2026):
//   - con --api-token, /proxies, /proxy.txt, /checker/hits, /checker/export,
//     /logs y /checker/report exigen token (401); sin configurarlo no cambia
//     nada (modo local).
//   - tras authFailsMax fallos desde una IP se responde 429 (fuerza bruta)
//     y el bloqueo expira tras authBlockDur; un acierto limpia los fallos.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLecturasSensiblesExigenToken(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.apiToken = "secreto123"
	srv := httptest.NewServer(a.APIMux(18080, "127.0.0.1"))
	defer srv.Close()

	paths := []string{"/proxies", "/proxy.txt?format=ob", "/checker/hits", "/checker/export", "/logs", "/checker/report"}
	get := func(url string) (int, string) {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// sin token -> 401 en todas las lecturas sensibles
	for _, p := range paths {
		if code, _ := get(srv.URL + p); code != http.StatusUnauthorized {
			t.Fatalf("%s sin token debio dar 401, got %d", p, code)
		}
	}

	// con token en query (como los <a> del panel) -> pasa
	// (200, o 404 en /checker/export y /checker/report: sin datos de checker)
	want := map[string]int{
		"/proxies": 200, "/proxy.txt?format=ob": 200, "/checker/hits": 200,
		"/checker/export": 404, "/logs": 200, "/checker/report": 404,
	}
	for p, w := range want {
		sep := "?"
		if strings.Contains(p, "?") {
			sep = "&"
		}
		if code, _ := get(srv.URL + p + sep + "token=secreto123"); code != w {
			t.Fatalf("%s con token debio dar %d, got %d", p, w, code)
		}
	}

	// con token en cabecera (jget del panel) -> pasa
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/proxies", nil)
	req.Header.Set("X-API-Token", "secreto123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /proxies con cabecera: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/proxies con cabecera-token debio dar 200, got %d", resp.StatusCode)
	}

	// sin --api-token configurado -> sin cambios (modo local por defecto)
	a.apiToken = ""
	if code, _ := get(srv.URL + "/proxy.txt"); code != http.StatusOK {
		t.Fatalf("/proxy.txt sin token configurado debio dar 200, got %d", code)
	}
}

// panelPost simula un request del panel (POST + X-GW-Panel [+ token]).
func panelAuthPost(a *App, tok string) int {
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/reload", nil)
	r.Header.Set("X-GW-Panel", "1")
	if tok != "" {
		r.Header.Set("X-API-Token", tok)
	}
	a.allowPanel(rr, r)
	return rr.Code
}

// TestPanelTokenInyectaSoloMeta regresiona el bug del ReplaceAll: el literal
// '__GW_TOKEN__' del guard JS de gwToken NO debe sustituirse (si no,
// `m.content !== '<token>'` nunca se cumple y el panel deja de mandar token).
func TestPanelTokenInyectaSoloMeta(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.apiToken = "secreto123"
	srv := httptest.NewServer(a.APIMux(18081, "127.0.0.1"))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/panel")
	if err != nil {
		t.Fatalf("GET /panel: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(b)

	if !strings.Contains(page, `content="secreto123"`) {
		t.Fatal("la meta del panel debe llevar el token inyectado")
	}
	if strings.Contains(page, `content="__GW_TOKEN__"`) {
		t.Fatal("la meta no quedo sustituida")
	}
	if !strings.Contains(page, `m.content !== '__GW_TOKEN__'`) {
		t.Fatal("el guard JS de gwToken conserva el literal '__GW_TOKEN__' (n=1 solo toca la meta)")
	}

	// sin token configurado: meta vacia, guard intacto
	a.apiToken = ""
	resp, err = http.Get(srv.URL + "/panel")
	if err != nil {
		t.Fatalf("GET /panel (sin token): %v", err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	page = string(b)
	if !strings.Contains(page, `content=""`) {
		t.Fatal("sin --api-token la meta debe quedar vacia")
	}
	if !strings.Contains(page, `m.content !== '__GW_TOKEN__'`) {
		t.Fatal("el guard JS debe conservarse tambien sin token")
	}
}

func TestAuthRateLimitBloqueaTrasFallos(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.apiToken = "secreto123"
	base := time.Now()
	a.authLim.now = func() time.Time { return base } // reloj falso

	// N-1 fallos: aun sin bloquear (401)
	for i := 0; i < authFailsMax-1; i++ {
		if c := panelAuthPost(a, "malo"); c != http.StatusUnauthorized {
			t.Fatalf("fallo %d: debio dar 401, got %d", i+1, c)
		}
	}
	// N fallo: el ultimo responde 401 y activa el bloqueo
	if c := panelAuthPost(a, "malo"); c != http.StatusUnauthorized {
		t.Fatalf("fallo %d debio dar 401 (el bloqueo afecta al siguiente request), got %d", authFailsMax, c)
	}
	// con token CORRECTO durante el bloqueo -> 429
	if c := panelAuthPost(a, "secreto123"); c != http.StatusTooManyRequests {
		t.Fatalf("token correcto durante bloqueo debio dar 429, got %d", c)
	}
	// las lecturas comparten el mismo bloqueo (mismo writeAuth)
	rr := httptest.NewRecorder()
	a.leerOK(rr, httptest.NewRequest(http.MethodGet, "/proxies", nil))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("lectura durante bloqueo debio dar 429, got %d", rr.Code)
	}
	// tras expirar el bloqueo, el token correcto vuelve a pasar
	base = base.Add(authBlockDur + time.Second)
	if c := panelAuthPost(a, "secreto123"); c != http.StatusOK {
		t.Fatalf("tras expirar el bloqueo el token correcto debio pasar, got %d", c)
	}
}

func TestAuthRateLimitAciertoLimpiaFallos(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	a.apiToken = "secreto123"
	base := time.Now()
	a.authLim.now = func() time.Time { return base }

	// N-1 fallos + acierto (limpia) + N-1 fallos: NO debe bloquear
	for i := 0; i < authFailsMax-1; i++ {
		if c := panelAuthPost(a, "malo"); c != http.StatusUnauthorized {
			t.Fatalf("fallo %d: debio dar 401, got %d", i+1, c)
		}
	}
	if c := panelAuthPost(a, "secreto123"); c != http.StatusOK {
		t.Fatalf("acierto debio pasar, got %d", c)
	}
	for i := 0; i < authFailsMax-1; i++ {
		if c := panelAuthPost(a, "malo"); c != http.StatusUnauthorized {
			t.Fatalf("fallo %d tras limpiar: debio dar 401, got %d", i+1, c)
		}
	}
	if c := panelAuthPost(a, "secreto123"); c != http.StatusOK {
		t.Fatalf("acierto tras N-1+N-1 fallos debio pasar (el acierto limpia el historial), got %d", c)
	}
}

// TestCSPIndiceYPanel: las paginas HTML (indice y panel) deben servir
// frame-ancestors 'none' + X-Frame-Options DENY (clickjacking).
func TestCSPIndiceYPanel(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	srv := httptest.NewServer(a.APIMux(18082, "127.0.0.1"))
	defer srv.Close()

	for _, p := range []string{"/", "/panel"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s sin frame-ancestors 'none' en CSP (got %q)", p, csp)
		}
		if !strings.Contains(csp, "object-src 'none'") || !strings.Contains(csp, "base-uri 'self'") {
			t.Fatalf("%s CSP incompleta: %q", p, csp)
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s sin X-Frame-Options DENY", p)
		}
	}
}

// TestIndiceEscapaBind: un --bind con caracteres HTML no debe inyectarse
// en la pagina de referencia de la API (fmt.Fprintf al HTML).
func TestIndiceEscapaBind(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	srv := httptest.NewServer(a.APIMux(18080, `127.0.0.1"><script>alert(1)</script>`))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(b)
	if strings.Contains(page, `"><script>alert(1)`) {
		t.Fatal("el bind sin escapar llego crudo al HTML del indice")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("el bind no aparece escapado (html.EscapeString) en el indice")
	}
}
