package main

// Tests del sistema de licencias (modo demo / Pro) y del contador de
// candidatos que aplica el tope demo del checker masivo.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func conLicPro(t *testing.T) {
	t.Helper()
	v := true
	licTestPro = &v
	t.Cleanup(func() { licTestPro = nil })
}

func enModoDemo(t *testing.T) {
	t.Helper()
	v := false
	licTestPro = &v
	t.Cleanup(func() { licTestPro = nil })
}

func TestLicEstadoInicial(t *testing.T) {
	// sin archivo de licencia (o forzado demo) debe describir modo demo
	enModoDemo(t)
	if licPro() {
		t.Fatal("con override demo, licPro() debio ser false")
	}
	if d := licDesc(); !strings.Contains(d, "Demo") {
		t.Errorf("licDesc demo = %q", d)
	}
	conLicPro(t)
	if !licPro() {
		t.Fatal("con override pro, licPro() debio ser true")
	}
	if d := licDesc(); !strings.Contains(d, "Pro") {
		t.Errorf("licDesc pro = %q", d)
	}
}

func TestStatsExponenVersionYLicencia(t *testing.T) {
	a := NewApp(nil, "round-robin", true, 0, "")
	st := a.statsSnapshot()
	if st.Version == "" {
		t.Error("stats.version vacia")
	}
	if st.Lic == "" {
		t.Error("stats.lic vacia")
	}
}

func TestCountCandidatesReglasDelFeed(t *testing.T) {
	// comentarios, vacias, duplicados, skipLocal y formato invalido NO cuentan
	texto := strings.Join([]string{
		"# comentario",
		"",
		"1.2.3.4:8080",
		"1.2.3.4:8080", // duplicado exacto
		"  5.6.7.8:3128 ",
		"no-es-un-proxy",
		"10.0.0.1:8080", // local (solo cuenta con skipLocal=false)
	}, "\n")

	n := countCandidates(massCfg{text: texto})
	if n != 3 { // 1.2.3.4, 5.6.7.8, 10.0.0.1
		t.Errorf("sin skipLocal: %d, esperaba 3", n)
	}
	n = countCandidates(massCfg{text: texto, skipLocal: true})
	if n != 2 { // sin el 10.0.0.1
		t.Errorf("con skipLocal: %d, esperaba 2", n)
	}
}

// TestDemoLimiteChecker: sin licencia, un job de mas de demoMaxLineas
// lineas se rechaza con error claro; con Pro arranca.
func TestDemoLimiteChecker(t *testing.T) {
	a := newMassApp(t)
	enModoDemo(t)

	lineas := make([]string, demoMaxLineas+1)
	for i := range lineas {
		// 11.x.x.x: sin esquema, unico y NO local (skipLocal=false de todas formas)
		lineas[i] = fmt.Sprintf("11.%d.%d.%d:%d",
			(i/65536)%256, (i/256)%256, i%256, 1024+(i%60000))
	}
	cfg := massCfg{text: strings.Join(lineas, "\n"), timeoutMs: 100, threads: 1}
	if _, err := a.massStart(cfg); err == nil || !strings.Contains(err.Error(), "demo") {
		t.Fatalf("job demo gigante debio rechazarse con aviso de demo, got %v", err)
	}

	// exactamente en el limite -> pasa (no lo supera)
	limite := strings.Join(lineas[:demoMaxLineas], "\n")
	j, err := a.massStart(massCfg{text: limite, timeoutMs: 50, threads: 1})
	if err != nil {
		t.Fatalf("job de %d lineas debio pasar el tope demo: %v", demoMaxLineas, err)
	}
	j.cancel()
	waitMassDone(t, a, 20*time.Second)

	// con Pro el limite no aplica
	conLicPro(t)
	if _, err := a.massStart(cfg); err != nil {
		t.Fatalf("job gigante con Pro debio arrancar: %v", err)
	}
	a.massCurrent().cancel()
	waitMassDone(t, a, 20*time.Second)
}

// TestDiscordSoloPro: notifyDiscord no postea nada en modo demo; en Pro si.
func TestDiscordSoloPro(t *testing.T) {
	var llegaron atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llegaron.Add(1)
		w.WriteHeader(204)
	}))
	defer ts.Close()

	// webhook.txt temporal apuntando al servidor de prueba
	ruta := filepath.Join(t.TempDir(), "webhook.txt")
	if err := os.WriteFile(ruta, []byte(ts.URL+"\n"), 0o644); err != nil {
		t.Fatalf("webhook.txt: %v", err)
	}
	j := &massJob{webhook: ruta}

	enModoDemo(t)
	j.notifyDiscord()
	if n := llegaron.Load(); n != 0 {
		t.Errorf("modo demo debio bloquear Discord, llegaron %d peticiones", n)
	}

	conLicPro(t)
	j.notifyDiscord()
	if n := llegaron.Load(); n != 1 {
		t.Errorf("modo Pro debio enviar 1 notificacion, llegaron %d", n)
	}
}
