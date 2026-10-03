package main

// Licencias ESPECTRO PROXY PRO — doble licencia:
//   - GPLv3 (comunidad): el codigo fuente se usa/distribuye bajo GPL.
//   - Comercial (Pro): binario con espectro.lic valido; desbloquea el
//     checker masivo ilimitado y las notificaciones a Discord.
//
// Modo demo (sin licencia): gateway, panel, health-check, sticky y la API
// completos; el checker masivo admite hasta demoMaxLineas por job.
// La verificacion usa internal/lic (AES-256-GCM de maquina + firma Ed25519).
// La clave privada vive en licencias/priv.key (fuera del repo) y solo pasa
// por lictool/; aqui solo va la publica.

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxygateway/internal/lic"
)

// licPubKey: clave publica Ed25519 del emisor (generada con
// `go run ./lictool genkey`; la privada NO se sube jamas al repo).
var licPubKey = "CF1JuPuhQaL7fLQUqYLWr4CYkDQxlY2O8a9oQo12e8w="

// version y buildDate se inyectan en el build de release:
//
//	go build -ldflags "-X main.version=1.0.0 -X main.buildDate=2026-10-03"
var (
	version   = "dev"
	buildDate = ""
)

// demoMaxLineas: tope de proxies por job del checker masivo sin licencia.
const demoMaxLineas = 2000

// licMaxTamano: maximo tamano razonable del archivo de licencia.
const licMaxTamano = 64 << 10 // 64 KB (una licencia real < 1 KB)

// licTestPro: los tests de Go pueden forzar el modo Pro/Demo (nil = normal).
var licTestPro *bool

type licEstado struct {
	pro      bool
	edition  string
	licensee string
	expires  string
	motivo   string // por que esta en demo (para el Log del panel)
}

var (
	licOnce sync.Once
	licCur  licEstado
)

// licRutas: busqueda de espectro.lic junto al exe y en el directorio de
// trabajo (doble-click => cwd suele ser el directorio del exe).
func licRutas() []string {
	var rutas []string
	if exe, err := os.Executable(); err == nil {
		rutas = append(rutas, filepath.Join(filepath.Dir(exe), "espectro.lic"))
	}
	if cwd, err := os.Getwd(); err == nil {
		rutas = append(rutas, filepath.Join(cwd, "espectro.lic"))
	}
	return rutas
}

func licCargar() {
	pub, err := base64.StdEncoding.DecodeString(licPubKey)
	if err != nil || len(pub) != 32 {
		licCur = licEstado{motivo: "clave publica embebida invalida"}
		return
	}
	id, err := lic.MachineID()
	if err != nil {
		licCur = licEstado{motivo: "no se pudo identificar la maquina"}
		return
	}
	visto := false
	for _, p := range licRutas() {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		// tope de tamano: un espectro.lic gigante colocado junto al exe no
		// debe inyectar memoria en el arranque (una licencia real < 1 KB)
		if len(raw) > licMaxTamano {
			licCur = licEstado{motivo: "espectro.lic demasiado grande"}
			continue
		}
		visto = true
		blob, err := lic.DecodeFile(raw)
		if err != nil {
			licCur = licEstado{motivo: "archivo espectro.lic ilegible: " + err.Error()}
			continue
		}
		pl, err := lic.Unseal(pub, blob, id)
		if err != nil {
			licCur = licEstado{motivo: "espectro.lic invalida para esta maquina: " + err.Error()}
			continue
		}
		if err := pl.Valid(time.Now()); err != nil {
			licCur = licEstado{motivo: "espectro.lic " + err.Error()}
			continue
		}
		licCur = licEstado{pro: true, edition: pl.Edition, licensee: pl.Licensee, expires: pl.Expires}
		return
	}
	if !visto {
		licCur = licEstado{motivo: "sin espectro.lic"}
	}
}

// licPro indica si hay licencia comercial valida (modo Pro).
func licPro() bool {
	if licTestPro != nil {
		return *licTestPro
	}
	licOnce.Do(licCargar)
	return licCur.pro
}

// licDesc describe la licencia para /stats, el panel y el Log.
func licDesc() string {
	if licPro() {
		if licTestPro != nil {
			return "Pro (test)"
		}
		s := "Pro"
		if licCur.licensee != "" {
			s += " — " + licCur.licensee
		}
		if licCur.expires != "" {
			s += ", caduca " + licCur.expires[:10]
		} else {
			s += ", perpetua"
		}
		return s
	}
	motivo := ""
	if licTestPro == nil {
		licOnce.Do(licCargar)
		motivo = licCur.motivo
	}
	if motivo == "" || motivo == "sin espectro.lic" {
		return fmt.Sprintf("Demo (checker hasta %d lineas/job)", demoMaxLineas)
	}
	return "Demo (" + motivo + ")"
}

// countCandidates cuenta los proxies que massFeed emitiria realmente
// (mismas reglas: comentarios/vacias fuera, skipLocal, parseo y dedup).
// Sirve para el tope demo ANTES de lanzar el job.
func countCandidates(cfg massCfg) int {
	seen := make(map[string]bool)
	n := 0
	count := func(raw string) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		if cfg.skipLocal && isLocalLine(line) {
			return
		}
		it := parseMassLine(line)
		if it == nil || seen[it.plain] {
			return
		}
		seen[it.plain] = true
		n++
	}
	scanRuta := func(path string) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
		for sc.Scan() {
			count(sc.Text())
		}
	}
	if cfg.text != "" {
		for _, line := range strings.Split(strings.ReplaceAll(cfg.text, "\r\n", "\n"), "\n") {
			count(line)
		}
		return n
	}
	fi, err := os.Stat(cfg.path)
	if err != nil {
		return 0
	}
	if !fi.IsDir() {
		scanRuta(cfg.path)
		return n
	}
	filepath.Walk(cfg.path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".txt" && ext != ".lst" && ext != ".csv" {
			return nil
		}
		scanRuta(p)
		return nil
	})
	return n
}
