package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type invalidLine struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

type importReport struct {
	OK           bool           `json:"ok"`
	Dry          bool           `json:"dry"`
	Valid        int            `json:"valid"`
	Duplicates   int            `json:"duplicates"`
	Ignored      int            `json:"ignored"`
	Invalid      []invalidLine  `json:"invalid"`
	InvalidTotal int            `json:"invalid_total"`
	Protocols    map[string]int `json:"protocols,omitempty"`
	SavedTo      string         `json:"saved_to,omitempty"`
	Total        int            `json:"total"`
	Error        string         `json:"error,omitempty"`
}

const maxImportBytes = 5 << 20 // 5 MB

var importExts = map[string]bool{".txt": true, ".lst": true, ".csv": true}

type importReq struct {
	Path string `json:"path"`
	Text string `json:"text"`
	Name string `json:"name"`
}

// rutaPermitida resuelve la ruta y exige que caiga dentro de cwd, del
// directorio del exe o de los directorios de las listas activas. Evita que
// el panel lea cualquier archivo del disco (path traversal / SSRF-file).
// Resuelve ademas symlinks/junctions para que un enlace dentro de la jaula
// no pueda apuntar a fuera de ella.
func (a *App) rutaPermitida(p string) bool {
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved // ruta real (si aun no existe, se compara la literal)
	}
	var roots []string
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		roots = append(roots, filepath.Dir(exe))
	}
	a.mu.Lock()
	for _, f := range a.files {
		if f != "" {
			roots = append(roots, filepath.Dir(f))
		}
	}
	a.mu.Unlock()
	for i, root := range roots {
		if r, err := filepath.EvalSymlinks(root); err == nil {
			roots[i] = r
		}
	}
	for _, root := range roots {
		rel, err := filepath.Rel(root, abs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// readImportPayload acepta JSON {path} o {text, name}. Con path lee el archivo
// (solo .txt/.lst/.csv, max 5MB, ruta dentro de la jaula); con text usa el
// cuerpo pegado y name el nombre del archivo original (para inferir el esquema).
func (a *App) readImportPayload(r *http.Request) (data string, source string, err error) {
	var req importReq
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxImportBytes+4096))
	if err := dec.Decode(&req); err != nil {
		return "", "", fmt.Errorf("JSON invalido: se espera {\"path\":\"...\"} o {\"text\":\"...\"}")
	}
	if strings.TrimSpace(req.Path) != "" {
		p := strings.TrimSpace(req.Path)
		if !importExts[strings.ToLower(filepath.Ext(p))] {
			return "", "", fmt.Errorf("extension no permitida (usa .txt, .lst o .csv)")
		}
		if !a.allowAnyPath && !a.rutaPermitida(p) {
			return "", "", fmt.Errorf("acceso denegado: la ruta esta fuera de los directorios permitidos (cwd, exe, listas). Usa --allow-any-path para permitirlo")
		}
		fi, statErr := os.Stat(p)
		if statErr != nil {
			return "", "", fmt.Errorf("no se pudo abrir el archivo: %v", statErr)
		}
		if fi.Size() > maxImportBytes {
			return "", "", fmt.Errorf("el archivo supera los 5 MB")
		}
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			return "", "", fmt.Errorf("no se pudo leer el archivo: %v", readErr)
		}
		return string(b), p, nil
	}
	if strings.TrimSpace(req.Text) == "" {
		return "", "", fmt.Errorf("envia {\"path\":...} o {\"text\":...}")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "texto pegado"
	}
	return req.Text, name, nil
}

// whyInvalid explica por que ParseProxy rechazo la linea (mensaje orientativo).
func whyInvalid(s string) string {
	if strings.Contains(s, "://") {
		i := strings.Index(s, "://")
		scheme := strings.ToLower(s[:i])
		if _, ok := typeMap[scheme]; !ok {
			return fmt.Sprintf("esquema no soportado '%s' (usa http, socks4, socks5)", scheme)
		}
		u, err := url.Parse(s)
		if err != nil {
			return "URL mal formada"
		}
		if u.Hostname() == "" {
			return "falta el host"
		}
		if ps := u.Port(); ps != "" {
			var n int
			fmt.Sscanf(ps, "%d", &n)
			if n < 1 || n > 65535 {
				return "puerto fuera de rango (1-65535)"
			}
		}
		return "URL invalida"
	}
	if strings.Contains(s, "@") {
		i := strings.LastIndex(s, "@")
		if _, _, ok := splitHostPort(s[i+1:]); !ok {
			return "se espera host:puerto despues de '@'"
		}
		return "credenciales invalidas"
	}
	parts := strings.Split(s, ":")
	if len(parts) >= 3 {
		if _, ok := typeMap[parts[0]]; ok {
			if parts[1] == "" {
				return "falta el host"
			}
			return "puerto invalido o fuera de rango (se espera: tipo:host:puerto:user:pass)"
		}
	}
	switch len(parts) {
	case 2:
		return "puerto faltante o invalido (se espera host:puerto)"
	case 3:
		return "puerto invalido (se espera host:puerto:usuario)"
	case 4:
		return "puerto invalido (se espera host:puerto:usuario:clave)"
	case 5:
		return "formato no reconocido"
	}
	return "formato no reconocido (ej: host:puerto, user:pass@host:puerto, socks5://host:puerto, 0:host:puerto:user:pass)"
}

// canon serializa un proxy a una forma normal que ParseProxy relee siempre.
func canon(p *Proxy) string {
	u := &url.URL{Scheme: p.Scheme, Host: p.Addr()}
	if p.User != "" {
		u.User = url.UserPassword(p.User, p.Password)
	}
	return u.String()
}

// appendImported agrega lineas canonicas al final de la lista principal
// (o a proxies_panel.txt si no se puede escribir). Devuelve la ruta usada.
func (a *App) appendImported(lines []string) (string, error) {
	a.mu.Lock()
	files := append([]string(nil), a.files...)
	a.mu.Unlock()

	target := ""
	if len(files) > 0 {
		target, _ = filepath.Abs(files[0])
	} else {
		if cwd, err := os.Getwd(); err == nil {
			target = filepath.Join(cwd, "proxies.txt")
		}
	}
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil && target != "" {
		// fallback: junto al ejecutable
		if exe, e := os.Executable(); e == nil {
			target = filepath.Join(filepath.Dir(exe), "proxies_panel.txt")
			f, err = os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				a.mu.Lock()
				seen := false
				for _, x := range a.files {
					if x == target {
						seen = true
					}
				}
				if !seen {
					a.files = append(a.files, target)
				}
				a.mu.Unlock()
			}
		}
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		w.WriteString(l)
		w.WriteString("\n")
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	return target, nil
}

// importHandler valida lineas de proxies ({path} o {text}).
// dry=true (/validate): solo informa. dry=false (/import): guarda y recarga.
func (a *App) importHandler(dry bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `{"ok":false,"error":"usa POST"}`)
			return
		}
		if !writeAuth(w, a.auth(r)) {
			return
		}
		data, source, err := a.readImportPayload(r)
		rep := importReport{OK: false, Dry: dry, Invalid: []invalidLine{},
			Protocols: map[string]int{}}

		if err != nil {
			rep.Error = err.Error()
			jsonOut(w, rep)
			return
		}

		a.mu.Lock()
		existing := make(map[string]bool, len(a.proxies))
		for _, p := range a.proxies {
			existing[p.Key()] = true
		}
		a.mu.Unlock()

		seen := make(map[string]bool)
		var accepted []string
		acceptedSet := make(map[string]bool)
		batch := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
		for i, raw := range batch {
			lineNo := i + 1
			s := strings.TrimSpace(raw)
			if s == "" || strings.HasPrefix(s, "#") {
				rep.Ignored++
				continue
			}
			p := ParseProxyDef(s, schemeFromFileName(source))
			if p == nil {
				rep.InvalidTotal++
				if len(rep.Invalid) < 100 {
					rep.Invalid = append(rep.Invalid, invalidLine{Line: lineNo, Text: s, Reason: whyInvalid(s)})
				}
				continue
			}
			if existing[p.Key()] || seen[p.Key()] || acceptedSet[p.Key()] {
				rep.Duplicates++
				continue
			}
			seen[p.Key()] = true
			acceptedSet[p.Key()] = true
			accepted = append(accepted, canon(p))
			rep.Protocols[p.Scheme]++
		}
		rep.Valid = len(accepted)
		rep.OK = rep.Valid > 0

		if dry {
			_, rep.Total = a.counts()
			jsonOut(w, rep)
			return
		}

		if rep.Valid == 0 {
			rep.Error = fmt.Sprintf("ninguna linea valida (%s, %d invalidas)", source, rep.InvalidTotal)
			_, rep.Total = a.counts()
			jsonOut(w, rep)
			return
		}
		savedTo, saveErr := a.appendImported(accepted)
		if saveErr != nil {
			rep.Error = "no se pudo guardar: " + saveErr.Error()
			_, rep.Total = a.counts()
			jsonOut(w, rep)
			return
		}
		a.LoadProxies()
		rep.SavedTo = savedTo
		_, rep.Total = a.counts()
		a.logf("importados %d proxies desde %s -> %s", rep.Valid, source, savedTo)
		jsonOut(w, rep)
	}
}
