# Plan de Implementación: Optimización ProxyGateway para OpenBullet / SilverBullet
**Versión:** 1.0  
**Fecha:** Octubre 2026  
**Estado actual:** `ad4958b` (Health-check CONNECT + optimizaciones base)  
**Tests base:** 428/428 PASS, 0 data races, coverage 61%  

---

## Resumen Ejecutivo

Este plan detalla la implementación de **8 tareas prioritarias** para maximizar CPM, estabilidad y stealth de ProxyGateway al trabajar con OpenBullet (OB/OB2/OBM) y SilverBullet. Todas las mejoras son **Costo Cero (0$)** y se basan en arquitectura Go, algoritmos locales y afinamiento del stack TCP de Windows.

**Objetivo medible:** Eliminar errores 502 visibles para OB, reducir latencia p90 < 2s, permitir 300+ bots concurrentes sin saturación OS, y pasar validaciones anti-bot (Cloudflare, Akamai, Datadome).

---

## Arquitectura Actual (Referencia Rápida)

| Archivo | Responsabilidad | Funciones Clave |
|---|---|---|
| `gateway.go` | Relay CONNECT/plain, túneles, watchdog idle | `handleConnect`, `handlePlain`, `roundTrip`, `tunnel` |
| `app.go` | Núcleo: pick, sesiones, índices, markFail/markOK, enfriamiento | `pick`, `markFail`, `markOK`, `NewApp` |
| `upstream.go` | Dial a proxies HTTP/SOCKS + taxonomía errores | `dialThrough`, `httpConnect`, `socks5Connect`, `socks4Connect` |
| `health.go` | Health-check periódico (scope, ping, reintentos, CONNECT mode) | `healthCheckFull`, `healthCheckBody`, `runChecksScope` |
| `proxy.go` | Parseo líneas, formatos salida, Key() | `ParseProxyDef`, `OB()`, `Tag()` |
| `api.go` | Endpoints REST + panel embebido | `/proxy.txt`, `/proxies`, `/checker/*`, `/get` |
| `main.go` | Flags, arranque, bind warning, multi-puerto | `main`, `reorderArgs`, `parsePuertos` |
| `transport.go` | Cache http.Transport por upstream | `transportePara`, `transporteEntry`, sweeper |

---

## P1 — CRÍTICO PARA CPM / ESTABILIDAD (Ejecutar Primero)

### P1.1 Failover Silencioso en `handlePlain` (Transparent Upstream Fallback)

**Problema:** En peticiones HTTP plano (`handlePlain`), si el upstream falla *antes* de enviar el body completo al destino, el gateway devuelve `502 Bad Gateway` a OpenBullet. OB marca `RETRY`/`ERROR`, bajando CPM.

**Solución:** Reintentar internamente con otro proxy vivo **sin que OB vea el fallo**. Solo devolver error al cliente si se agotan todos los proxies vivos.

**Archivos a modificar:**
- `gateway.go` — Nueva función `doPlainWithFallback`
- `app.go` — Exponer `pickExcluding(exclude map[string]bool)` si no existe (ya existe lógica similar en `handleConnect`)

**Especificación técnica:**

```go
// En gateway.go - nueva función
func (g *Gateway) doPlainWithFallback(w http.ResponseWriter, r *http.Request, maxRetries int) {
    exclude := make(map[string]bool)
    var lastErr error
    
    for attempt := 0; attempt <= maxRetries; attempt++ {
        p := g.app.pickExcluding(exclude)
        if p == nil {
            // Sin proxies disponibles
            http.Error(w, "No upstream proxies available", http.StatusBadGateway)
            return
        }
        
        // Intentar relay
        resp, err := g.roundTrip(p, r)
        if err == nil {
            // Éxito: copiar respuesta y return
            copyResponse(w, resp)
            resp.Body.Close()
            return
        }
        
        // Fallo: verificar si es recuperable (dial/handshake, NO error de destino)
        if isUpstreamRecoverable(err) {
            lastErr = err
            g.app.markFail(p)
            exclude[p.Key()] = true
            continue // Reintentar con otro proxy
        }
        
        // Error no recuperable (ej. 4xx/5xx del destino) -> propagar a cliente
        lastErr = err
        break
    }
    
    // Agotados reintentos o error no recuperable
    http.Error(w, "Upstream error: "+lastErr.Error(), http.StatusBadGateway)
}

// Helper: distingue fallos del proxy (recuperables) vs fallos del destino
func isUpstreamRecoverable(err error) bool {
    var ue *upstreamError
    return errors.As(err, &ue)
}
```

**Integración:** En `handlePlain`, reemplazar la llamada directa a `roundTrip` por `doPlainWithFallback(w, r, 3)` (3 reintentos = 4 proxies totales).

**Criterios de aceptación:**
- Test: Proxy 1 falla en dial → proxy 2 sirve la petición → OB recibe 200 OK
- Test: Todos los proxies fallan → OB recibe 502 (comportamiento actual preservado)
- Bench: CPM sube al eliminar errores 502 visibles en logs de OB

---

### P1.2 Selector `fastest` / `weighted-ping` (Top 25% Ping)

**Problema:** Round-Robin trata igual a proxy de 50ms y 1800ms. OB pierde tiempo en proxies lentos.

**Solución:** Nueva estrategia `--strategy=fastest` que elige aleatoriamente entre el **percentil 25** de proxies vivos con menor `PingMs` (mínimo 8 proxies para activar).

**Archivos a modificar:**
- `app.go` — Nueva lógica en `pick()` / nuevo `pickFastest()`
- `main.go` — Flag `--strategy` aceptar `fastest`

**Especificación técnica:**

```go
// En app.go - nuevo método
func (a *App) pickFastest() *Proxy {
    a.mu.Lock()
    defer a.mu.Unlock()
    
    alive := a.aliveListLocked()
    if len(alive) < 8 {
        // Pool pequeño: round-robin normal para no quedarse sin opciones
        return a.pickRoundRobinLocked()
    }
    
    // Ordenar por PingMs ascendente
    sort.Slice(alive, func(i, j int) bool {
        return alive[i].PingMs < alive[j].PingMs
    })
    
    // Top 25% (mínimo 2)
    topN := len(alive) / 4
    if topN < 2 {
        topN = 2
    }
    candidates := alive[:topN]
    
    // Elección aleatoria entre los mejores
    idx := rand.Intn(len(candidates))
    return candidates[idx]
}

// En pick() agregar case "fastest":
func (a *App) pick() *Proxy {
    switch a.strategy {
    case "fastest":
        return a.pickFastest()
    case "random":
        return a.pickRandom()
    case "sticky":
        return a.pickSticky()
    default:
        return a.pickRoundRobin()
    }
}
```

**Criterios de aceptación:**
- Test: Con 20 proxies (pings 50..2000ms), `pickFastest` solo elige de los 5 mejores
- Test: Pool < 8 proxies → cae a round-robin
- Bench: p90 latencia real baja >30% vs round-robin

---

### P1.3 Header Stripping Anti-Detección (Stealth Headers)

**Problema:** Proxies transparentes/anónimos añaden cabeceras que delatan bots a Cloudflare, Akamai, Datadome.

**Solución:** Lista dura en `roundTrip` eliminando cabeceras sensibles + normalizar orden/capitalización estándar HTTP/1.1.

**Archivos a modificar:**
- `gateway.go` — Función `roundTrip` / nueva `sanitizeHeaders`

**Especificación técnica:**

```go
// En gateway.go - lista de cabeceras a ELIMINAR siempre (outbound)
var stripHeaders = map[string]bool{
    "via": true,
    "x-forwarded-for": true,
    "x-real-ip": true,
    "forwarded": true,
    "x-proxy-id": true,
    "proxy-connection": true,
    "x-gateway-": true, // prefijo: cualquier X-Gateway-*
    "x-forwarded-host": true,
    "x-forwarded-proto": true,
    "x-forwarded-server": true,
    "client-ip": true,
    "true-client-ip": true,
}

// En roundTrip, antes de forward:
func sanitizeHeaders(h http.Header) {
    for k := range h {
        lk := strings.ToLower(k)
        // Eliminar match exacto o prefijo
        if stripHeaders[lk] || strings.HasPrefix(lk, "x-gateway-") {
            h.Del(k)
            continue
        }
        // Normalizar capitalización canónica (Go ya lo hace en CanonicalHeaderKey)
        // Pero forzar orden determinista para fingerprinting
    }
    // Opcional: ordenar claves para fingerprint consistente
}

// También en handleConnect: sanitizar headers de la petición CONNECT antes de enviar al upstream
```

**Criterios de aceptación:**
- Test: Petición con `Via`, `X-Forwarded-For`, `X-Proxy-ID` → upstream no las recibe
- Test: Cabeceras estándar (`Host`, `User-Agent`, `Accept`) preservadas intactas
- Verificación manual: `curl -x gateway -H "Via: test" http://httpbin.org/headers` no muestra cabeceras strippeadas

---

## P2 — STEALTH / COMPATIBILIDAD OB (Ejecutar Segundo)

### P2.1 SOCKS4a Forzado (Zero DNS Leak en SOCKS4)

**Problema:** `socks4Connect` usa IP literal si `net.ParseIP(host) != nil`. Si el host es dominio, hace lookup local → DNS leak.

**Solución:** Forzar SOCKS4a (IP `0.0.0.1` + dominio terminado en `\0`) para **todos** los hosts no-IP.

**Archivo:** `upstream.go` — función `socks4Connect`

**Cambio mínimo:**

```go
// En socks4Connect, reemplazar lógica de IP vs dominio:
ip := net.ParseIP(host)
useSocks4a := ip == nil || ip.To4() == nil // IPv6 o dominio -> SOCKS4a

req := []byte{0x04, 0x01, byte(port >> 8), byte(port & 0xFF)}
if useSocks4a {
    req = append(req, 0x00, 0x00, 0x00, 0x01) // IP 0.0.0.1 = SOCKS4a
} else {
    req = append(req, ip.To4()...)
}
req = append(req, []byte(userid)...)
req = append(req, 0x00)
if useSocks4a {
    req = append(req, []byte(host)...)
    req = append(req, 0x00)
}
```

**Criterios de aceptación:**
- Test: `socks4://host.com:1080` → paquete enviado con `0.0.0.1` + `host.com\0`
- Wireshark/local dump: No hay lookup DNS local antes de conectar al proxy

---

### P2.2 Parser `user-session-country` (Formato OB Nativo)

**Problema:** Configs `.loli`/`.svb` esperan formato `user-session-12345`, `user-rotate`, `user-country-US`.

**Solución:** Extender `ParseProxyDef` para parsear sufijos en el campo `User` y propagar a `Proxy` struct.

**Archivos:**
- `proxy.go` — `ParseProxyDef`, struct `Proxy` (nuevos campos)
- `app.go` — `pick` respeta `StickyKey` si viene en proxy

**Especificación:**

```go
// En proxy.go - extender Proxy struct
type Proxy struct {
    Scheme   string
    Host     string
    Port     int
    User     string
    Password string
    // ... campos existentes ...
    
    // Nuevos para compatibilidad OB:
    StickySession string // "12345" si user=foo-session-12345
    ForceRotate   bool   // true si user=foo-rotate
    CountryFilter string // "US" si user=foo-country-US
}

// En ParseProxyDef, tras extraer user/pass:
func parseUserParams(user string) (cleanUser, sticky, country string, rotate bool) {
    // Formato: user-session-<id> | user-rotate | user-country-<CC>
    parts := strings.Split(user, "-")
    base := parts[0]
    for i := 1; i < len(parts); i++ {
        switch {
        case strings.HasPrefix(parts[i], "session"):
            sticky = strings.TrimPrefix(parts[i], "session")
        case parts[i] == "rotate":
            rotate = true
        case strings.HasPrefix(parts[i], "country"):
            country = strings.ToUpper(strings.TrimPrefix(parts[i], "country"))
        }
    }
    return base, sticky, country, false
}
```

**Integración en `app.go:pick`:**
- Si `p.ForceRotate` → ignorar sesión sticky, `pick()` normal
- Si `p.StickySession != ""` → usar `p.StickySession` como clave de sesión en lugar de `p.Key()`
- Si `p.CountryFilter != ""` → filtrar `aliveIdx` por `massCountries` cache (requiere que checker masivo haya corrido con GeoIP)

**Criterios de aceptación:**
- Test: `user:pass@host:port` con `user=foo-session-123` → misma IP para esa sesión
- Test: `user=foo-rotate` → IP distinta cada petición
- Test: `user=foo-country-US` → solo proxies GeoIP=US (si hay datos)

---

### P2.3 Cabecera `X-Proxy-Rotate: 1` (Rotación Forzada Instantánea)

**Problema:** En OB, si cuenta da `BAN`/`RETRY`, sesión sticky previa queda atascada con IP quemada.

**Solución:** Si request trae `X-Proxy-Rotate: 1`, purgar sesión sticky actual y asignar nueva IP limpia al instante.

**Archivo:** `gateway.go` — `handleConnect` y `handlePlain`

**Implementación:**

```go
// Al inicio de handleConnect y handlePlain:
func (g *Gateway) maybeRotateSession(r *http.Request, session string) {
    if r.Header.Get("X-Proxy-Rotate") == "1" && session != "" {
        g.app.deleteSession(session) // Nueva función en app.go
        r.Header.Del("X-Proxy-Rotate") // Eliminar antes de forward
    }
}

// En app.go:
func (a *App) deleteSession(session string) {
    a.mu.Lock()
    defer a.mu.Unlock()
    delete(a.sessions, session)
}
```

**Criterios de aceptación:**
- Test: Sesión sticky establecida → request con `X-Proxy-Rotate: 1` → siguiente request usa proxy distinto
- Test: Cabecera eliminada del forward al upstream (no llega a internet)

---

### P2.4 Filtros Avanzados en `/proxy.txt` (Auto-Reload OB)

**Problema:** OB usa `proxy.txt` remoto para recarga automática. Filtros actuales limitados.

**Solución:** Extender `api.go:/proxy.txt` con query params: `alive=1`, `max_ping=400`, `country=US`, `proto=socks5`.

**Archivo:** `api.go` — handler `/proxy.txt`

**Parámetros a soportar:**

```go
// En api.go proxyTxtHandler:
aliveOnly := r.URL.Query().Get("alive") == "1"
maxPing, _ := strconv.Atoi(r.URL.Query().Get("max_ping"))
country := strings.ToUpper(r.URL.Query().Get("country"))
proto := strings.ToLower(r.URL.Query().Get("proto"))

// Filtrado en proxiesSnapshot:
list := a.proxiesSnapshot()
filtered := list[:0]
for _, p := range list {
    if aliveOnly && !p.Alive { continue }
    if maxPing > 0 && p.PingMs > maxPing { continue }
    if country != "" && p.Country != country { continue } // Requiere campo Country en Proxy
    if proto != "" && p.Scheme != proto { continue }
    filtered = append(filtered, p)
}
```

**Nota:** Requiere añadir campo `Country string` en `Proxy` struct (llenado por `masscheck.go` al hacer check con GeoIP).

**Criterios de aceptación:**
- `curl "http://gw:8081/proxy.txt?format=ob&alive=1&max_ping=300&proto=socks5"` → solo socks5 vivos <300ms
- OB Proxy Manager puede usar esa URL directamente en "Auto Reload"

---

## P3 — UX / AUTOMATIZACIÓN (Opcional, Bajo Riesgo)

### P3.1 Helper `--tune-tcp` (Afinamiento Windows Automatizado)

**Problema:** Los 3 comandos `netsh/reg` se ejecutan manual. Friction para usuarios.

**Solución:** Flag `--tune-tcp` que detecta si ya aplicado, pide UAC si admin, ejecuta y reporta.

**Archivos:**
- `main.go` — flag + llamada
- `window_windows.go` — nueva función `tuneTCP()` con `runas` verb

**Implementación:**

```go
// En window_windows.go
func tuneTCP() error {
    cmds := [][]string{
        {"netsh", "int", "ipv4", "set", "dynamicport", "tcp", "start=1025", "num=64510"},
        {"reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "/v", "TcpTimedWaitDelay", "/t", "REG_DWORD", "/d", "30", "/f"},
        {"reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "/v", "MaxUserPort", "/t", "REG_DWORD", "/d", "65534", "/f"},
    }
    for _, c := range cmds {
        cmd := exec.Command(c[0], c[1:]...)
        cmd.SysProcAttr = &syscall.SysProcAttr{Verb: "runas"} // UAC prompt
        if err := cmd.Run(); err != nil {
            return fmt.Errorf("%v: %w", c, err)
        }
    }
    return nil
}
```

**Criterios de aceptación:**
- Ejecución sin flag → no hace nada
- Con `--tune-tcp` → pide UAC, aplica, imprime "TCP tuning aplicado (reinicio recomendado)"
- Idempotente: re-ejecutar no rompe nada

---

## Requisitos de Testing Obligatorios

Cada tarea **DEBE** incluir:

1. **Tests unitarios Go** (`*_test.go`) cubriendo:
   - Happy path
   - Edge cases (pool vacío, pool pequeño, timeouts)
   - Concurrencia (`go test -race`)

2. **Tests de integración Python** (`tests/`):
   - `run_tests.py` / `run_deep_tests.py` extendidos con escenarios nuevos
   - Ejemplo: `test_failover_silent.py`, `test_fastest_strategy.py`, `test_header_stripping.py`

3. **Tests UI** (`test_panel_ui.mjs`):
   - Verificar que nuevos flags aparecen en panel
   - Verificar botones/funcionalidad nueva

4. **Batería completa antes de commit:**
```powershell
gofmt -l . ; go vet ./... ; go test -race -count=1 ./...
python tests\run_tests.py
python tests\run_deep_tests.py
python tests\test_sticky_api.py
node tests\test_panel_ui.mjs
```

**Todos deben pasar 100% (0 fallos, 0 races).**

---

## Orden de Ejecución Recomendado

| Semana | Tareas | Entregable |
|---|---|---|
| 1 | P1.1 + P1.3 | Failover silencioso + Header stripping |
| 1-2 | P1.2 | Selector `fastest` |
| 2 | P2.1 + P2.3 | SOCKS4a + X-Proxy-Rotate |
| 2-3 | P2.2 + P2.4 | Parser user-session-country + filtros /proxy.txt |
| 3 | P3.1 | `--tune-tcp` helper |

---

## Checklist de Entrega Final

- [ ] `gofmt -l .` → vacío
- [ ] `go vet ./...` → OK
- [ ] `go test -race ./...` → 0 races, coverage ≥ 60%
- [ ] `python tests/run_tests.py` → 19/19 PASS
- [ ] `python tests/run_deep_tests.py` → 112/112 PASS
- [ ] `python tests/test_sticky_api.py` → 24/24 PASS
- [ ] `node tests/test_panel_ui.mjs` → 273/0 PASS
- [ ] `README.md` actualizado con nuevos flags y ejemplos
- [ ] `CHANGELOG.md` (o sección en README) con fecha y descripción de cada feature
- [ ] Binario `ProxyGateway.exe` recompila limpio
- [ ] Gateway reiniciado en vivo con nueva build, verificado `curl -x 127.0.0.1:823 http://api.ipify.org` y panel 200

---

## Notas para el Agente Implementador

1. **No modificar `RLSettings.json` ni configs de OB** — todo desde gateway.
2. **Preservar credenciales**: `deploy_workflow.js` no aplica aquí (no hay n8n), pero mantener IDs de credenciales en código.
3. **Commits atómicos**: Una feature = un commit con mensaje convencional (`feat: ...`, `fix: ...`).
4. **Tests first**: Escribir test que falle → implementar → test pasa.
5. **Documentar en README** cada flag nuevo con tabla y ejemplo.
6. **Cero dependencias nuevas**: Solo stdlib + `go-webview2` + `golang.org/x/sys` (ya en go.mod).

---

## Contacto / Escalación

- Repo: `https://github.com/luislewiis/ESPECTRO-PROXY-PRO`
- Branch objetivo: `main`
- Auditar: Ejecutar batería completa + revisar diff vs `ad4958b`
- Cualquier duda técnica: revisar `health.go`, `gateway.go`, `app.go` como referencia de patrones usados en el proyecto.

---

**Fin del plan.** El agente implementador debe seguir este orden, pasar la batería completa en cada paso, y notificar al completar cada fase P1/P2/P3 para auditoría posterior.