# ESPECTRO PROXY PRO (ProxyGateway)

**ESPECTRO PROXY PRO** — gateway de rotación de proxies estilo Dataimpulse,
escrito en Go (solo stdlib + go-webview2). Incluye panel WebView2,
health-check periódico, sesiones sticky, estrategias round-robin/random,
API REST y un checker masivo integrado.

## Arranque rápido

```powershell
go build -ldflags "-s -w" -o ProxyGateway.exe .
.\ProxyGateway.exe proxies.txt                 # lista por defecto junto al exe
.\ProxyGateway.exe lista.txt --http-port 8080 --api-port 8081
```

Doble-click sin argumentos: busca `proxies.txt` (o `proxy.txt`, `lista.txt`)
junto al exe, crea plantilla si no existe y abre el panel. En doble-click la
ventana de consola se **cierra del todo** (FreeConsole) si es exclusiva del
proceso: el programa queda solo dentro de la ventana del panel y el veredicto
queda en la pestaña **Log** ("consola propia cerrada"). Con terminal
compartida la consola no se toca y `--console` la mantiene visible.

## Flags

| Flag | Default | Descripción |
|---|---|---|
| `--bind` | `127.0.0.1` | Dirección de escucha (aviso si no es loopback) |
| `--http-port` | `8080` | Puerto del gateway proxy |
| `--api-port` | `8081` | Puerto de la API/panel |
| `--strategy` | `round-robin` | `round-robin` \| `random` \| `sticky` |
| `--check-interval` | `60` | Segundos entre health-checks (0 = off); el primer check espera al intervalo |
| `--check-batch` | `1000` | Proxies chequeados por ciclo de health-check (0 = todos); rota por `LastCheck` (menos recientes primero) |
| `--check-timeout` | `5000` | Timeout en ms por intento de health-check |
| `--check-retries` | `1` | Reintentos extra por proxy antes de darlo por muerto (0 = sin reintentos) |
| `--check-all` | `false` | El auto-check revisa también los muertos verificados (por defecto solo vivos + sin verificar) |
| `--no-state` | `false` | No persistir el estado de analisis (no crea `<lista>.state.json`) |
| `--state-file` | *(auto)* | Ruta del archivo de estado (default: `<lista>.state.json` junto a la primera lista) |
| `--test-url` | `http://api.ipify.org/` | URL de validación |
| `--api-token` | *(vacío)* | Token opcional para endpoints mutantes (header `X-API-Token`) |
| `--allow-any-path` | `false` | Desactiva la jaula de rutas de `/validate` e `/import` |
| `--idle-timeout` | `600` | Watchdog de inactividad en conexiones (0 = off) |
| `--console` | `false` | Mantiene visible la ventana de consola (por defecto se cierra en doble-click) |
| `--version` | | Imprime versión, build y licencia, y sale |
| `--no-browser` / `--window` / `--quiet` / `--check-now` | | UX y utilidades |

## API

- **Lectura (GET)**: `/get?session=X`, `/stats`, `/proxies`, `/logs`, `/proxy.txt`, `/panel`
  - `/proxies?limit=&offset=&sort=ping` (JSON con `checked`, `ping_ms`, `last_check`).
  - `/proxy.txt?sort=ping` exporta los vivos ordenados por latencia.
- **Escritura (POST + cabecera `X-GW-Panel: 1`)**: `/reload`, `/set-strategy?strategy=`, `/check`, `/proxy-remove`, `/proxy-edit`
  - `/check?scope=alive` reanaliza solo vivos + sin verificar; sin parámetro = toda la lista.
  - `/proxy-remove` `{"scope":"dead|alive|all"}` o `{"keys":["scheme|host|port|user", ...]}` →
    `dead`/`alive`/`keys` borran de la lista en memoria **y reescriben los
    `.txt` de origen** (comentarios y líneas vacías se conservan);
    `scope:"all"` (*vaciar todo*) **solo vacía la memoria**: no toca ningún
    `.txt` ni el `state.json`, y `/reload` o un reinicio los vuelven a cargar.
    Respuesta `{"ok","removed","total","files","persist"}` (`persist:false` en `all`).
  - `/proxy-edit` `{"key":"scheme|host|port|user","line":"nueva línea"}` →
    reescribe ese proxy en disco con credenciales completas (`LineaCanon()`);
    conserva su estado si la dirección no cambia y lo resetea si cambia.
    Respuesta `{"ok","key","total"}`.
- **POST + JSON**: `/validate` y `/import` (`{"path":"..."}` o `{"text":"...","name":"..."}`)
  - Rutas limitadas a cwd, directorio del exe y directorios de las listas activas (symlinks/junctions resueltos antes de validar).
- **Checker masivo** (sección "Checker Masivo" del panel):
  - `POST /checker/start` (`X-GW-Panel`): `{"path"|"text", "judge", "country", "geo", "retries", "timeout", "threads", "skip_local"}` — 409 si ya hay un job en marcha.
  - `POST /checker/cancel` · `POST /checker/remove` · `GET /checker/status` · `GET /checker/hits?proto=&limit=`
  - `POST /checker/remove` (`X-GW-Panel`): `{"line":"1.2.3.4:8080"}` · `{"proto":"http|socks4|socks5|all"}` →
    `{"ok", "removed", "remaining"}`. Borra vivos **en memoria**: el contador vivo,
    `/checker/hits`, `/checker/export` y `/checker/countries` se actualizan solos.
    Los `.txt` de la sesión en `Resultados/` **no se reescriben** (quedan como
    registro bruto del run).
  - `GET /checker/export?proto=all|http|socks4|socks5&format=full|plain` · `GET /checker/countries` · `GET /checker/report`
  - Salidas en `Resultados/[dd.mm.yy] [hh.mm.ss]/`: `Live_HTTP.txt`, `Live_SOCKS4.txt`, `Live_SOCKS5.txt`, `Paises Validados/<pais>.txt` (con geo) y `Report.json`.
- Si `--api-token` está configurado, los endpoints de escritura exigen `X-API-Token`,
  y las lecturas sensibles (`/proxies`, `/logs`, `/proxy.txt`, `/checker/hits`,
  `/checker/export`, `/checker/report`) también (401); 10 fallos de token
  desde una IP → 429 durante 2 min (`authLimiter`).

## Formatos de línea soportados

```
1.2.3.4:8080
usuario:clave@1.2.3.4:8080
socks5://1.2.3.4:1080
0:1.2.3.4:8080::          # formato OB: tipo:host:puerto:user:pass
```

El nombre del archivo infiere el esquema (`socks5_x.txt` → socks5).

## Licencia (doble)

- **Comunidad (GPLv3)**: el fuente se usa, copia y modifica bajo los
  términos de `LICENSE` (GNU GPL v3). Para uso comercial integrado/cerrado,
  adquiere la **licencia comercial**.
- **Pro (binario con `espectro.lic`)**: licencia firmada con
  **Ed25519** y **cifrada AES-256-GCM con clave de la máquina**
  (MachineGuid de Windows): es ilegible, no transferible y no puede
  fabricarse sin la clave privada del emisor. Vive en `internal/lic`.
- **Modo Demo (sin licencia)**: todo funciona (gateway, panel,
  health-check, sticky, API), excepto: el **checker masivo** limitado a
  **2000 líneas por job** y las **notificaciones a Discord** desactivadas.
  Coloca `espectro.lic` junto al exe (y **reinicia** el programa) para
  pasar a Pro.
- Emisión de licencias (solo el vendedor): `lictool/` —
  `go build -o lictool.exe ./lictool`; la clave privada queda en
  `licencias/priv.key` (**gitignored**, jamás se reparte). El cliente
  manda su id con `lictool machine`; se emite con `lictool issue`.
- Release ofuscado (opcional): `.\build_release.ps1 -Version 1.0.0`
  (usa [garble](https://github.com/burrowers/garble) si está instalado;
  descarga solo el SDK de Go a `%USERPROFILE%\sdk` si garble lo necesita).

## Tests

```powershell
gofmt -l . ; go vet . ; go test -count=1 . ./internal/... ; go test -race -count=1 . ./internal/...   # 88+9 tests, coverage 60.1% (lic 71.4%)
go test -run "^$" -bench . -benchmem
go test -fuzz=FuzzReadHead -fuzztime=15s . ; go test -fuzz=FuzzUnseal -fuzztime=15s ./internal/lic   # fuzz (4 targets)
python tests\run_tests.py        # suite funcional (19)
python tests\test_sticky_api.py  # sesiones/API (25)
python tests\run_deep_tests.py   # suite profunda (105: S1-S14)
node tests\test_panel_ui.mjs     # suite UI boton a boton (266: vm + Chrome headless)
```

## Decisiones de diseño

- **Cola híbrida / API**: la API no comparte lock con el relay de peticiones;
  índices `byKey`/`aliveIdx` dan `pick` y `counts` en O(1).
- **ARQ-01**: solo los fallos de transporte contra el proxy (`upstreamError`)
  cuentan para `markFail`; respuestas del proxy ante destino caído no matan el pool.
- **RED-01**: `--idle-timeout` refresca deadlines en cada Read/Write de túnel.
- **Sesiones**: mapa `session → clave Key()` con TTL 10 min y cap 10k;
  sobreviven a `/reload`; se limpian al marcar el proxy muerto.
- **Ventana WebView2 con perfil por instancia**: cada proceso usa su propio
  `%TEMP%\gw_webview\<pid>` (se borra al cerrar la ventana). Con el perfil por
  defecto (`%APPDATA%\<nombre-del-exe>`) una segunda instancia que abre
  `--window` mientras otra tiene la ventana viva se congela sin bombear
  mensajes; el panel no guarda nada en el perfil, asi que no se pierde estado.
- **Banner dentro del programa**: la info de arranque (marca, endpoints,
  estrategia, health-check y archivo de estado) ya no se imprime en la
  consola: vive en la seccion **Info de arranque** del panel y en la pagina
  `/` (la consola solo emite eventos y una linea con la URL del panel).
- **Arranque sin saturar**: el primer health-check espera al `--check-interval`
  (antes se disparaba al arrancar y ralentizaba la máquina con listas grandes);
  el log de detalle se limita a 5 `muerto:`/`revivido:` por pasada y el resto
  va en un solo resumen.
- **Health-check por lotes con rotación por `LastCheck`**: en vez de chequear
  TODA la lista cada ciclo (24k proxies = ~50 min de trabajo continuo que
  saturaba red/sockets), cada ciclo chequea `--check-batch` proxies (1000).
  Los candidatos se ordenan por `LastCheck` ascendente (los nunca verificados
  primero, luego los menos recientemente revisados): la rotación es
  "self-service" y un reinicio CONTINÚA el escaneo donde quedó. Con 24k
  proxies se chequea todo en ~24 ciclos (~24 min) y el gateway respira
  entre ciclos.
- **Auto-check selectivo**: el loop automático solo revisa **vivos + sin
  verificar** (`Checked=false`); los muertos verificados no se re-analizan
  solos (se reviven con "Check ahora" / `POST /check` / `--check-all`).
  `--check-retries 1` (default) da un segundo intento antes de marcar
  muerto (evita muertes por golpe de red) y cada check registra **ping
  (ms)** por proxy (TTFB hasta la línea de estado).
- **Estado persistente**: cada lista guarda `alive/fails/checked/ping_ms/
  last_check` en `<lista>.state.json` (atómico, guardado diferido 1.5s y al
  salir). Un reinicio o un `/reload` NO re-analiza desde cero: los muertos
  siguen muertos, los vivos siguen vivos y los importados nuevos se
  verifican como "SIN VERIFICAR". `--no-state` lo desactiva.
- **Consola cerrada en doble-click (FreeConsole)**: con `--window` y consola
  exclusiva (`GetConsoleProcessList == 1`) la consola se ELIMINA al crearse
  la ventana: no queda pestaña ni ventana de terminal y el programa vive solo
  dentro del panel. El veredicto se registra en el Log del panel
  ("consola propia cerrada" / "consola no cerrada (procesos en la terminal:
  N)"); una terminal compartida nunca se cierra ni se oculta. `--console`,
  `--no-browser` y `--check-now` la mantienen visible y los errores la
  restauran en `pausaSiConsola`.
- **Panel paginado**: `/proxies?limit=200&offset=N` evita serializar 24k
  proxies (varios MB) cada 4s, que congelaba la UI. El panel muestra páginas
  de 200 con botones ←/→ y refresca la tabla cada 15s (stats/logs cada 4s).
- **Checker masivo integrado** (fusión EspectroProxy → ESPECTRO PROXY PRO, `masscheck.go`):
  valida listas/carpeta sin tocar la lista del gateway. Línea sin esquema →
  cascada SOCKS5 → SOCKS4 → HTTP; con esquema (`socks5://`, `2:host:puerto`)
  se respeta solo ese. Timeout dinámico por ping al juez (2.5/4/6s, 5s si el
  juez cae; `timeout` fijo lo anula), reintentos 0-5 y autopilot
  `NumCPU*250`. Juez custom con prioridad sobre
  ip-api.com (`geo`/`country`), filtro de país y anonimato estilo azenv;
  filtro de locales (127./192.168./10./localhost) activo por defecto.
  Discord opcional leyendo `webhook.txt` del cwd. Un solo job a la vez (409).
  Autopilot `NumCPU*250` con **cap de 4000 hilos** (antes 15000: desde el
  panel se podía auto-DoSar la máquina).
- **Gestor de proxies en la tabla**: cada fila de la tabla de proxies tiene
  `✎` (editar esa línea) y `×` (borrarla) y, sobre la cabecera, *borrar
  muertos* / *borrar vivos* / *vaciar todo* (scopes `dead|alive|all` de
  `/proxy-remove`). El `×`, *borrar muertos* y *borrar vivos* persisten en
  los `.txt` de origen (el reescritor conserva comentarios y orden, y la
  línea se guarda con esquema y credenciales completos); *vaciar todo*
  **solo vacía la lista en memoria** —los `.txt` fuente no se tocan y
  `/reload` o un reinicio los restauran tal cual—.
- **Borrado de resultados (panel)**: en el input "Pegar listas" hay
  *Borrar línea* (línea del cursor, `Ctrl+Del` vía teclado), *Borrar
  HTTP/SOCKS4/SOCKS5* (solo líneas con esquema explícito `http://`,
  `socks4(a)://`, `socks5://` — las `ip:port` sueltas no se pueden clasificar
  hasta comprobarse y se conservan con aviso), *Vaciar todo* y *Vaciar
  archivos*. En la tabla de vivos: filtro por protocolo, casilla de
  selección, `×` por fila, *borrar selección* y *vaciar vivos*. Todo pasa
  por `POST /checker/remove` salvo el input, que se edita en el cliente.
- **Endurecimiento de auditoría (01/10/2026)**: `readCappedLine` acota las
  líneas de la fase de cuerpo (tamaño de chunk y trailers) y las cabeceras
  de respuesta del health-check —una línea sin `\n` inflaba `bufio` sin
  límite (DoS de memoria; `readHead` ya tenía `byteCap` pero el cuerpo se
  leía con cap desactivado)—; `ServeGateway` solo termina con
  `net.ErrClosed` (un error transitorio de `Accept` ya no tumba el
  gateway); `massStart` hace el chequeo de "job en curso" y el alta en una
  sola sección crítica (dos `/checker/start` concurrentes podían crear 2
  jobs). Tests: `audit_deep_test.go` (15) + bloque S14 del deep (9).
- **Auditoría fase 2 / fuzzing (02/10/2026)**: `fuzz_test.go` fuzzea las
  tres puertas de datos no confiables (parser de proxies, cabeceras y
  cuerpo del gateway) con invariante de "nunca panica / nunca supera
  `bodyCap`". El fuzz encontró dos cosas y quedaron corregidas:
  `readHead` aceptaba cabeceras con `field-name` vacío (`  ::` → `h[""]`,
  que el upstream recibiría como `": v"`; ahora responde 400) y
  `main_test.go` dejaba `os.Args[0]` pisado a `"exe"`, con lo que el
  coordinator de `go test -fuzz` no podía re-spawnear workers
  (`exec: "exe": not found`); el crasher quedó como seed de regresión
  en `testdata/fuzz/FuzzReadHead/`.
- **Token en lecturas + rate-limit (02/10/2026)**: con `--api-token`, las
  lecturas `/proxies`, `/proxy.txt` (incluido `format=ob`, con credenciales),
  `/checker/hits` y `/checker/export` exigen el token (401) —antes solo los
  POST mutantes lo hacían—; el panel lo manda por cabecera (`jget`) y por
  `?token=` en los enlaces de descarga (`<a href>`). Además `authLimiter`
  cuenta los fallos de token por IP: 10 en 10 min → 429 durante 2 min
  (fuerza bruta) y un acierto válido limpia el historial. Sin `--api-token`
  nada cambia (modo local por defecto). **Fix relacionado**: el servidor
  inyectaba el token con `strings.ReplaceAll`, que también sustituía el
  literal `'__GW_TOKEN__'` del guard JS de `gwToken` (la comparación
  quedaba `!== '<token>'` y el panel nunca mandaba el token, ni siquiera
   en los POSTs); ahora es `strings.Replace` n=1 sobre la meta.
   Tests: `auth_ratelimit_test.go` (4).
- **Auditoría exhaustiva + hardening (03/10/2026)**: auditoría integral
  (funciones, botones, UI, seguridad, privacidad) + Snyk SAST/SCA. Fixes:
  health-check usa `u.Host` en las cabeceras `Host` (respeta el puerto);
  `MaxHeaderBytes` 64 KB en el servidor API; apagado ordenado
  (SIGINT/SIGTERM → `Shutdown` de la API + cierre del listener + defers);
  `prepareOut` cierra los ficheros ya abiertos si el resto falla (sin
  FDs huérfanos); cap de hilos del checker 15000→4000; CSP +
  `X-Frame-Options: DENY` + `Referrer-Policy` en `/` y `/panel` (cierra
  clickjacking; `frame-ancestors 'none'` y `object-src 'none'`), con
  `bind` y `gatewayBase` escapados en el HTML del índice; `/logs` y
  `/checker/report` exigen token (antes `/logs` filtraba los `p.Tag` de
  credenciales con el token puesto); el panel avisa de 401 ("token
  invalido") en la tabla y en la pill de estado en vez de quedarse
  cargando, y `esc()` ahora también escapa comillas simples; el `<a>` de
  descargas cubre también `/checker/report`. **Salvavidas Ctrl+C**
  (herencia EspectroProxy): con un checker en marcha, la señal cancela el
  job y espera a `finish()` (flush de buffers + `Report.json`) antes de
  salir. **Panic recovery en main** (herencia Security Shield V3): mensaje
  + stack en stderr y consola pausada (doble-click no pierde el error).
  Toolchain **Go 1.26.6 + x/sys v0.44.0** (CVEs de stdlib corregidos;
  Snyk SCA 5→0) y `.snyk` con los FPs documentados. Tests:
  `TestCSPIndiceYPanel`, `TestIndiceEscapaBind`, `TestMassShutdownSalvavidas`
  (81 en total, coverage 59.5%).
- **Licencias + release ofuscado (03/10/2026)**: sistema de licencia dual
  (ver *Licencia (doble)*), flag `--version` con metadata por ldflags,
  toolchain **Go 1.27.1** + x/sys v0.44.0 (Snyk SCA 0), garble 0.18 con
  SDK per-user en `%USERPROFILE%\sdk` (Go prohíbe parchear el linker del
  toolchain en GOMODCACHE), fuzz `FuzzUnseal` (4,3 M execs sin panic),
  clave privada verificada ausente del binario, archivos de comunidad
  (`LICENSE` GPLv3, `SECURITY.md`, `.gitignore`, CI) y `.snyk` con los
  FPs ampliados. Tests: **88+9**, coverage 60.1% (lic 71.4%); batería
  completa en verde sobre el binario ofuscado (19 + 105 + 25 + 266).

## Estructura

```
main.go        flags, arranque, bind warning
app.go         App, pick/sesiones, índices, markFail/markOK
gateway.go     relay CONNECT/plain, túneles, watchdog idle
upstream.go    dial a proxies HTTP/SOCKS + taxonomía de errores
health.go      health-check periódico (scope, ping, reintentos)
masscheck.go   checker masivo (cascada, geo, país, discord, /checker/*)
state.go       estado persistente <lista>.state.json
api.go         endpoints REST + panel embebido
import.go      /validate, /import, jaula de rutas
proxy.go       parseo de líneas y formatos de salida
licensing.go   licencias (modo demo/Pro, tope del checker, --version)
internal/lic/  formato de licencia (Ed25519 + AES-GCM por máquina)
lictool/       emisión de licencias (clave privada; uso del vendedor)
panel.html     panel (embed)
legacy/        prototipo Python original (referencia)
tests/         suites Python (19 + 25 + 105) + test_panel_ui.mjs (266, Node)
build_release.ps1  build de release (garble si está instalado)
```
