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
| `--http-port` | `8080` | Puerto del gateway proxy. **Acepta varios separados por comas** (`8082,823,8084`): el mismo gateway se sirve en todos a la vez, como DataImpulse (80/8080/823) |
| `--api-port` | `8081` | Puerto de la API/panel |
| `--auto-port` | `true` | Si un puerto está ocupado, usa el siguiente libre y avisa (log + notificación flotante con Continuar/Copiar/Cerrar en Windows). `--auto-port=false` → error clásico y sale |
| `--no-notify` | `false` | No mostrar la notificación flotante al cambiar de puerto (tests/automatización) |
| `--strategy` | `round-robin` | `round-robin` \| `random` \| `sticky` \| `fastest` (Top 25% menor latencia) |
| `--check-interval` | `60` | Segundos entre health-checks (0 = off); el primer check espera al intervalo |
| `--check-batch` | `1000` | Proxies chequeados por ciclo de health-check (0 = todos); rota por `LastCheck` (menos recientes primero) |
| `--check-timeout` | `5000` | Timeout en ms por intento de health-check |
| `--check-retries` | `1` | Reintentos extra por proxy antes de darlo por muerto (0 = sin reintentos) |
| `--check-connect` | `false` | El health-check usa CONNECT (tunel) en vez de GET: detecta proxies que pasan el check pero no tunelizan (502 en CONNECT) |
| `--check-all` | `false` | El auto-check revisa también los muertos verificados (por defecto solo vivos + sin verificar) |
| `--no-cooldown` | `false` | Desactiva el enfriamiento de proxies fallados en la rotación (diagnóstico/A-B: cada proxy que falla se aparta 45s) |
| `--no-state` | `false` | No persistir el estado de analisis (no crea `<lista>.state.json`) |
| `--state-file` | *(auto)* | Ruta del archivo de estado (default: `<lista>.state.json` junto a la primera lista) |
| `--test-url` | `http://api.ipify.org/` | URL de validación |
| `--api-token` | *(vacío)* | Token opcional para endpoints mutantes (header `X-API-Token`) |
| `--allow-any-path` | `false` | Desactiva la jaula de rutas de `/validate` e `/import` |
| `--idle-timeout` | `600` | Watchdog de inactividad en conexiones (0 = off) |
| `--tune-tcp` | `false` | Afina el stack TCP de Windows (puertos dinámicos a 64k y TimedWaitDelay 30s) para alta concurrencia (300+ bots) y sale |
| `--harvest` | `false` | **Auto-Fuentes**: recolecta proxies de ~50 fuentes públicas en bucle y descubre fuentes nuevas solo (ver más abajo) |
| `--harvest-interval` | `15` | Minutos entre pasadas del Auto-Fuentes |
| `--harvest-out` | `harvested.txt` | Archivo **propio** del Auto-Fuentes (nunca toca `proxies.txt`) |
| `--harvest-max-lines` | `120000` | Tope de líneas del archivo recolectado (0 = sin tope). 480k líneas ≈ 700 MB de RAM; 120k ≈ 220 MB |
| `--harvest-defer` | `false` | No recolectar al arrancar: esperar al primer intervalo |
| `--no-harvest-check` | `false` | No validar lo recién recolectado (queda para el health-check normal) |
| `--console` | `false` | Mantiene visible la ventana de consola (por defecto se cierra en doble-click) |
| `--version` | | Imprime versión, build y licencia, y sale |
| `--no-browser` / `--window` / `--quiet` / `--check-now` | | UX y utilidades |

## Compatibilidad con checkers de proxy y herramientas de automatización (OpenBullet, SilverBullet, OBM)

El gateway es un **endpoint proxy universal**: habla proxy-HTTP estándar hacia
el cliente (con `Proxy-Authorization` para sesiones) y por dentro saca el
tráfico por los proxies reales del pool (socks4/socks4a/socks5/http), igual que hace
DataImpulse o BrightData.

### Características de alto rendimiento para bots:
- **Failover silencioso automático:** Si un proxy falla durante peticiones plain GET/POST, el gateway reintenta automáticamente con el siguiente proxy en milisegundos sin devolver errores `502` a OpenBullet.
- **Header Stripping Anti-Detección (Stealth):** Elimina automáticamente cabeceras que delatan proxies intermediarios (`Via`, `X-Forwarded-For`, `X-Real-IP`, `X-Gateway-*`, etc.) hacia el servidor de destino y hacia el cliente.
- **SOCKS4a Zero DNS Leak:** Todas las conexiones SOCKS4 hacia nombres de dominio se envían en formato SOCKS4a para que el proxy remoto resuelva el DNS de forma privada.
- **Estrategia `fastest`:** Filtra dinámicamente el 25% de proxies con menor latencia ping para disparar el CPM (+30-40%).
- **Rotación instantánea con `X-Proxy-Rotate: 1`:** Si OpenBullet detecta un BAN o captcha, enviar esta cabecera invalida la sesión sticky y asigna una nueva IP al instante.

Línea de proxy para pegar en OB M2 / SilverBullet (una sola):

| Pegas | Resultado |
|---|---|
| `127.0.0.1:8082` | Rota la IP en cada petición (como DataImpulse por defecto) |
| `127.0.0.1:8082:user-session-123:clave` | IP fija para esa sesión sticky |
| `127.0.0.1:8082:user-country-US:clave` | Rota únicamente entre proxies del país indicado (ej. US) |
| `127.0.0.1:8082:user-session-123-country-DE:clave` | Sesión sticky fijada a un proxy del país solicitado (ej. DE) |
| `127.0.0.1:8082:user-rotate:clave` | Fuerza una nueva rotación de IP en cada request |

Con `--http-port 8082,823` esos mismos proxies valen por **cualquiera** de los
puertos (los checkers nunca marcan ninguno como muerto).

## Auto-Fuentes (`--harvest`): recolección continua sin intervención

El gateway deja de depender de que tú pegues listas: recolecta solo, cada
`--harvest-interval` minutos, de un catálogo curado de **~50 fuentes públicas
verificadas en vivo** (TheSpeedX, monosans, proxifly, ErcinDedeoglu, MuRongPIG,
hookzof, spys.me, ProxyScrape v4…), **descubre fuentes nuevas** leyendo los
catálogos de *otros* scrapers (meta-harvesting) y las prueba antes de aceptarlas.

```powershell
.\ProxyGateway.exe --harvest --harvest-interval 15 --strategy fastest --check-connect
```

### Qué hace cada ciclo

1. **Recolecta** las fuentes habilitadas en paralelo (24 descargas simultáneas).
2. **Extrae** `IP:PUERTO` con regex y **descarta basura**: privadas, loopback,
   link-local, CGNAT (100.64/10), documentación (192.0.2/24, 203.0.113/24),
   reservadas (240/4) y `0.0.0.0/8` (el relleno típico de las listas gratis).
3. **Deduplica** contra el pool existente (por protocolo + host + puerto).
4. **Escribe solo lo nuevo** en su archivo propio (`harvested.txt`), nunca en
   `proxies.txt`.
5. **Drena un health-check** de lo recién llegado (300 workers, `--check-connect`
   por defecto con el flag puesto): promoted al pool **solo si tuneliza**.

### Política "solo vivo y filtrado"

Lo recolectado entra al pool como **no vivo y sin verificar**, así que
`/proxy.txt?alive=1` — lo que come OB — **jamás** entrega un proxy sin validar.
Esto es lo que evita las "pausas": la basura de las listas gratis (≈98% muerta)
nunca llega a tus bots.

### Números reales medidos (16/10/2026, esta máquina)

| Métrica | Valor |
|---|---|
| Fuentes builtin OK | **51/51** (0 fallidas) |
| Líneas crudas por pasada | ~808.000 |
| Únicos por protocolo+host:puerto | ~806.000 |
| **Únicos reales `IP:PUERTO`** | **~210.000** (el resto son duplicados entre fuentes) |
| Puerto TCP abierto (muestra aleatoria de 400) | 33% |
| **Que tunelizan de verdad** | **~1–2%** |
| Tope por defecto (`--harvest-max-lines 120000`) → vivos | ~1.000–2.500 |
| Memoria con 123.000 proxies | ~220 MB |

> **Ojo con el "millón de proxies"**: el ecosistema *gratuito* mundial tiene
> ~200–800 k entradas en cualquier instante y solo el 1–3% funciona. Para
> **millones de IPs limpias** la vía es tu proveedor rotativo (DataImpulse); el
> pool gratis es para volumen barato y para no depender de nadie. Si aun así
> quieres todo lo que hay: `--harvest-max-lines 0` (asume ~700 MB+ de RAM).

### Auto-descubrimiento de fuentes (meta-harvesting)

`Descubrir fuentes nuevas` en el panel lee los **catálogos de fuentes** de otros
proyectos scrapers (`config.toml` de monosans, `Sources.txt` de
sascha/Zeiger, `sources.txt` de Thordata, READMEs de proxifly/TheSpeedX) y
extrae las URLs de listas. Cada candidata se **prueba en vivo**: solo se agrega
si entrega ≥5 `IP:PUERTO`. Es la forma de pasar de 50 → cientos de fuentes sin
adivinar. Si defines `GITHUB_TOKEN` (o `GH_TOKEN`) en el entorno, además usa la
API de **GitHub Code Search** para encontrar listas recién publicadas.

### Endpoints

| Endpoint | Método | Qué hace |
|---|---|---|
| `/harvest/status` | GET | Estado + contadores (fuentes, crudas, únicas, nuevas, vivos, pool) |
| `/harvest/sources` | GET | Lista de fuentes (nombre, URL, proto, origen, activa/pausada) |
| `/harvest/run` | POST | Fuerza una pasada ahora |
| `/harvest/discover` | POST | Busca y prueba fuentes nuevas |
| `/harvest/purge` | POST | Borra del archivo recolectado los muertos ya verificados |
| `/harvest/source` | POST | Agrega/edita/pausa una fuente propia (`{name,url,proto,enabled}`) |
| `/harvest/source/remove` | POST | Quita una fuente (`{url}`) |
| `/harvest/export` | GET | Descarga el `harvested.txt` |

Mutantes: `POST` + cabecera `X-GW-Panel` (+ `X-API-Token` si está puesto).
Lecturas: token solo si `--api-token` está configurado. Las descargas pasan por
una **guarda SSRF** (solo `http`/`https`, hosts loopback/privados bloqueados,
tope de 24 MB por descarga).

## API

- **Lectura (GET)**: `/get?session=X`, `/stats`, `/proxies`, `/logs`, `/proxy.txt`, `/panel`
  - `/proxies?limit=&offset=&sort=ping` (JSON con `checked`, `ping_ms`, `last_check`).
  - `/proxy.txt` exporta la lista de proxies con soporte de filtros:
    - `?alive=1`: Solo proxies actualmente vivos.
    - `?country=US`: Solo proxies de un país específico.
    - `?max_ping=400`: Solo proxies con latencia $\le$ 400 ms.
    - `?scheme=socks5` (o `?proto=socks5`): Solo proxies con ese protocolo.
    - `?sort=ping`: Ordena por menor latencia primero.
    - `?format=ob`: Formato nativo OpenBullet (`tipo:host:puerto:user:pass`).
    - `?format=full`: Formato URI completo (`scheme://host:port`).
    - `?format=plain`: Formato clásico `host:puerto` (default).
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
- **Auto-Fuentes** (sección "Auto-Fuentes" del panel): `/harvest/status`,
  `/harvest/sources`, `/harvest/run`, `/harvest/discover`, `/harvest/purge`,
  `/harvest/source`, `/harvest/source/remove`, `/harvest/export`
  (detalle arriba; mutantes con `X-GW-Panel`).
- Si `--api-token` está configurado, los endpoints de escritura exigen `X-API-Token`,
  y las lecturas sensibles (`/proxies`, `/logs`, `/proxy.txt`, `/checker/status`,
  `/checker/hits`, `/checker/export`, `/checker/report`) también (401); 10 fallos de token
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
gofmt -l . ; go vet . ; go test -count=1 . ./internal/... ; go test -race -count=1 . ./internal/...   # 129+9 tests, coverage 64.9% (lic 71.4%)
go test -run "^$" -bench . -benchmem
go test -fuzz=FuzzReadHead -fuzztime=15s . ; go test -fuzz=FuzzUnseal -fuzztime=15s ./internal/lic   # fuzz (4 targets)
python tests\run_tests.py        # suite funcional (19)
python tests\test_sticky_api.py  # sesiones/API (25)
python tests\run_deep_tests.py   # suite profunda (112: S1-S14)
node tests\test_panel_ui.mjs     # suite UI boton a boton (300: vm + 2x Chrome headless)
```

## Decisiones de diseño

- **Cola híbrida / API**: la API no comparte lock con el relay de peticiones;
  índices `byKey`/`aliveIdx` dan `pick` y `counts` en O(1).
- **ARQ-01**: solo los fallos atribuibles al PROXY cuentan para `markFail`:
  transporte/dial contra el proxy, autenticación, `CONNECT` HTTP con status
  != 200 (un 502/503/504 significa que el proxy **no tuneliza**) y SOCKS con
  REP de culpa del proxy (socks5 `01/02/07/08`, socks4 `5C/5D`). Los rechazos
  de destino (socks5 `03-06`, socks4 `5B`, respuestas ante web caída) no
  matan el pool. Evidencia: A/B bajo carga 12/10/2026 (los proxies con 502
  eterno no morían jamás y la rotación los reelegía sin fin → p90 6,3s →
  3,6s tras el cambio).
- **Enfriamiento (12/10/2026)**: `markFail` aparta al proxy de la rotación
  45s (`enfriamientoS`) para no pagar su timeout en cada petición;
  `markOK` lo readmite ya; pools < 8 vivos no se enfrían (se prueban
  todos); purga al superar 512 entradas; `--no-cooldown` lo desactiva.
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
  FPs ampliados. Tests: **115+9**, coverage 65.7% (lic 71.4%); batería
  completa en verde sobre el binario ofuscado (19 + 112 + 25 + 273 + 5 ob_optim).
- **Optimización de rendimiento + fix de "pausas" de OB (12/10/2026)**:
  cache de `http.Transport` por upstream (keep-alive reutilizado, TTL 90s
  + sweeper; relay ~200µs/op en micro-benchmark), buffers de 64 KB con
  `sync.Pool` en los túneles, `dialUpTimeout` 4s (antes 10s, los muertos
  se descartan 2.5× más rápido) y `ResponseHeaderTimeout` 10s. Fix raíz
  de las pausas (A/B bajo carga con dos gateways, misma lista): un
  `CONNECT` que devuelve 502/503/504 (proxy que pasa el health-check —
  cualquier respuesta HTTP vale— pero no tuneliza) ahora cuenta como
  fallo del proxy y activa el **enfriamiento** de 45 s; antes no contaba,
  la rotación lo reelegía sin fin y cada bot pagaba 4 reintentos × 4 s.
  Medición: p90 6,3 s → 3,6 s (−43%). Asimetría SOCKS corregida en la
  misma pass: REP socks5 `01/02/07/08` y socks4 `5C/5D` también cuentan
  como fallo del proxy. `/checker/countries` ahora exige token. Tests:
  `transport_test.go`, `enfriar_test.go`, `TestCONNECT502MarcaUpstream`,
  `TestSocks5REP*` y `TestSocks4RepIdentd*`.
- **Health-check CONNECT (12/10/2026 — pass 2)**: flag `--check-connect`
  para que el health-check valide con `CONNECT` (túnel) en vez de `GET`.
  Detecta y mata preventivamente los proxies que pasan el GET del check
  pero devuelven 502 en CONNECT (lo que usa OB M2). Sin esto, esos proxies
  se colaban en el pool "vivo" y solo morían en el relay (reintentos +
  enfriamiento 45s); con `--check-connect` el auto-check los detecta en
  la validación periódica. Tests: `health_test.go` (cobertura nueva).
- **Blindaje OBM / SilverBullet (13/10/2026)**: suite completa para cero
  retries en OpenBullet Multi / SilverBullet:
  - **Failover silencioso en peticiones plain (`handlePlain`):** reintenta
    hasta 4 proxies tras fallos upstream sin devolver 502 a OBM (`TestFailoverSilentPlain`).
  - **TLS pipelined handshake (ClientHello coalescido):** propaga `bufio.Reader`
    con bytes ya leídos al upstream para que el handshake TLS no se bloquee
    (`TestConnectPipelinedTLS`).
  - **TCP Half-Close / CloseWrite:** soporta desconexión asimétrica limpia
    sin cortar la respuesta del servidor en medio (`TestTunnelHalfCloseClient`).
  - **Estrategia `fastest` (Top 25% ping):** selecciona dinámicamente los proxies
    con menor latencia, disparando CPM (+30-40%).
  - **Header Stripping Stealth:** elimina `Via`, `X-Forwarded-For`, `X-Real-IP`,
    `X-Gateway-*`, `Forwarded`, etc. en request y response.
  - **SOCKS4a Zero DNS Leak:** todas las conexiones SOCKS4 a dominios usan
    formato SOCKS4a (el proxy remoto resuelve DNS).
  - **Parser `user-session-country`:** formato nativo OB (`user-session-123`,
    `user-rotate`, `user-country-US`, combinaciones).
  - **Rotación forzada `X-Proxy-Rotate: 1` + `user-rotate`:** invalida sesión
    sticky y asigna IP limpia al instante.
  - **Filtros avanzados `/proxy.txt`**: `?alive=1&country=US&max_ping=300&proto=socks5&sort=ping`.
  - **`--tune-tcp` UAC auto:** afinamiento Windows (puertos 64k, TIME_WAIT 30s)
    con elevación automática `runas`.
  Tests: `ob_optim_test.go` (5 tests nuevos) + batería completa 430/430 PASS,
  0 races, coverage 65.7%.
- **Auto-Fuentes (`--harvest`) — recolección continua (16/10/2026)**: el
  gateway deja de depender de listas pegadas a mano. `harvest.go` recolecta un
  catálogo curado de **51 fuentes públicas verificadas en vivo** (0 fallidas),
  extrae `IP:PUERTO` con regex, filtra basura (privadas, loopback, link-local,
  CGNAT, documentación, reservadas, `0.0.0.0/8`), deduplica por protocolo y
  escribe **solo lo nuevo** en su archivo propio (`harvested.txt`): **nunca**
  toca `proxies.txt`. Lo recolectado entra al pool como **no vivo y sin
  verificar** (política "solo vivo y filtrado"), de modo que
  `/proxy.txt?alive=1` — lo que come OB — jamás entrega un proxy sin validar;
  el **drenaje** (300 workers) lo promueve solo si tuneliza.
  - **Auto-descubrimiento (meta-harvesting)**: `Discover()` lee los catálogos
    de fuentes de otros scrapers (monosans `config.toml`, `Sources.txt` de
    sascha/Zeiger, `sources.txt` de Thordata, READMEs) + GitHub Code Search
    (con `GITHUB_TOKEN`), y **prueba en vivo** cada candidata: solo se agrega
    si entrega ≥5 `IP:PUERTO`.
  - **Guarda SSRF**: solo `http`/`https`, hosts loopback/privados/link-local
    bloqueados (comprobando el DNS resuelto), tope de 24 MB por descarga.
  - **Tope de memoria** `--harvest-max-lines` (120k por defecto): 480k líneas
    costaban **712 MB** de RAM; con el tope, 123k proxies quedan en **222 MB**.
  - **Purga** de muertos ya verificados (`/harvest/purge`) para mantener el
    pool limpio y liberar el tope.
  - Endpoints `/harvest/status|sources|run|discover|purge|source|export` +
    sección nueva en el panel (contadores, tabla de fuentes, pausar/activar,
    filtro, añadir fuente propia).
  - Medición real: 808k crudas → 806k únicas por protocolo → **210k únicas
    `IP:PUERTO`** → **1-2% tuneliza** (444 vivos validados en una pasada de
    180 s). Dato de contexto: el "806.121 proxies" que circula son
    **duplicados**; al deduplicar queda ~1/4.
  - Tests: `harvest_test.go` (10 tests: extracción/filtros, guarda SSRF,
    persistencia y merge de fuentes, descubrimiento, tope de líneas,
    demote de recién llegados, purga) + fase C de la suite UI (24 tests).
    Batería: **19 + 112 + 25 + 300 + 178** (Go) PASS, 0 races,
    coverage 64.9% (lic 71.4%).

## Estructura

```
main.go        flags, arranque, bind warning
app.go         App, pick/sesiones, índices, markFail/markOK
gateway.go     relay CONNECT/plain, túneles, watchdog idle
upstream.go    dial a proxies HTTP/SOCKS + taxonomía de errores
health.go      health-check periódico (scope, ping, reintentos)
harvest.go     Auto-Fuentes: recoleccion + descubrimiento de fuentes
harvest_api.go endpoints /harvest/*
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
tests/         suites Python (19 + 25 + 112) + test_panel_ui.mjs (300, Node)
build_release.ps1  build de release (garble si está instalado)
```
