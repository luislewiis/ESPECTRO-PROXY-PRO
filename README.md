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

### Scripts de producción (Windows)

| Script | Qué hace |
|---|---|
| `iniciar.cmd` | Doble-click = producción: proxy en **8082 y 823**, panel/API en **8081**, `--check-connect` (validación por túnel, la que necesita OB), health-check cada 60 s. Además ofrece el afinado de TCP si aún no está aplicado (pide admin) |
| `parar.cmd` | Cierra el gateway por PID (no por nombre) y deja libres 8081/8082/823 |
| `tunar-tcp.cmd` | Aplica **una vez** el afinado del stack TCP de Windows (64k puertos de usar y tirar + `TIME_WAIT` 30 s). Afecta a todo Windows; hace falta administrador |

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
| `--check-retries` | `3` | Reintentos por proxy antes de darlo por muerto. **Cada reintento prueba un protocolo distinto** (socks5 → socks4 → http) y el último repite el declarado (golpe de red / proxy lento, estilo *Proxy Checker by xRisky*) |
| `--check-mode` | `alive` | Modo del auto-health-check: `alive` (solo vivos + nunca verificados, barato) o `full` (**chequeo completo** de la lista en cada ciclo). `--check-all` es el alias histórico de `full`. Cambiable en caliente desde el panel (`POST /set-check-mode?mode=alive\|full`) |
| `--success-key` | *(vacío)* | Texto que **debe** aparecer en el cuerpo de la respuesta para dar el proxy por válido (validación de contenido real, estilo Proxy Checker). Ej.: `--test-url https://www.google.com/ --success-key "title>Google"` | 
| `--geo-mmdb` | *(auto)* | Ruta a una base MaxMind DB de países (`GeoLite2-Country.mmdb` / `DbipLite-Country.mmdb`) para **GeoIP offline** sin límites de tasa. Vacío = autodetecta `*.mmdb` en el directorio actual |
| `--activate-out` | `activados.txt` | Archivo propio donde el checker guarda los proxies **activados por país** (nunca toca `proxies.txt` ni `harvested.txt`). Se carga al pool desde el arranque si existe |
| `--api-token` | *(vacío)* | Token opcional para endpoints mutantes (header `X-API-Token`) |
| `--allow-any-path` | `false` | Desactiva la jaula de rutas de `/validate` e `/import` |
| `--idle-timeout` | `600` | Watchdog de inactividad en conexiones (0 = off) |
| `--upstream-timeout` | `120` | Tope **total** (cabeceras + cuerpo) por petición relayada por la vía HTTP; corta upstreams que gotean el cuerpo (0 = sin tope) |
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

### Fuente remota en OB M2 / SilverBullet: usa tope de líneas

Dos formas de conectar OB con el gateway, según quién gestione la rotación:

| Modo | Qué pegas en OB | Quién rota / reintenta |
|---|---|---|
| **A (recomendado)** | una sola línea `127.0.0.1:823` (o `user-session-123:clave@127.0.0.1:823`) | el gateway: rota, reintenta en milisegundos y mantiene la sesión sticky. OB solo chequea **1** proxy |
| **B** | fuente remota `/proxy.txt?alive=1&sort=ping&max=300` | OB: gestiona 300 proxies y los marca muertos por su cuenta |

En `Settings → RemoteProxySources` (OB M2) el campo se compone de `Url`,
`Pattern` y `Output` (los mismos que ya usas con DataImpulse), con `Type: 0`
(HTTP):

| Campo | Valor |
|---|---|
| `Url` | `http://127.0.0.1:8081/proxy.txt?alive=1&sort=ping&max=300` |
| `Pattern` | `([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+)` |
| `Output` | `[1]` |

En SilverBullet basta la URL en la lista de *Proxy Sources*, tipo `HTTP`.
Si activas `--api-token`, añade `&token=TU_TOKEN` a la URL.

### TLS_NEW_v9 (uTLS "TLS GRUPO VIP"): qué es y cómo encadenarlo

`TLS_NEW_v9.exe` **no es un proxy HTTP**: es una GUI (Tkinter) que levanta una
API local de *fetch* (FastAPI/uvicorn en `127.0.0.1:9000`) y hace cada petición
con `curl_cffi` (huella TLS de Chrome/Safari, "bypass WAF uTLS"). Contrato
verificado el 20/10/2026:

- `GET /` con la cabecera **`x-tls-url: https://destino/...`** (o `x-tp-url`)
  devuelve estado + cabeceras + cuerpo del destino.
- **No soporta `CONNECT`**: un cliente proxy clásico (OB, SilverBullet,
  `curl -x`) recibe `404 {"detail":"Not Found"}`. Por eso OB **no puede** usarlo
  como proxy directamente.
- **Sí acepta un proxy upstream por entorno** (lo lee `curl_cffi`), que es la
  vía para darle las IPs del pool:

```powershell
$env:HTTP_PROXY  = 'http://user-session-mibot:p@127.0.0.1:823'
$env:HTTPS_PROXY = $env:HTTP_PROXY
$env:ALL_PROXY   = $env:HTTP_PROXY
Start-Process 'C:\ruta\TLS_NEW_v9.exe'
```

Así cada fetch sale por el gateway (`CONNECT` + `Proxy-Authorization`, que el
gateway ya interpreta como `user-session-123`, `user-country-US` o
`user-rotate`): **uTLS + IPs del pool**. El usuario se fija al arrancar la
herramienta, no por petición: `user-rotate` para rotar en cada request,
`user-session-X` para IP fija.

> **Riesgo medido:** si el upstream falla, el TLS reintenta 3 veces y **luego va
> directo**, devolviendo `200` con tu IP real (fuga silenciosa). Corre el
> gateway con `--check-interval 60 --check-connect` y comprueba en el panel que
> el pool no está vacío antes de confiar en la cadena.

## Panel (identidad "Espectro")

El panel es una app de **3 zonas** con identidad propia (tokens de la mascota:
neón violeta/cian/oro sobre negro), y **todos los números salen de datos
medidos**: si algo no se ha medido, se muestra "—" en vez de inventarlo.

| Zona | Contenido |
|---|---|
| **Rail izquierdo** | Estado de análisis (válidos, caídos, reintentos aplicados, cola, último ciclo), Hilos & motor (hilos activos, modo de chequeo, tipo de validación), Velocidad & salida (CPM real, tasa de éxito, latencia p50/p90, sesiones), Vivos por protocolo (barras), Geolocalización top y Anonimato del último barrido. Cada tarjeta es **plegable** |
| **Centro** | KPIs, barra de acciones, carga de proxies, checker masivo, Auto-Fuentes, tabla del pool, log, **Guías** y **Configuración** |
| **Ficha lateral** | Al hacer clic en una fila: host:puerto, protocolo declarado vs. real, ping, país, **si tuneliza CONNECT** (sí / no / sin medir), fallos seguidos, enfriamiento, último check y la **línea exacta para OpenBullet** con un clic |

- **Dos modos de densidad** (conmutador *Resumen / Detalle* en la cabecera):
  `resumen` = lo esencial, `detalle` = todas las métricas y bloques extra.
- **Pestañas**: `Panel · Checker · Pool · Auto-Fuentes · Guías · Configuración · Log`.
- **Sistema de ayuda `?`**: cada control lleva un chip `?` con una tarjeta que
  explica **QUÉ HACE** y **SE CONECTA CON** (con ratón o con Tab).
- **Guías & recetas**: las 4 formas de enganchar el gateway (OB M2 / SilverBullet,
  fuente remota, uTLS-TLS NEW, cURL/Python) con el **puerto y la sesión reales**
  ya escritos, y botón de copiar.
- **Configuración** (pestaña propia): modo del chequeo, validación GET/CONNECT,
  reintentos, intervalo, estrategia, URL de validación, clave de éxito, Auto-Fuentes
  e intervalo. Se aplican **en caliente** y se guardan en `settings.json` (junto al
  programa, gitignored). **Los flags de la línea de comandos mandan** sobre el
  fichero: si arrancaste con `--check-mode full`, el panel no lo pisa.

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
`/proxy.txt?alive=1` — lo que come OB — **jamás** entrega un proxy sin validar
(exige `Alive && Checked`; el modo optimista es opt-in con
`?alive=1&include_unchecked=1`).
Esto es lo que evita las "pausas": la basura de las listas gratis (≈98% muerta)
nunca llega a tus bots.

### Chequeo: dos modos y reintentos con rotación de protocolo

Estilo *Proxy Checker by xRisky*, con dos mejoras que el gateway añade:

| Modo | Qué revisa | Cuándo usarlo |
|---|---|---|
| `alive` (por defecto) | solo los **vivos** + los **nunca verificados** | en producción: barato, no toca los muertos ya verificados |
| `full` | **toda** la lista en cada ciclo | cuando quieres el estado real del pool (diagnóstico, "revisar el estado") |

Se elige con `--check-mode alive|full` (o `--check-all`) y se cambia en caliente
desde el panel (selector **Chequeo**) o con `POST /set-check-mode?mode=full`.

**Reintentos con rotación de protocolo:** cada proxy se prueba hasta 4 veces y
**cada intento usa un protocolo distinto** (el declarado → socks5 → socks4 →
http; el último repite el declarado para absorber golpes de red). Motivo: en
las listas públicas el puerto suele venir **rotulado** (un socks5 etiquetado
como `http`), y con un solo intento se perdían proxies que sí funcionan. Cuando
un proxy responde con otro protocolo, el gateway lo **reclasifica**
(`reclasificado: … responde como socks5`), lo guarda en el estado y a partir de
ahí **el tráfico real usa el protocolo que funciona** — sin tocar tu `.txt`.

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

## Checker Masivo (nivel Proxy Checker by xRisky)

El checker valida **contenido real**, no solo que el proxy responda una línea
HTTP: eso era lo que hacía que se colaran proxies que devuelven páginas de
error del operador o del propia proxy.

### Site + Success Key (validación de contenido)

- **Site**: URL que se pide a través del proxy (ej. `https://www.google.com/`).
- **Success Key**: texto que **debe** aparecer en la respuesta (ej. `title>Google`,
  sin distinguir mayúsculas ni espacios sobrantes). Si no aparece, el proxy se
  marca **muerto** aunque haya devuelto `200 OK`.
- Sin Success Key se mantiene la **rama rápida** (cualquier respuesta válida
  cuenta): ideal para chequear cientos de miles de líneas rápido.
- Si no se indica Site, la validación se hace contra el **juez** (1 sola
  petición por proxy).
- Los proxies con inspección TLS (o certificados raros) **no** se descartan: el
  checker no valida la cadena de certificados, valida el **contenido**.

### Anonimato (Elite / High / Transparent)

Solo se consulta a los **vivos** (los muertos no gastan peticiones):

| Nivel | Significado |
|---|---|
| `Elite` | El juez no ve ni tu IP ni que hay un proxy |
| `High` | El juez ve que hay un proxy (`Via`/`Forwarded`) pero no tu IP |
| `Transparent` | El juez ve tu IP real (`X-Forwarded-For`/`Client-IP`) |
| `Unknown` | El juez no devolvió un eco de cabeceras (no se pudo clasificar) |

Si el Site **es** el juez (caso por defecto sin Site), el anonimato sale del
mismo cuerpo ya leído: **1 petición por proxy**.

### GeoIP offline (sin límites de tasa)

- Lee `GeoLite2-Country.mmdb` / `DbipLite-Country.mmdb` con un **lector mmdb
  propio** (sin dependencias): autodetecta `*.mmdb` en el directorio de trabajo
  o se le indica con `--geo-mmdb "<ruta>"`.
- Sin base mmdb, el país se pide al juez solo para los vivos (ip-api, ~45/min).
- El país se muestra en **inglés** (como GeoLite2/xRisky) + ISO, y el filtro es
  **tolerante**: acepta nombre en inglés, en español o el ISO (`brasil`, `BR`,
  `brazil`, `reino unido`, `GB`, `united kingdom`...), incluso el nombre oficial
  largo de DB-IP.

### Cascada en paralelo (Parallel)

Prueba SOCKS5, SOCKS4 y HTTP **a la vez**: un proxy muerto cuesta **1 timeout**
en vez de 3 (hasta ~3x más CPM). Gana el vivo de menor latencia. Se puede
desactivar para cascada secuencial clásica.

### Estado en vivo (estilo xRisky)

El panel muestra `Valid / Invalid / Retry / Checked / Remaining / CPM /
Time Elapsed`, el `Thread State` por protocolo (HTTP · Socks4 · Socks5 activos),
el reparto de anonimato, IPv4/IPv6, la base GeoIP en uso, el Site y la Success
Key. La tabla de vivos añade columna de **IP** (IPv4/IPv6) y el país con su ISO.

### Activar y exportar por país

El checker sabe el país de cada vivo (mmdb offline o juez). Dos funciones usan
ese dato, ambas con la misma selección de países (varios, o **todos**):

- **Activar en el pool**: pasa al pool del gateway los vivos elegidos y los deja
  **VIVOS** con el ping y el país medidos, de forma que OpenBullet los consume
  al instante (`/proxy.txt?alive=1`). Se persisten en su **archivo propio**
  (`activados.txt`, `--activate-out`) que se recarga al arrancar: **nunca** se
  toca `proxies.txt` ni `harvested.txt`. Opción **"solo estos"**: deja el pool
  únicamente con los países elegidos (el resto se desactiva, `Alive=false`); los
  activados en esa pasada nunca se desactivan.
  - Efecto lateral útil: al rellenar `Country`, ya funcionan los filtros por
    país de `/proxy.txt` y las sesiones sticky `user-country-US` del gateway.
- **Exportar selección**: descarga los vivos del checker filtrando por país,
  protocolo y formato: `plain` (`ip:puerto`), `proto` (`esquema://ip:puerto`),
  `full` (línea con ping · anon · país), `ob` (`tipo:ip:puerto:user:pass`),
  `csv` y `json`.

En el panel, los países de los vivos se pintan como **chips clicables** en la
sección del checker (sin elegir ninguno = todos) y alimentan tanto el botón
**Activar en el pool** como los enlaces de descarga. Los países también se
guardan en disco por sesión (`Paises Validados/<pais>.txt`).

El filtro es **tolerante** (`brasil` = `BR` = `brazil`, `reino unido` = `GB`),
acepta varios países separados por comas y, en el pool, los valores ISO se
comparan de forma **exacta** para que `au` (Australia) no capture `AT` (Austria).

### Números reales medidos (16/10/2026, esta máquina)

150 vivos de un pool real, `Site=https://www.google.com/`,
`Success Key=title>Google`, anonimato + paralelo + GeoIP por mmdb:

```
142 evaluados -> 38 vivos (18 http, 20 socks5), 104 muertos, 107 reintentos
CPM 354 · 24s · anonimato: 28 Elite / 1 High / 1 Transparent / 8 sin clasificar
paises (mmdb offline): 19 US, 7 CA, 2 GB, 2 IE, 2 IT, 1 BR, 1 FR, 1 MX
filtro "brasil" -> 1 vivo · "united states" -> 14 · "GB" -> 1 · "reino unido" -> 1
```

## API

- **Lectura (GET)**: `/get?session=X`, `/stats`, `/proxies`, `/logs`, `/proxy.txt`, `/panel`, `/settings`
  - `/settings` devuelve los ajustes vigentes del panel (modo del chequeo, validación, reintentos, intervalo, estrategia, URL/clave de validación, Auto-Fuentes, densidad). `POST /settings` (cabecera `X-GW-Panel`) los **aplica en caliente** y los guarda en `settings.json`.
  - `/proxies?limit=&offset=&sort=ping` (JSON con `checked`, `ping_ms`, `last_check`).
  - `/proxy.txt` exporta la lista de proxies con soporte de filtros:
    - `?alive=1`: Solo proxies **vivos y validados** (`Alive && Checked`). Tras un
      arranque limpio, tu propia lista no aparece aquí hasta que el health-check
      la valide (o la actives desde el checker): así se cumple la política "solo
      vivo y filtrado". Para el modo optimista histórico (servir la lista recién
      cargada aunque no esté verificada) añade `&include_unchecked=1`.
    - `?country=US`: Solo proxies de un país específico. Acepta **varios**
      (`?country=BR,US`), ISO o nombre en inglés/español (`brasil`, `reino unido`).
      Vacío o `all` = todos.
    - `?max_ping=400`: Solo proxies con latencia $\le$ 400 ms.
    - `?scheme=socks5` (o `?proto=socks5`): Solo proxies con ese protocolo.
      `scheme=socks4` **incluye** `socks4a` (igual que el checker y el export OB,
      que no distinguen 4a); `scheme=socks4a` pide solo 4a.
    - `?sort=ping`: Ordena por menor latencia primero.
    - `?max=500` (alias `?limit=`): corta la lista a N líneas **después** de
      ordenar (con `sort=ping` se queda con las N más rápidas; techo duro
      200.000). Es el parámetro que evita que OB/SilverBullet se cuelguen con la
      lista completa: ver "Fuente remota" más arriba.
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
- **POST + JSON (con cabecera `X-GW-Panel: 1`)**: `/validate` y `/import` (`{"path":"..."}` o `{"text":"...","name":"..."}`)
  - Rutas limitadas a cwd, directorio del exe y directorios de las listas activas (symlinks/junctions resueltos antes de validar).
  - `/import` escribe en la lista principal: exige la cabecera del panel para que
    una web ajena no pueda colar proxys en tu lista por CSRF (auditoría 17/10/2026).
- **Checker masivo** (sección "Checker Masivo" del panel):
  - `POST /checker/start` (`X-GW-Panel`): `{"path"|"text", "site", "success_key", "judge", "country", "geo", "anon", "parallel", "retries", "timeout", "threads", "skip_local"}` — 409 si ya hay un job en marcha.
  - `POST /checker/cancel` · `POST /checker/remove` · `GET /checker/status` · `GET /checker/hits?proto=&limit=`
  - `POST /checker/remove` (`X-GW-Panel`): `{"line":"1.2.3.4:8080"}` · `{"proto":"http|socks4|socks5|all"}` →
    `{"ok", "removed", "remaining"}`. Borra vivos **en memoria**: el contador vivo,
    `/checker/hits`, `/checker/export` y `/checker/countries` se actualizan solos.
    Los `.txt` de la sesión en `Resultados/` **no se reescriben** (quedan como
    registro bruto del run).
  - `GET /checker/export?proto=all|http|socks4|socks5&format=full|plain|proto|ob|csv|json&countries=all|BR,US,brasil` · `GET /checker/countries` (`{countries:{...}, list:[{name,iso,count}]}`) · `GET /checker/report`
  - `POST /checker/activate` (`X-GW-Panel`): `{"countries":"all|BR,US,brasil","proto":"all|http|socks4|socks5","only":false}`
    → `{"ok","result":{activated,new,updated,demoted,in_file,countries,file,pool_alive,pool_total,at}}`.
    Pasa los vivos del checker (filtrados por país/protocolo) al pool **como
    vivos**, con `PingMs`/`Country` medidos, y los persiste en `activados.txt`.
    Con `only:true` desactiva del pool lo que no coincida. 400 si no hay vivos
    que coincidan o no hay job.
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
- **Tope upstream (17/10/2026)**: `--upstream-timeout` (120s) acota la petición
  relayada completa (cabeceras + cuerpo). `ResponseHeaderTimeout` (10s) solo
  cubría las cabeceras: un upstream que respondía 200 y luego goteaba el cuerpo
  retenía la conexión indefinidamente. El túnel `CONNECT` ya tenía el watchdog
  de inactividad. `0` = sin tope (comportamiento clásico).
- **`/proxy.txt?alive=1` estricto (17/10/2026)**: exige `Alive && Checked`, así
  que la promesa "jamás entrega un proxy sin validar" también se cumple con tus
  propias listas en un arranque limpio (antes `ParseProxyDef` marcaba
  `Alive=true` y OB recibía 12k+ proxies sin verificar). `include_unchecked=1`
  recupera el modo optimista; `include_unchecked` no afecta al relay interno,
  que sigue usando la lista viva.
- **`scheme=socks4` agrupa `socks4a`**: una sola semántica en todo el producto
  (checker `protoMatch`, export OB —tipo 1— y `/proxy.txt`). `scheme=socks4a`
  sigue siendo exacto.
- **Superficie de red**: el gateway es un proxy de reenvío por diseño (acepta
  `CONNECT` a cualquier host:puerto). Se escucha en loopback por defecto y
  `--bind` no-loopback imprime un aviso: si lo expones a la LAN, pon un firewall
  o `--api-token` (la API/panel NO tienen autenticación propia).
- **Triage Snyk (17/10/2026)**: `SAST 57` son falsos positivos verificados — 11
  `javascript/DOMXSS` en `panel.html` (todo `innerHTML` pasa por `esc()`) y 2
  `go/PT` (`import.go` lee tras `rutaPermitida`; `editProxy` escribe a
  `p.File`, que viene del pool, no del request). `SCA 0`. Los códigos no se
  "silencian" con ficheros de política a propósito: un ignore global taparía
  XSS/path-traversal futuros.
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
- **Checker nivel Proxy Checker by xRisky — contenido, anonimato y GeoIP
  offline (16/10/2026)**: la debilidad era dar por **vivo** cualquier proxy que
  devolviera una línea HTTP (páginas de error del operador, portales cautivos o
  respuestas del propio proxy colándose). Ahora:
  - **Site + Success Key**: se pide una URL real a través del proxy y se exige
    un texto en el cuerpo (`title>Google`, sin distinguir mayúsculas). Sin
    Success Key se mantiene la rama rápida (cualquier respuesta válida).
    El checker **no** valida la cadena de certificados TLS: valida el
    contenido, así que un proxy con inspección TLS o certificado raro no se
    descarta por eso.
  - **Anonimato Elite / High / Transparent** (con `Unknown` si el juez no
    devuelve eco) y **solo a los vivos**. Si el Site es el juez (caso por
    defecto) el anonimato sale del mismo cuerpo: **1 petición por proxy**.
  - **GeoIP offline por mmdb** (`geoip.go`): lector MaxMind DB propio, **sin
    dependencias** (metadata, árbol 24/28/32 bits, punteros, tipos 1-15,
    caché). Autodetecta `*.mmdb` o `--geo-mmdb "<ruta>"`; verificado contra
    GeoLite2 y DB-IP reales (IPv4 e IPv6). Elimina el límite de ip-api
    (~45/min), que ahora solo se usa —para los vivos— si no hay base.
  - **Filtro de país tolerante**: nombre en inglés, en español o ISO, y también
    el nombre oficial largo de DB-IP (`brasil` = `BR` = `brazil`,
    `reino unido` = `GB` = `united kingdom`). Motivo: GeoLite2 viejo trae
    `names.es="RU"` para Reino Unido y DB-IP usa nombres de la ONU
    larguísimos; el país se **muestra** en inglés (como GeoLite2/xRisky) + ISO.
  - **Cascada en paralelo** (`parallel`, por defecto): SOCKS5/SOCKS4/HTTP a la
    vez; un muerto cuesta **1 timeout** en vez de 3 (~3x CPM) y gana el vivo de
    menor ping.
  - **Estado en vivo tipo xRisky** en el panel: `Valid / Invalid / Retry /
    Checked / Remaining / CPM / Time Elapsed`, `Thread State` por protocolo,
    reparto de anonimato, IPv4/IPv6, base GeoIP en uso, Site y Success Key; la
    tabla añade columna **IP** (v4/v6) y el país con su ISO.
  - Medición real (150 vivos del pool, Google + `title>Google`, anon +
    paralelo + mmdb): **142 evaluados → 38 vivos, CPM 354, 24s**; anonimato
    28 Elite / 1 High / 1 Transparent / 8 sin clasificar; países 19 US, 7 CA,
    2 GB, 2 IE, 2 IT, 1 BR, 1 FR, 1 MX; filtros `brasil`→1, `united states`→14,
    `GB`→1, `reino unido`→1.
  - Tests nuevos: `checker_pro_test.go` (12) y `geoip_test.go` (mmdb sintético,
    inválidos, ciclo, y bases reales vía `ESPECTRO_TEST_MMDB`).
    Batería: **19 + 112 + 25 + 300 + 198** (Go) PASS, 0 races, coverage 65.8%.
- **Activar y exportar por país (16/10/2026)**: el país que ya calculaba el
  checker se aprovecha para dos funciones nuevas, con la misma selección de
  países (varios o todos) y filtro tolerante (`brasil` = `BR` = `brazil`,
  `reino unido` = `GB`):
  - **Activar en el pool** (`POST /checker/activate` + botón en el panel): los
    vivos elegidos entran al pool **VIVOS** con ping y país medidos (OpenBullet
    los ve al instante en `/proxy.txt?alive=1`) y se persisten en su **archivo
    propio** `activados.txt` (`--activate-out`), que se carga al arrancar:
    **nunca** toca `proxies.txt` ni `harvested.txt`. `only:true` ("solo estos")
    desactiva del pool lo que no coincida.
    Motivo: hasta ahora `p.Country` solo se rellenaba desde el estado, así que
    `?country=` de `/proxy.txt` y las sesiones sticky `user-country-US` no
    tenían datos; activar por país los habilita de verdad.
  - **Exportar por país** (`/checker/export?countries=`) y enlaces del panel con
    formato `plain`, `proto`, `full`, `ob`, `csv` o `json`.
  - **Filtro multi-país tolerante** también en `/proxy.txt` y en el gateway
    (`pickWithCountry`): `?country=BR,US`, `?country=brasil`,
    `user-country-reino unido`. Los ISO del pool se comparan de forma exacta
    ("au" no captura "Austria").
  - Panel: chips clicables de países de los vivos (con ISO y conteo), botón
    **Activar en el pool**, casilla "solo estos", selector de formato y
    **Exportar selección**; los enlaces de descarga siguen a la selección.
  - Tests: `activate_test.go` (8 tests: parseo/tolerancia ISO, activación con
    persistencia y sin duplicados, "solo estos", filtro por protocolo, export
    por país y formatos, endpoints) + fase B21 de la suite UI (16 checks).
    Batería: Go **0 races**, coverage **67.5%**; UI **318 pass / 0 fail**.

## Estructura

```
main.go        flags, arranque, bind warning
app.go         App, pick/sesiones, índices, markFail/markOK
gateway.go     relay CONNECT/plain, túneles, watchdog idle
upstream.go    dial a proxies HTTP/SOCKS + taxonomía de errores
health.go      health-check periódico (scope, ping, reintentos)
harvest.go     Auto-Fuentes: recoleccion + descubrimiento de fuentes
harvest_api.go endpoints /harvest/*
geoip.go       lector MaxMind DB propio (GeoIP offline, sin dependencias).
masscheck.go   checker masivo (cascada, geo, país, discord, /checker/*)
activate.go    activar/exportar por país (checker -> pool, activados.txt)
state.go       estado persistente <lista>.state.json
api.go         endpoints REST + panel embebido
import.go      /validate, /import, jaula de rutas
proxy.go       parseo de líneas y formatos de salida
licensing.go   licencias (modo demo/Pro, tope del checker, --version)
internal/lic/  formato de licencia (Ed25519 + AES-GCM por máquina)
lictool/       emisión de licencias (clave privada; uso del vendedor)
panel.html     panel (embed)
legacy/        prototipo Python original (referencia)
tests/         suites Python (19 + 25 + 112) + test_panel_ui.mjs (318, Node; GW_EXE= para probar otro binario)
build_release.ps1  build de release (garble si está instalado)
```
