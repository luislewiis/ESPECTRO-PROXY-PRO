# Seguridad — ESPECTRO PROXY PRO

## Modelo de amenaza

ProxyGateway es una herramienta **local** (bind 127.0.0.1 por defecto) que
actúa de proxy HTTP/SOCKS y panel web. Consideraciones:

- La API/panel **no llevan autenticación por defecto** (modo local). Si usas
  `--bind` distinto de loopback, activa `--api-token` (401/429 en lecturas y
  mutantes) y protege los puertos con firewall.
- El gateway proxy **no tiene autenticación de clientes** (diseño): cualquiera
  con acceso a la red donde escucha puede usarlo. No lo expongas a Internet.
- Los archivos `proxies.txt`, `*.state.json`, `Resultados/` y `webhook.txt`
  contienen datos sensibles (credenciales de proxies, IPs, webhooks): están
  en `.gitignore` y **no deben subirse a ningún repositorio**.
- La clave privada de licencias (`licencias/priv.key`) solo existe en la
  máquina del emisor; jamás se distribuye ni se versiona.

## Ciclo de vida de seguridad

- Auditorías internas + fuzzing (3 targets) + Snyk SAST/SCA antes de cada
  release. Política de falsos positivos documentada en `.snyk`.
- Dependencias: solo stdlib + `go-webview2` + `x/sys` (ver `go.mod`).
- Límites de recursos: `MaxHeaderBytes` 64 KB, `byteCap` en cabeceras,
  `bodyCap` en cuerpos, tope de 4000 hilos en el checker, rate-limit de
  autenticación (10 fallos → 429).

## Reportar una vulnerabilidad

1. Usa **GitHub Security Advisories** del repositorio (modo privado) una vez
   publicado, o contacta al maintainer por privado.
2. Incluye pasos de reproducción y el impacto real (escala local/red).
3. No publiques exploits antes de que haya una versión corregida.

## Alcance

- ✔ Código fuente de este repositorio, el binario oficial y el panel web.
- ✘ Redes de terceros, los proxies de usuarios, servicios juzgadores.
