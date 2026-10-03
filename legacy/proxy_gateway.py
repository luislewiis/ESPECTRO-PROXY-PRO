#!/usr/bin/env python3
"""proxy_gateway.py - Gateway de rotacion de proxies estilo Dataimpulse (solo stdlib).

Carga listas de proxies desde archivos .txt, los valida (health-check periodico) y
expone UN unico endpoint HTTP local que rota automaticamente. Incluye sesiones
sticky (misma IP para un token) como Dataimpulse.

Formatos de linea aceptados:
  1.2.3.4:8080
  usuario:clave@1.2.3.4:8080
  http://1.2.3.4:8080
  socks5://user:pass@1.2.3.4:1080
  0:1.2.3.4:8080::        (formato OB/OpenBullet: 0=http 1=socks4 2=socks5)
  1.2.3.4:8080:user:pass

Uso:
  python proxy_gateway.py proxies.txt listas/*.txt
  python proxy_gateway.py proxies.txt --http-port 8080 --api-port 8081 --strategy sticky

Endpoints (API):
  http://127.0.0.1:8081/                 Info y enlaces
  http://127.0.0.1:8081/get?session=abc  Enlace gateway con sesion fija (sticky)
  http://127.0.0.1:8081/stats            Estadisticas JSON
  http://127.0.0.1:8081/proxy.txt        Lista viva host:port (para OB M2)
  http://127.0.0.1:8081/proxy.txt?format=ob   Lista formato OB (0:host:port:user:pass)
  http://127.0.0.1:8081/reload           Recarga los archivos .txt

Uso con tus herramientas:
  - Como proxy unico (rotacion automatica):  http://127.0.0.1:8080
  - Con sesion sticky:                       http://SESION:clave@127.0.0.1:8080
"""

import argparse
import asyncio
import base64
import glob as globmod
import json
import random
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass, field

CONNECT_TIMEOUT = 10
HEAD_TIMEOUT = 30
BODY_TIMEOUT = 60
IDLE_TIMEOUT = 60
MAX_HEAD = 64 * 1024
BODY_CAP = 20 * 1024 * 1024

TYPE_MAP = {
    "0": "http", "1": "socks4", "2": "socks5", "3": "http",
    "http": "http", "https": "http", "socks": "socks5",
    "socks4": "socks4", "socks4a": "socks4a", "socks5": "socks5",
}


class ProxyError(Exception):
    pass


@dataclass(unsafe_hash=True)
class Proxy:
    scheme: str
    host: str
    port: int
    user: str = ""
    password: str = ""
    alive: bool = True
    fails: int = 0
    last_check: float = 0.0

    @property
    def key(self):
        return (self.scheme, self.host, self.port, self.user)

    @property
    def tag(self):
        auth = f"{self.user}@@" if self.user else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    @property
    def plain(self):
        return f"{self.host}:{self.port}"

    @property
    def ob(self):
        t = {"http": "0", "socks4": "1", "socks5": "2"}.get(self.scheme, "0")
        return f"{t}:{self.host}:{self.port}:{self.user}:{self.password}"


def _split_hostport(s):
    if s.startswith("["):
        i = s.index("]")
        return s[1:i], int(s[i + 1:].lstrip(":") or 443)
    host, _, port = s.rpartition(":")
    return host, int(port)


def parse_proxy(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    try:
        if "://" in s:
            u = urllib.parse.urlsplit(s)
            scheme = u.scheme.lower()
            if scheme not in TYPE_MAP:
                return None
            scheme = TYPE_MAP[scheme]
            host = u.hostname
            port = u.port or (1080 if scheme.startswith("socks") else 8080)
            user = urllib.parse.unquote(u.username or "")
            pwd = urllib.parse.unquote(u.password or "")
            return Proxy(scheme, host, port, user, pwd)

        if "@" in s:
            left, right = s.rsplit("@", 1)
            user, _, pwd = left.partition(":")
            host, port = _split_hostport(right)
            return Proxy("http", host, port, user, pwd)

        parts = s.split(":")
        if len(parts) >= 3 and parts[0].lower() in TYPE_MAP:
            scheme = TYPE_MAP[parts[0].lower()]
            host = parts[1]
            port = int(parts[2])
            user = parts[3] if len(parts) > 3 else ""
            pwd = parts[4] if len(parts) > 4 else ""
            return Proxy(scheme, host, port, user, pwd)

        if len(parts) == 2:
            host, port = _split_hostport(s)
            return Proxy("http", host, port)
        if len(parts) == 3:
            host, port = _split_hostport(f"{parts[0]}:{parts[1]}")
            return Proxy("http", host, port, parts[2], "")
        if len(parts) == 4:
            host, port = _split_hostport(f"{parts[0]}:{parts[1]}")
            return Proxy("http", host, port, parts[2], parts[3])
    except Exception:
        return None
    return None


# ---------------------------------------------------------------- upstreames

async def open_http_tunnel(p, host, port):
    r, w = await asyncio.wait_for(
        asyncio.open_connection(p.host, p.port), CONNECT_TIMEOUT)
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}",
             "Proxy-Connection: keep-alive"]
    if p.user:
        tok = base64.b64encode(f"{p.user}:{p.password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {tok}")
    w.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await w.drain()
    status = await asyncio.wait_for(r.readline(), CONNECT_TIMEOUT)
    while True:
        line = await asyncio.wait_for(r.readline(), CONNECT_TIMEOUT)
        if not line or line in (b"\r\n", b"\n"):
            break
    try:
        code = int(status.split()[1])
    except Exception:
        code = 0
    if code != 200:
        w.close()
        raise ProxyError(f"upstream CONNECT devolvio {code or 'basura'}")
    return r, w


async def open_socks5(p, host, port):
    r, w = await asyncio.wait_for(
        asyncio.open_connection(p.host, p.port), CONNECT_TIMEOUT)
    try:
        if p.user:
            w.write(b"\x05\x02\x00\x02")
            await w.drain()
            ver, method = await asyncio.wait_for(r.readexactly(2), CONNECT_TIMEOUT)
            if method == 0xFF:
                raise ProxyError("socks5: sin metodos aceptables")
            if method == 0x02:
                ub = p.user.encode()[:255]
                pb = (p.password or "").encode()[:255]
                w.write(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
                await w.drain()
                resp = await asyncio.wait_for(r.readexactly(2), CONNECT_TIMEOUT)
                if resp[1] != 0:
                    raise ProxyError("socks5: autenticacion rechazada")
            elif method != 0x00:
                raise ProxyError(f"socks5: metodo inesperado {method}")
        else:
            w.write(b"\x05\x01\x00")
            await w.drain()
            ver, method = await asyncio.wait_for(r.readexactly(2), CONNECT_TIMEOUT)
            if method != 0x00:
                raise ProxyError(f"socks5: servidor pidio metodo {method}")
        hb = host.encode()
        if len(hb) > 255:
            raise ProxyError("host demasiado largo")
        w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + int(port).to_bytes(2, "big"))
        await w.drain()
        hdr = await asyncio.wait_for(r.readexactly(4), CONNECT_TIMEOUT)
        if hdr[1] != 0x00:
            raise ProxyError(f"socks5: connect fallo rep={hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            await r.readexactly(6)
        elif atyp == 4:
            await r.readexactly(18)
        elif atyp == 3:
            ln = (await r.readexactly(1))[0]
            await r.readexactly(ln + 2)
        else:
            raise ProxyError(f"socks5: atyp raro {atyp}")
        return r, w
    except Exception:
        w.close()
        raise


async def open_socks4(p, host, port):
    r, w = await asyncio.wait_for(
        asyncio.open_connection(p.host, p.port), CONNECT_TIMEOUT)
    try:
        uid = (p.user or "ob").encode()[:255]
        req = b"\x04\x01" + int(port).to_bytes(2, "big")
        try:
            req += socket.inet_aton(host)
        except OSError:
            req += b"\x00\x00\x00\x01"  # socks4a: requiere hostname
        req += uid + b"\x00"
        try:
            socket.inet_aton(host)
        except OSError:
            req += host.encode() + b"\x00"
        w.write(req)
        await w.drain()
        resp = await asyncio.wait_for(r.readexactly(8), CONNECT_TIMEOUT)
        if resp[1] != 0x5A:
            raise ProxyError(f"socks4: rep={resp[1]}")
        return r, w
    except Exception:
        w.close()
        raise


async def open_tunnel(p, host, port):
    if p.scheme == "http":
        return await open_http_tunnel(p, host, port)
    if p.scheme == "socks5":
        return await open_socks5(p, host, port)
    if p.scheme in ("socks4", "socks4a"):
        return await open_socks4(p, host, port)
    raise ProxyError(f"esquema desconocido {p.scheme}")


# ------------------------------------------------------------------ lecturas

def parse_head(raw):
    lines = raw.decode("latin-1").split("\r\n")
    first = lines[0].split()
    if len(first) < 3:
        raise ProxyError("linea de peticion invalida")
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    return first[0], first[1], first[2], headers


async def read_body(reader, headers):
    if headers.get("transfer-encoding", "").lower() == "chunked":
        buf = bytearray()
        while True:
            size_line = await asyncio.wait_for(reader.readline(), BODY_TIMEOUT)
            if not size_line:
                break
            try:
                size = int(size_line.split(b";")[0].strip(), 16)
            except ValueError:
                raise ProxyError("chunk invalido")
            if size == 0:
                while True:
                    ln = await asyncio.wait_for(reader.readline(), BODY_TIMEOUT)
                    if not ln or ln in (b"\r\n", b"\n"):
                        break
                break
            if len(buf) + size > BODY_CAP:
                raise ProxyError("cuerpo demasiado grande")
            data = await asyncio.wait_for(reader.readexactly(size + 2), BODY_TIMEOUT)
            buf += data[:size]
        return bytes(buf)
    cl = headers.get("content-length")
    if cl:
        n = int(cl)
        if n > BODY_CAP:
            raise ProxyError("cuerpo demasiado grande")
        if n:
            return await asyncio.wait_for(reader.readexactly(n), BODY_TIMEOUT)
    return b""


# ------------------------------------------------------------------ relay

async def pump(src, dst, stats, up):
    total = 0
    while True:
        data = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
        if not data:
            break
        total += len(data)
        dst.write(data)
        await dst.drain()
    if up:
        stats["bytes_up"] += total
    else:
        stats["bytes_down"] += total


async def relay_bidi(cr, cw, ur, uw, stats):
    t1 = asyncio.create_task(pump(cr, uw, stats, True))
    t2 = asyncio.create_task(pump(ur, cw, stats, False))
    try:
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED,
                            timeout=IDLE_TIMEOUT * 60)
    finally:
        for t in (t1, t2):
            t.cancel()
        for w in (cw, uw):
            try:
                w.close()
            except Exception:
                pass
        await asyncio.gather(t1, t2, return_exceptions=True)


async def relay_chunked(r, w, stats):
    while True:
        size_line = await asyncio.wait_for(r.readline(), BODY_TIMEOUT)
        if not size_line:
            break
        w.write(size_line)
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            raise ProxyError("chunk invalido en respuesta")
        if size == 0:
            while True:
                ln = await asyncio.wait_for(r.readline(), BODY_TIMEOUT)
                w.write(ln)
                if not ln or ln in (b"\r\n", b"\n"):
                    break
            break
        remaining = size + 2
        sent = 0
        while remaining > 0:
            d = await asyncio.wait_for(r.read(min(65536, remaining)), BODY_TIMEOUT)
            if not d:
                raise ProxyError("conexion cerrada a mitad de chunk")
            w.write(d)
            sent += len(d)
            remaining -= len(d)
        stats["bytes_down"] += sent
    await w.drain()


HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
              "proxy-authorization", "proxy-connection", "te", "trailers",
              "upgrade", "transfer-encoding", "content-length"}


async def read_response_head(ur):
    head = await asyncio.wait_for(ur.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
    lines = head.decode("latin-1").split("\r\n")
    status_line = lines[0]
    headers = []
    cl = None
    chunked = False
    for ln in lines[1:]:
        if not ln or ":" not in ln:
            continue
        k, _, v = ln.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k == "content-length":
            try:
                cl = int(v)
            except ValueError:
                cl = None
            headers.append((k, v))
            continue
        if k == "transfer-encoding" and "chunked" in v.lower():
            chunked = True
            headers.append((k, v))
            continue
        if k in HOP_BY_HOP:
            continue
        headers.append((k, v))
    return status_line, headers, cl, chunked


def build_response_head(status_line, headers):
    out = status_line + "\r\n"
    for k, v in headers:
        out += f"{k}: {v}\r\n"
    out += "Connection: close\r\n\r\n"
    return out.encode("latin-1")


async def relay_body(ur, cw, cl, chunked, stats):
    if cl is not None:
        remaining = cl
        while remaining > 0:
            d = await asyncio.wait_for(ur.read(min(65536, remaining)), BODY_TIMEOUT)
            if not d:
                break
            cw.write(d)
            await cw.drain()
            stats["bytes_down"] += len(d)
            remaining -= len(d)
    elif chunked:
        await relay_chunked(ur, cw, stats)
    else:
        while True:
            d = await asyncio.wait_for(ur.read(65536), BODY_TIMEOUT)
            if not d:
                break
            cw.write(d)
            await cw.drain()
            stats["bytes_down"] += len(d)


# --------------------------------------------------------------- gateway

class Gateway:
    def __init__(self, app):
        self.app = app

    def alive_list(self):
        return [p for p in self.app.proxies if p.alive]

    def pick(self, session=None, exclude=frozenset()):
        alive = [p for p in self.alive_list() if p not in exclude]
        cands = alive or [p for p in self.app.proxies if p not in exclude]
        if not cands:
            return None
        if session:
            p = self.app.sessions.get(session)
            if p is not None and p in cands:
                return p
        if self.app.strategy == "random":
            chosen = random.choice(cands)
        else:
            self.app.rr = (self.app.rr + 1) % len(cands)
            chosen = cands[self.app.rr]
        if session:
            self.app.sessions[session] = chosen
        return chosen

    def mark_fail(self, p):
        p.fails += 1
        if p.fails >= 3 and p.alive:
            p.alive = False
            log(f"proxy marcado muerto: {p.tag} (3 fallos)")
            for k in [k for k, v in self.app.sessions.items() if v is p]:
                del self.app.sessions[k]

    def mark_ok(self, p):
        p.fails = 0

    def session_of(self, headers):
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("latin-1")
                return decoded.partition(":")[0] or None
            except Exception:
                return None
        return None

    async def handle(self, reader, writer):
        try:
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            except Exception:
                return
            try:
                method, target, _ver, headers = parse_head(raw)
            except ProxyError:
                return
            app = self.app
            app.stats["requests"] += 1
            try:
                if method == "CONNECT":
                    await self.do_connect(reader, writer, target, headers)
                else:
                    await self.do_http(reader, writer, method, target, headers)
            except Exception as e:
                app.stats["errors"] += 1
                log(f"error: {method} {target[:80]} -> {e}")
                try:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                except Exception:
                    pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def do_connect(self, cr, cw, target, headers):
        if ":" in target:
            host, _, port = target.rpartition(":")
            port = int(port)
        else:
            host, port = target, 443
        session = self.session_of(headers)
        exclude = set()
        last_err = None
        for _ in range(4):
            p = self.pick(session, exclude)
            if not p:
                break
            try:
                ur, uw = await open_tunnel(p, host, port)
            except Exception as e:
                last_err = e
                self.mark_fail(p)
                exclude.add(p)
                log(f"falla {p.tag} CONNECT {host}:{port}: {e}")
                continue
            self.mark_ok(p)
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await cw.drain()
            if not self.app.quiet:
                log(f"CONNECT {host}:{port} via {p.tag}")
            await relay_bidi(cr, cw, ur, uw, self.app.stats)
            return
        self.app.stats["errors"] += 1
        cw.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        await cw.drain()
        log(f"502 CONNECT {host}:{port}: sin proxy util ({last_err})")

    async def do_http(self, cr, cw, method, target, headers):
        if "://" in target:
            url = target
        else:
            host_hdr = headers.get("host")
            if not host_hdr:
                cw.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await cw.drain()
                return
            path = target if target.startswith("/") else "/" + target
            url = f"http://{host_hdr}{path}"
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        port = u.port or 80
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        body = await read_body(cr, headers)
        session = self.session_of(headers)
        exclude = set()
        last_err = None
        for _ in range(4):
            p = self.pick(session, exclude)
            if not p:
                break
            ur = uw = None
            try:
                if p.scheme == "http":
                    ur, uw = await asyncio.wait_for(
                        asyncio.open_connection(p.host, p.port), CONNECT_TIMEOUT)
                    req_line = f"{method} {url} HTTP/1.1"
                else:
                    ur, uw = await open_tunnel(p, host, port)
                    req_line = f"{method} {path} HTTP/1.1"
                out = req_line + "\r\n"
                for k, v in headers.items():
                    if k in HOP_BY_HOP or k == "host":
                        continue
                    out += f"{k}: {v}\r\n"
                out += f"Host: {headers.get('host') or host_hdr_for(host, port)}\r\n"
                out += "Connection: close\r\n"
                if body or "content-length" in headers:
                    out += f"Content-Length: {len(body)}\r\n"
                out += "\r\n"
                uw.write(out.encode("latin-1") + body)
                await uw.drain()
                status_line, rheaders, cl, chunked = await read_response_head(ur)
            except Exception as e:
                last_err = e
                self.mark_fail(p)
                exclude.add(p)
                log(f"falla {p.tag} {method} {host}: {e}")
                for w in (uw, ur):
                    if w is not None:
                        try:
                            w.close()
                        except Exception:
                            pass
                continue

            # ya tenemos respuesta del upstream: no mas reintentos
            self.mark_ok(p)
            if not self.app.quiet:
                log(f"{method} {url[:90]} via {p.tag}")
            try:
                cw.write(build_response_head(status_line, rheaders))
                await cw.drain()
                await relay_body(ur, cw, cl, chunked, self.app.stats)
            except Exception as e:
                self.app.stats["errors"] += 1
                log(f"relay cortado {method} {host}: {e}")
            finally:
                for w in (uw, ur):
                    try:
                        w.close()
                    except Exception:
                        pass
            return
        self.app.stats["errors"] += 1
        cw.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        await cw.drain()
        log(f"502 {method} {url[:90]}: sin proxy util ({last_err})")


def host_hdr_for(host, port):
    return f"{host}:{port}" if port != 80 else host


# --------------------------------------------------------------- health

async def health_check(p, test_url):
    u = urllib.parse.urlsplit(test_url)
    host = u.hostname
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    try:
        if p.scheme == "http":
            r, w = await asyncio.wait_for(
                asyncio.open_connection(p.host, p.port), 8)
            req = f"GET {test_url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
            if p.user:
                tok = base64.b64encode(f"{p.user}:{p.password}".encode()).decode()
                req += f"Proxy-Authorization: Basic {tok}\r\n"
            w.write((req + "\r\n").encode())
            await w.drain()
            status = await asyncio.wait_for(r.readline(), 8)
            w.close()
            return status.startswith(b"HTTP/")
        r, w = await asyncio.wait_for(open_tunnel(p, host, port), 8)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        w.write(req.encode())
        await w.drain()
        status = await asyncio.wait_for(r.readline(), 8)
        w.close()
        return status.startswith(b"HTTP/")
    except Exception:
        return False


# --------------------------------------------------------------- app

def log(msg):
    print(f"[gw] {time.strftime('%H:%M:%S')} {msg}", flush=True)


class App:
    def __init__(self, args):
        self.args = args
        self.files = []
        for pattern in args.files:
            matched = sorted(globmod.glob(pattern)) or [pattern]
            self.files.extend(matched)
        self.proxies = []
        self.sessions = {}
        self.rr = -1
        self.strategy = args.strategy
        self.quiet = args.quiet
        self.stats = {"requests": 0, "errors": 0, "bytes_up": 0, "bytes_down": 0}
        self.load_proxies()

    def load_proxies(self):
        old = {p.key: p for p in self.proxies}
        proxies = []
        seen = set()
        skipped = 0
        for f in self.files:
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        p = parse_proxy(line)
                        if p is None:
                            if line.strip() and not line.strip().startswith("#"):
                                skipped += 1
                            continue
                        if p.key in seen:
                            continue
                        seen.add(p.key)
                        prev = old.get(p.key)
                        if prev:
                            p.alive = prev.alive
                            p.fails = prev.fails
                            p.last_check = prev.last_check
                        proxies.append(p)
            except OSError as e:
                log(f"no se pudo leer {f}: {e}")
        self.proxies = proxies
        log(f"lista cargada: {len(proxies)} proxies desde {len(self.files)} archivo(s)"
            + (f", {skipped} lineas ignoradas" if skipped else ""))
        return skipped

    async def checker_loop(self):
        interval = self.args.check_interval
        if interval <= 0:
            log("health-check desactivado (--check-interval 0)")
            return
        while True:
            await asyncio.sleep(interval)
            await self.run_checks()

    async def run_checks(self):
        sem = asyncio.Semaphore(64)
        test_url = self.args.test_url

        async def one(p):
            async with sem:
                ok = await health_check(p, test_url)
            p.last_check = time.time()
            if ok and not p.alive:
                p.alive = True
                p.fails = 0
                log(f"revivido: {p.tag}")
            elif not ok and p.alive:
                p.alive = False
                log(f"muerto: {p.tag}")
            elif ok:
                p.fails = 0

        await asyncio.gather(*(one(p) for p in list(self.proxies)))
        alive = len(self.alive_count())
        log(f"health-check: {alive}/{len(self.proxies)} vivos")

    def alive_count(self):
        return [p for p in self.proxies if p.alive]

    # ------------------------------------------------------------- api

    async def handle_api(self, reader, writer):
        try:
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            except Exception:
                return
            try:
                method, target, _v, headers = parse_head(raw)
            except ProxyError:
                return
            path, _, query = target.partition("?")
            qs = urllib.parse.parse_qs(query)
            gport = self.args.http_port
            base = f"http://{self.args.bind}:{gport}"
            body = None
            ctype = "text/plain; charset=utf-8"
            if path == "/":
                alive = len(self.alive_count())
                total = len(self.proxies)
                token = (qs.get("session") or ["MI_SESION"])[0]
                body = f"""<!doctype html><meta charset="utf-8"><title>Proxy Gateway</title>
<h1>Proxy Gateway (estilo Dataimpulse)</h1>
<p><b>{alive}/{total}</b> proxies vivos | estrategia: {self.strategy}</p>
<ul>
<li>Endpoint rotativo: <code>{base}</code></li>
<li>Sesion sticky: <code>http://{token}:clave@{self.args.bind}:{gport}</code></li>
<li><a href="/get?session={token}">/get?session={token}</a> (enlace magico JSON)</li>
<li><a href="/stats">/stats</a></li>
<li><a href="/proxy.txt">/proxy.txt</a> (lista viva, para OB M2)</li>
<li><a href="/reload">/reload</a></li>
</ul>"""
                ctype = "text/html; charset=utf-8"
            elif path == "/get":
                token = (qs.get("session") or [""])[0] or "s" + secrets_token()
                p = gw_pick_session(self, token)
                if p is None:
                    body = json.dumps({"error": "sin proxies vivos"})
                else:
                    body = json.dumps({
                        "session": token,
                        "gateway": base,
                        "proxy": f"http://{token}:clave@{self.args.bind}:{gport}",
                        "sticky_on": p.tag,
                        "strategy": self.strategy,
                        "alive": len(self.alive_count()),
                        "total": len(self.proxies),
                    }, indent=2)
                ctype = "application/json"
            elif path == "/stats":
                body = json.dumps({
                    "requests": self.stats["requests"],
                    "errors": self.stats["errors"],
                    "bytes_up": self.stats["bytes_up"],
                    "bytes_down": self.stats["bytes_down"],
                    "alive": len(self.alive_count()),
                    "dead": len(self.proxies) - len(self.alive_count()),
                    "total": len(self.proxies),
                    "sessions": len(self.sessions),
                    "strategy": self.strategy,
                    "files": self.files,
                }, indent=2)
                ctype = "application/json"
            elif path == "/proxy.txt":
                fmt = (qs.get("format") or ["plain"])[0]
                lines = [p.ob if fmt == "ob" else p.plain
                         for p in self.alive_count()] or \
                        [p.ob if fmt == "ob" else p.plain for p in self.proxies]
                body = "\n".join(lines) + "\n"
            elif path == "/reload":
                n = self.load_proxies()
                body = json.dumps({"ok": True, "total": len(self.proxies)})
                ctype = "application/json"
            else:
                body = "404 - endpoints: / /get /stats /proxy.txt /reload\n"
                status = "HTTP/1.1 404 Not Found"
                writer.write(f"{status}\r\nContent-Type: {ctype}\r\n"
                             f"Content-Length: {len(body.encode())}\r\n"
                             f"Connection: close\r\n\r\n{body}".encode())
                await writer.drain()
                return
            data = body.encode("utf-8")
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
                         f"Content-Length: {len(data)}\r\n"
                         f"Connection: close\r\n\r\n".encode() + data)
            await writer.drain()
        finally:
            try:
                writer.close()
            except Exception:
                pass


def secrets_token():
    import secrets
    return secrets.token_hex(6)


def gw_pick_session(app, token):
    gw = Gateway(app)
    return gw.pick(token)


# --------------------------------------------------------------- main

async def main_async(args):
    app = App(args)
    if not app.proxies:
        print("ERROR: no se cargo ningun proxy. Ejemplo de linea: 1.2.3.4:8080",
              file=sys.stderr)
        return 2
    gateway = Gateway(app)
    await asyncio.start_server(gateway.handle, args.bind, args.http_port,
                               limit=1 << 20)
    await asyncio.start_server(app.handle_api, args.bind, args.api_port,
                               limit=1 << 20)
    print("=" * 62, flush=True)
    print(" Proxy Gateway listo")
    print(f" Proxies cargados: {len(app.proxies)}")
    print(f" Endpoint (rotacion):  http://{args.bind}:{args.http_port}")
    print(f" API / enlace magico:  http://{args.bind}:{args.api_port}/get?session=MI_SESION")
    print(f" Lista txt viva:       http://{args.bind}:{args.api_port}/proxy.txt")
    print(f" Estrategia: {args.strategy} | health-check cada {args.check_interval}s")
    print("=" * 62, flush=True)

    asyncio.create_task(app.checker_loop())
    await asyncio.Event().wait()
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Gateway local de rotacion de proxies estilo Dataimpulse")
    ap.add_argument("files", nargs="*", help="archivos .txt con proxies (acepta globs)")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--api-port", type=int, default=8081)
    ap.add_argument("--strategy", choices=["round-robin", "random", "sticky"],
                    default="round-robin")
    ap.add_argument("--check-interval", type=int, default=60,
                    help="segundos entre health-checks (0 = off)")
    ap.add_argument("--test-url", default="http://api.ipify.org/",
                    help="URL usada para validar proxies")
    ap.add_argument("--check-now", action="store_true",
                    help="validar una vez y salir")
    ap.add_argument("--quiet", action="store_true", help="no loguea cada peticion")
    args = ap.parse_args()

    if not args.files:
        ap.error("indica al menos un archivo .txt de proxies")

    if args.check_now:
        async def one_check():
            app = App(args)
            await app.run_checks()
            for p in app.proxies:
                print(("OK   " if p.alive else "DEAD ") + p.tag)
        asyncio.run(one_check())
        return 0

    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[gw] detenido")
        return 0


if __name__ == "__main__":
    sys.exit(main())
