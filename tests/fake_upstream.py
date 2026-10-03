import asyncio, sys, urllib.parse

async def handle(cr, cw):
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 15)
    except Exception:
        cw.close(); return
    lines = head.decode("latin-1", "replace").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 3:
        cw.close(); return
    method, target = parts[0], parts[1]
    try:
        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await cw.drain()
        else:
            u = urllib.parse.urlsplit(target)
            host, port = u.hostname, u.port or 80
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            out = f"{method} {path} HTTP/1.1\r\n"
            for ln in lines[1:]:
                if not ln or ":" not in ln:
                    continue
                k, _, v = ln.partition(":")
                if k.strip().lower() in ("proxy-connection", "connection"):
                    continue
                out += ln + "\r\n"
            out += "\r\n"
            uw.write(out.encode("latin-1"))
            await uw.drain()
    except Exception:
        try:
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await cw.drain()
        except Exception:
            pass
        cw.close(); return

    async def pump(a, b):
        try:
            while True:
                d = await a.read(65536)
                if not d:
                    break
                b.write(d); await b.drain()
        except Exception:
            pass
    t1 = asyncio.create_task(pump(cr, uw))
    t2 = asyncio.create_task(pump(ur, cw))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED, timeout=30)
    t1.cancel(); t2.cancel()
    try:
        cw.close(); uw.close()
    except Exception:
        pass

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19000
    await asyncio.start_server(handle, "127.0.0.1", port)
    print(f"fake upstream http on {port}", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
