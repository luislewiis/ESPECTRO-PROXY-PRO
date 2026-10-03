import asyncio, base64, sys

async def handle(cr, cw):
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 15)
        lines = head.decode("latin-1", "replace").split("\r\n")
        for ln in lines[1:]:
            if ln.lower().startswith("content-length:"):
                n = int(ln.split(":", 1)[1].strip())
                if n > 0:
                    await asyncio.wait_for(cr.readexactly(n), 15)
        want = "basic " + base64.b64encode(
            f"{sys.argv[3]}:{sys.argv[4]}".encode()).decode().lower()
        got = ""
        for ln in lines[1:]:
            if ln.lower().startswith("proxy-authorization:"):
                got = ln.split(":", 1)[1].strip().lower()
        if got != want:
            cw.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                     b"Proxy-Authenticate: Basic realm=\"deep\"\r\n"
                     b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            await cw.drain()
        else:
            body = ("ID:" + sys.argv[2]).encode()
            cw.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + body)
            await cw.drain()
    except Exception:
        pass
    try:
        cw.close()
    except Exception:
        pass

async def main():
    await asyncio.start_server(handle, "127.0.0.1", int(sys.argv[1]))
    print(f"auth-proxy {sys.argv[2]} on {sys.argv[1]}", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
