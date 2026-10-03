import asyncio, sys

async def handle(cr, cw):
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 15)
        lines = head.decode("latin-1", "replace").split("\r\n")
        for ln in lines[1:]:
            if ln.lower().startswith("content-length:"):
                n = int(ln.split(":", 1)[1].strip())
                if n > 0:
                    await asyncio.wait_for(cr.readexactly(n), 15)
        label = sys.argv[2] if len(sys.argv) > 2 else "X"
        body = ("ID:" + label).encode()
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
    port = int(sys.argv[1])
    label = sys.argv[2] if len(sys.argv) > 2 else "X"
    await asyncio.start_server(handle, "127.0.0.1", port)
    print(f"id-proxy {label} on {port}", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
