import asyncio, socket, struct, sys

async def handle(cr, cw):
    try:
        ver, cmd = await cr.readexactly(2)
        port_b = await cr.readexactly(2)
        ip_b = await cr.readexactly(4)
        uid = b""
        while True:
            b = await cr.readexactly(1)
            if b == b"\x00":
                break
            uid += b
        if ip_b[:3] == b"\x00\x00\x00" and ip_b != b"\x00\x00\x00\x00":
            hb = b""
            while True:
                b = await cr.readexactly(1)
                if b == b"\x00":
                    break
                hb += b
            host = hb.decode()
        else:
            host = socket.inet_ntoa(ip_b)
        port = struct.unpack(">H", port_b)[0]
        if ver != 4 or cmd != 1:
            cw.close()
            return
        ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        cw.write(b"\x00\x5a\x00\x00\x00\x00\x00\x00")
        await cw.drain()
    except Exception:
        try:
            cw.write(b"\x00\x5b\x00\x00\x00\x00\x00\x00")
            await cw.drain()
        except Exception:
            pass
        try:
            cw.close()
        except Exception:
            pass
        return

    async def pump(a, b):
        try:
            while True:
                d = await a.read(65536)
                if not d:
                    break
                b.write(d)
                await b.drain()
        except Exception:
            pass
    t1 = asyncio.create_task(pump(cr, uw))
    t2 = asyncio.create_task(pump(ur, cw))
    await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED, timeout=30)
    t1.cancel()
    t2.cancel()
    try:
        cw.close()
        uw.close()
    except Exception:
        pass

async def main():
    await asyncio.start_server(handle, "127.0.0.1", int(sys.argv[1]))
    print(f"socks4 on {sys.argv[1]}", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
