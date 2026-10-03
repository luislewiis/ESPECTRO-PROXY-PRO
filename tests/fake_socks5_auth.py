import asyncio, socket, struct, sys

USER = sys.argv[2] if len(sys.argv) > 2 else "u"
PASS = sys.argv[3] if len(sys.argv) > 3 else "p"

async def handle(cr, cw):
    try:
        ver, nm = await cr.readexactly(2)
        methods = await cr.readexactly(nm)
        if ver != 5 or 2 not in methods:
            cw.write(b"\x05\xff")
            await cw.drain()
            cw.close()
            return
        cw.write(b"\x05\x02")
        await cw.drain()
        aver, ulen = await cr.readexactly(2)
        user = (await cr.readexactly(ulen)).decode()
        plen = (await cr.readexactly(1))[0]
        pw = (await cr.readexactly(plen)).decode()
        if aver != 1 or user != USER or pw != PASS:
            cw.write(b"\x01\x01")
            await cw.drain()
            cw.close()
            return
        cw.write(b"\x01\x00")
        await cw.drain()
        ver, cmd, rsv, atyp = await cr.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await cr.readexactly(4))
        elif atyp == 3:
            ln = (await cr.readexactly(1))[0]
            host = (await cr.readexactly(ln)).decode()
        else:
            cw.close()
            return
        port = struct.unpack(">H", await cr.readexactly(2))[0]
        ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        cw.write(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0))
        await cw.drain()
    except Exception:
        try:
            cw.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
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
    print(f"socks5-auth on {sys.argv[1]} user={USER}", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
