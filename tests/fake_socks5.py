import asyncio, socket, struct, sys

async def handle(cr, cw):
    try:
        ver, nm = await cr.readexactly(2)
        await cr.readexactly(nm)
        cw.write(b"\x05\x00"); await cw.drain()
        ver, cmd, rsv, atyp = await cr.readexactly(4)
        if atyp == 1:
            raw = await cr.readexactly(4)
            host = socket.inet_ntoa(raw)
        elif atyp == 3:
            ln = (await cr.readexactly(1))[0]
            host = (await cr.readexactly(ln)).decode()
        elif atyp == 4:
            raw = await cr.readexactly(16)
            host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            cw.close(); return
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
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19001
    await asyncio.start_server(handle, "127.0.0.1", port)
    print(f"fake socks5 on {port}", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
