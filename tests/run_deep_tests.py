import json, os, re, shutil, socket, subprocess, sys, threading, time, urllib.request

TEMP = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GW = os.path.join(os.path.dirname(TEMP), "ProxyGateway.exe")
GW = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GW
WORK = os.path.join(os.environ.get("TEMP", "."), "opencode", "deeptest")
TARGET = "127.0.0.1:18440"
results = []
procs = []

def check(name, cond, detail=""):
    results.append((name, bool(cond), "PASS"))
    print(("PASS " if cond else "FAIL ") + name + (" | " + str(detail)[:250] if detail and not cond else ""))

def skip(name, why):
    results.append((name, True, "SKIP"))
    print("SKIP " + name + " | " + why)

def curl(*args, timeout=15):
    p = subprocess.run(["curl.exe", "-s", "--max-time", str(timeout), "--noproxy", "", *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout

def curl_code(*args, timeout=15):
    p = subprocess.run(["curl.exe", "-s", "--max-time", str(timeout), "--noproxy", "",
                        "-w", "\n%{http_code}", *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = p.stdout.rsplit("\n", 1)
    return (out[1].strip() if len(out) > 1 else ""), (out[0] if out else "")

def raw(port, payload, timeout=8):
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    if isinstance(payload, str):
        payload = payload.encode()
    s.sendall(payload)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    s.close()
    return data.decode("latin-1", "replace")

def raw_shut(port, payload, timeout=8):
    # igual que raw() pero cierra el lado de escritura tras enviar
    # (fin de stream): el servidor resuelve con EOF en vez de esperar
    # mas datos (obligatorio para probar rechazos tras el cuerpo)
    s = socket.create_connection(("127.0.0.1", port), timeout)
    s.settimeout(timeout)
    if isinstance(payload, str):
        payload = payload.encode()
    s.sendall(payload)
    s.shutdown(socket.SHUT_WR)
    data = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            data += b
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    s.close()
    return data.decode("latin-1", "replace")

def start_helper(script, *args):
    p = subprocess.Popen([sys.executable, os.path.join(TEMP, script), *args],
                         cwd=TEMP, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    return p

def start_gw(listfile, http_port, api_port, *extra, stdout=None):
    cmd = [GW, listfile, "--http-port", str(http_port), "--api-port", str(api_port),
           "--check-interval", "0", "--test-url", "http://" + TARGET + "/",
           "--no-browser", "--no-state"]
    cmd += list(extra)
    out = stdout if stdout else subprocess.DEVNULL
    p = subprocess.Popen(cmd, cwd=TEMP, stdout=out, stderr=out)
    procs.append(p)
    return p

def start_cli(listfile, *extra, stdout_file, stderr_file):
    fo = open(stdout_file, "w")
    fe = open(stderr_file, "w")
    p = subprocess.Popen([GW, listfile, "--no-state", *extra], cwd=TEMP, stdout=fo, stderr=fe)
    procs.append(p)
    return p, fo, fe

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def api(port, path):
    with OPENER.open("http://127.0.0.1:%d%s" % (port, path), timeout=10) as r:
        return json.loads(r.read().decode())

def api_wait(port, tries=40):
    for _ in range(tries):
        try:
            api(port, "/stats")
            return True
        except Exception:
            time.sleep(0.25)
    return False

def wait_cond(fn, timeout=6, step=0.25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False

def wait_alive(api_port, want=True, timeout=7):
    t0 = time.time()
    while time.time() - t0 < timeout:
        curl("-X", "POST", "-H", "X-GW-Panel: 1", "http://127.0.0.1:%d/check" % api_port)
        try:
            if api(api_port, "/proxies")[0]["alive"] is want:
                return True
        except Exception:
            pass
        time.sleep(0.4)
    return False

def tags_of(px):
    return [(p["scheme"], p["host"], p["port"], p["alive"], p["fails"]) for p in px]

def write(name, content):
    path = os.path.join(WORK, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    return path

try:
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)

    P_ID_A, P_ID_B = 18450, 18451
    P_DEAD, P_ID_C = 18498, 18452
    P_X, P_Y = 18453, 18454
    P_TUNNEL = 18455
    P_REV = 18456
    P_S4, P_S5A, P_AUTH = 18457, 18458, 18459

    l_gwa = write("gwa.txt", f"127.0.0.1:{P_ID_A}\n127.0.0.1:{P_ID_B}\n")
    l_gwb = write("gwb.txt", f"127.0.0.1:{P_DEAD}\n127.0.0.1:{P_ID_C}\n")
    l_gwc = write("gwc.txt", f"127.0.0.1:{P_X}\n127.0.0.1:{P_Y}\n")
    l_gwd = write("gwd.txt", f"127.0.0.1:{P_TUNNEL}\n")
    l_gwe = write("gwe.txt", "# sin proxies\n")
    l_gwf = write("gwf.txt", f"127.0.0.1:{P_REV}\n")
    l_gws4 = write("up_socks4.txt", f"127.0.0.1:{P_S4}\n")
    l_gws5a = write("up_socks5.txt", f"u:p@127.0.0.1:{P_S5A}\n")
    l_gwauth = write("gwauth.txt", f"au:ap@127.0.0.1:{P_AUTH}\n")
    l_gwwin = write("gwwin.txt", f"127.0.0.1:{P_ID_A}\n")
    l_cli = write("cli.txt", f"127.0.0.1:{P_ID_A}\n127.0.0.1:{P_DEAD}\n")

    start_helper("target_srv.py", "18440")
    start_helper("tls_srv.py", "18441")
    start_helper("fake_id_proxy.py", str(P_ID_A), "A")
    start_helper("fake_id_proxy.py", str(P_ID_B), "B")
    start_helper("fake_id_proxy.py", str(P_ID_C), "C")
    start_helper("fake_id_proxy.py", str(P_X), "X")
    start_helper("fake_id_proxy.py", str(P_Y), "Y")
    start_helper("fake_upstream.py", str(P_TUNNEL))
    start_helper("fake_socks4.py", str(P_S4))
    start_helper("fake_socks5_auth.py", str(P_S5A), "u", "p")
    start_helper("fake_auth_proxy.py", str(P_AUTH), "auth", "au", "ap")

    gwa = start_gw(l_gwa, 18430, 18431)
    start_gw(l_gwb, 18432, 18433)
    start_gw(l_gwc, 18434, 18435)
    start_gw(l_gwd, 18436, 18437)
    start_gw(l_gwe, 18438, 18439)
    start_gw(l_gwf, 18442, 18443)
    start_gw(l_gws4, 18444, 18445)
    start_gw(l_gws5a, 18446, 18447)
    start_gw(l_gwauth, 18448, 18449)

    apis = [18431, 18433, 18435, 18437, 18439, 18443, 18445, 18447, 18449]
    ready = all([api_wait(p) for p in apis])
    check("arranque: 9 gateways con API viva", ready, apis)

    # ---------------- S1: estrategias (GWA 18430/18431)
    bodies = []
    for i in range(6):
        rc, out = curl("-x", "http://127.0.0.1:18430", f"http://{TARGET}/?r={i}")
        bodies.append(out.strip())
    a_cnt = sum(1 for b in bodies if b == "ID:A")
    b_cnt = sum(1 for b in bodies if b == "ID:B")
    check("S1 round-robin exacto A=3 B=3", a_cnt == 3 and b_cnt == 3, bodies)

    rc, out = curl("-X", "POST", "-H", "X-GW-Panel: 1",
                   "http://127.0.0.1:18431/set-strategy?strategy=random")
    check("S1 set-strategy random ok", '"ok":true' in out, out)
    seen, bad = set(), 0
    for i in range(30):
        rc, out = curl("-x", "http://127.0.0.1:18430", f"http://{TARGET}/?x={i}")
        if out.strip() in ("ID:A", "ID:B"):
            seen.add(out.strip())
        else:
            bad += 1
    check("S1 random: 30 req, ambos upstreams, 0 fallos", len(seen) == 2 and bad == 0, seen)

    rc, out = curl("-X", "POST", "-H", "X-GW-Panel: 1",
                   "http://127.0.0.1:18431/set-strategy?strategy=sticky")
    check("S1 set-strategy sticky ok", '"ok":true' in out, out)
    rc, out = curl("http://127.0.0.1:18431/get?session=deep1")
    try:
        j = json.loads(out)
        check("S1 /get sticky_on asignado", j.get("session") == "deep1" and "sticky_on" in j, out)
    except Exception:
        j = None
        check("S1 /get sticky_on asignado", False, out)
    sticky_ids = []
    for i in range(5):
        rc, out = curl("-x", "http://deep1:x@127.0.0.1:18430", f"http://{TARGET}/?s={i}")
        sticky_ids.append(out.strip())
    check("S1 sticky: 5 req mismo upstream", len(set(sticky_ids)) == 1 and sticky_ids[0] in ("ID:A", "ID:B"), sticky_ids)

    code, body = curl_code("-X", "POST", "-H", "X-GW-Panel: 1",
                           "http://127.0.0.1:18431/set-strategy?strategy=loco")
    check("S1 set-strategy invalida -> 400", code == "400" and "estrategia invalida" in body, code + " " + body)
    code, body = curl_code("-X", "GET", "http://127.0.0.1:18431/reload")
    check("S1 /reload GET -> 405", code == "405", code + " " + body[:60])
    code, body = curl_code("-X", "POST", "http://127.0.0.1:18431/reload")
    check("S1 /reload sin cabecera -> 403", code == "403", code + " " + body[:60])
    st = api(18431, "/stats")
    check("S1 stats.strategy=sticky", st["strategy"] == "sticky", st["strategy"])
    # El banner informativo vive DENTRO del panel (seccion "Info de arranque")
    check("S1 stats expone check_itv y state_file (para el panel)",
          "check_itv" in st and "state_file" in st, str(st)[:220])
    boot_out = os.path.join(WORK, "boot_banner.out")
    with open(boot_out, "w", encoding="utf-8") as bf:
        start_gw(l_gwa, 18470, 18471, stdout=bf)
    if api_wait(18471):
        time.sleep(0.3)
        with open(boot_out, encoding="utf-8", errors="replace") as bf:
            boot_txt = bf.read()
        check("S1 consola sin banner (va dentro del panel)",
              "ESPECTRO PROXY PRO listo" not in boot_txt and "[gw] panel:" in boot_txt,
              boot_txt[:200].replace("\n", " | "))
    else:
        check("S1 consola sin banner (va dentro del panel)", False, "gateway 18471 no arranco")

    # ---------------- S2: API sesiones/logs (GWA)
    rc, out1 = curl("http://127.0.0.1:18431/get")
    rc, out2 = curl("http://127.0.0.1:18431/get")
    try:
        t1, t2 = json.loads(out1)["session"], json.loads(out2)["session"]
        check("S2 /get genera tokens aleatorios distintos",
              re.fullmatch(r"s[0-9a-f]{16}", t1) and t1 != t2, t1 + " " + t2)
    except Exception:
        check("S2 /get genera tokens aleatorios distintos", False, out1 + out2)
    st = api(18431, "/stats")
    check("S2 stats.sessions>=3", st["sessions"] >= 3, st["sessions"])
    lg = api(18431, "/logs")
    check("S2 /logs con lineas [gw]", isinstance(lg.get("lines"), list) and any("[gw]" in l for l in lg["lines"]), str(lg)[:150])

    # ---------------- S3: markFail y muerte (GWB 18432/18433)
    rc, out = curl("-x", "http://127.0.0.1:18432", f"http://{TARGET}/?m=1")
    check("S3 req1: falla dead y responde C", out.strip() == "ID:C", out)
    px = api(18433, "/proxies")
    dead = [p for p in px if p["port"] == P_DEAD][0]
    c1 = [p for p in px if p["port"] == P_ID_C][0]
    check("S3 tras 1 fallo: dead sigue vivo con fails=1", dead["alive"] and dead["fails"] == 1, dead)

    dead_marked = False
    for i in range(8):
        curl("-x", "http://127.0.0.1:18432", f"http://{TARGET}/?m={i+2}")
        px = api(18433, "/proxies")
        dead = [p for p in px if p["port"] == P_DEAD][0]
        if not dead["alive"]:
            dead_marked = True
            break
    check("S3 dead marcado muerto a los 3 fallos", dead_marked and dead["fails"] >= 3, dead)

    oks = []
    for i in range(4):
        rc, out = curl("-x", "http://127.0.0.1:18432", f"http://{TARGET}/?m={i+5}")
        oks.append(out.strip() == "ID:C")
    check("S3 tras muerte: 4 req seguidas OK via C", all(oks), oks)

    rc, out = curl("http://127.0.0.1:18433/proxy.txt")
    check("S3 /proxy.txt solo vivos (C)", "127.0.0.1:%d" % P_ID_C in out.split() and "127.0.0.1:%d" % P_DEAD not in out.split(), out)

    c_proc = [p for p in procs if p.args and str(P_ID_C) in [str(x) for x in p.args]]
    if c_proc:
        c_proc[0].kill()
        c_proc[0].wait()
    last = ""
    for i in range(3):
        last = raw(18432, f"GET http://{TARGET}/ HTTP/1.1\r\nHost: {TARGET}\r\n\r\n")
    check("S3 todos los upstreams caidos -> 502", last.startswith("HTTP/1.1 502"), last[:80])
    st = api(18433, "/stats")
    check("S3 stats.errors>=1", st["errors"] >= 1, st["errors"])
    rc, out = curl("http://127.0.0.1:18433/proxy.txt")
    check("S3 /proxy.txt fallback con todos muertos", "127.0.0.1:%d" % P_DEAD in out.split() and "127.0.0.1:%d" % P_ID_C in out.split(), out)

    # ---------------- S4: sticky reasignacion (GWC 18434/18435)
    rc, out = curl("http://127.0.0.1:18435/get?session=sx")
    try:
        j = json.loads(out)
        check("S4 sesion inicial -> X", j.get("sticky_on", "").endswith(":%d" % P_X), out)
    except Exception:
        check("S4 sesion inicial -> X", False, out)
    ids = []
    for i in range(3):
        rc, out = curl("-x", "http://sx:x@127.0.0.1:18434", f"http://{TARGET}/?z={i}")
        ids.append(out.strip())
    check("S4 3 req pegadas a X", ids == ["ID:X"] * 3, ids)

    x_proc = [p for p in procs if p.args and str(P_X) in [str(x) for x in p.args]]
    if x_proc:
        x_proc[0].kill()
        x_proc[0].wait()
    rc, out = curl("-x", "http://sx:x@127.0.0.1:18434", f"http://{TARGET}/?z=9")
    check("S4 tras matar X: sesion reasigna a Y", out.strip() == "ID:Y", out)
    rc, out = curl("-x", "http://sx:x@127.0.0.1:18434", f"http://{TARGET}/?z=10")
    check("S4 sesion estable en Y", out.strip() == "ID:Y", out)
    px = api(18435, "/proxies")
    xp = [p for p in px if p["port"] == P_X][0]
    check("S4 X con fails registrado", xp["fails"] >= 1, xp)

    # ---------------- S5: gateway HTTP edge (GWD 18436/18437)
    rc, out = curl("-x", "http://127.0.0.1:18436", f"http://{TARGET}/")
    check("S5 GET basico", out.strip() == "PROXY-GATEWAY-OK", out)
    rc, out = curl("-x", "http://127.0.0.1:18436", "-d", "hola=mundo", "-H", "X-Test: deep",
                   f"http://{TARGET}/")
    check("S5 POST echo", "POST-ECHO:hola=mundo:H=deep" in out, out)

    chunked = (f"POST / HTTP/1.1\r\nHost: {TARGET}\r\nTransfer-Encoding: chunked\r\n\r\n"
               "4\r\nhola\r\n6\r\n mundo\r\n0\r\n\r\n")
    resp = raw(18436, chunked)
    check("S5 body chunked reconstruido", "POST-ECHO:hola mundo" in resp, resp[:200])

    resp = raw(18436, f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nContent-Length: abc\r\n\r\n")
    check("S5 content-length invalido -> 400", "400 Bad Request" in resp, resp[:80])
    resp = raw(18436, "GET / HTTP/1.1\r\n\r\n")
    check("S5 sin Host -> 400", "400 Bad Request" in resp, resp[:80])

    rc, out = curl("-X", "PUT", "-d", "x", "-x", "http://127.0.0.1:18436", f"http://{TARGET}/")
    check("S5 metodo PUT retransmitido (501)", "501" in out, out[:80])

    big = "GET / HTTP/1.1\r\nHost: x\r\n" + "".join("X-P%d: %s\r\n" % (i, "a" * 5000) for i in range(120))
    resp = raw(18436, big + "\r\n", timeout=10)
    st = api(18437, "/stats")
    check("S5 cabecera 600KB (sobre limite) cierra sin romper", resp == "" and st["total"] == 1, "resp_len=%d" % len(resp))

    st0 = api(18437, "/stats")
    rc, out = curl("-x", "http://127.0.0.1:18436", f"http://{TARGET}/big")
    st1 = api(18437, "/stats")
    check("S5 descarga 50KB + bytes_down", len(out) == 50000 and st1["bytes_down"] - st0["bytes_down"] >= 50000,
          "len=%d delta=%d" % (len(out), st1["bytes_down"] - st0["bytes_down"]))

    rc, out = curl("--proxytunnel", "-x", "http://127.0.0.1:18436", f"http://{TARGET}/")
    check("S5 CONNECT/tunel http", out.strip() == "PROXY-GATEWAY-OK", out)

    rc, out = curl("-k", "-x", "http://127.0.0.1:18436", "https://127.0.0.1:18441/")
    check("S5 TLS end-to-end via CONNECT", out.strip() == "TLS-OK", out)

    st0 = api(18437, "/stats")
    codes = []
    lock = threading.Lock()
    def hit(i):
        rc, out = curl("-x", "http://127.0.0.1:18436", f"http://{TARGET}/?c={i}", timeout=20)
        with lock:
            codes.append(out.strip() == "PROXY-GATEWAY-OK")
    ts = [threading.Thread(target=hit, args=(i,)) for i in range(50)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    st1 = api(18437, "/stats")
    check("S5 50 peticiones concurrentes todas OK", sum(codes) == 50, sum(codes))
    check("S5 stats.requests crece >=50", st1["requests"] - st0["requests"] >= 50,
          st1["requests"] - st0["requests"])

    rc, out = curl("-x", "http://127.0.0.1:18436", "https://api.ipify.org/", timeout=12)
    if rc == 0 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", out.strip()):
        check("S5 red externa https via gateway", True, out.strip())
    else:
        skip("S5 red externa https via gateway", "sin conectividad rc=%d" % rc)

    # ---------------- S6: cero proxies (GWE 18438/18439)
    rc, out = curl("http://127.0.0.1:18439/get?session=vacio")
    check("S6 /get sin proxies -> error", "sin proxies vivos" in out, out)
    rc, out = curl("http://127.0.0.1:18439/proxy.txt")
    check("S6 /proxy.txt vacio", out.strip() == "", repr(out[:50]))
    resp = raw(18438, f"GET http://{TARGET}/ HTTP/1.1\r\nHost: {TARGET}\r\n\r\n")
    check("S6 gateway sin proxies -> 502", resp.startswith("HTTP/1.1 502"), resp[:60])
    st = api(18439, "/stats")
    check("S6 stats total=0", st["total"] == 0, st["total"])

    # ---------------- S7: health-check (GWF 18442/18443)
    px = api(18443, "/proxies")
    check("S7 arranca con Alive=true default", px[0]["alive"], px[0])
    ok = wait_alive(18443, want=False)
    check("S7 /check marca muerto el upstream caido", ok, api(18443, "/proxies"))
    rev = start_helper("fake_id_proxy.py", str(P_REV), "R")
    ok = wait_alive(18443, want=True)
    check("S7 /check revive el upstream", ok, api(18443, "/proxies"))
    lg = api(18443, "/logs")
    joined = " ".join(lg["lines"])
    check("S7 logs con muerto/revivido/health-check",
          "health-check" in joined and ("revivido" in joined or "muerto" in joined), joined[-300:])

    # ---------------- S8: protocolos end-to-end
    rc, out = curl("-x", "http://127.0.0.1:18444", f"http://{TARGET}/")
    check("S8 socks4 GET via gateway", out.strip() == "PROXY-GATEWAY-OK", out)
    rc, out = curl("--proxytunnel", "-x", "http://127.0.0.1:18444", f"http://{TARGET}/")
    check("S8 socks4 CONNECT/tunel", out.strip() == "PROXY-GATEWAY-OK", out)
    ok = wait_alive(18445, want=True)
    check("S8 socks4 health-check vivo", ok, api(18445, "/proxies"))

    rc, out = curl("-x", "http://127.0.0.1:18446", f"http://{TARGET}/")
    check("S8 socks5+auth GET via gateway", out.strip() == "PROXY-GATEWAY-OK", out)
    ok = wait_alive(18447, want=True)
    check("S8 socks5+auth health-check vivo", ok, api(18447, "/proxies"))

    rc, out = curl("-x", "http://127.0.0.1:18448", f"http://{TARGET}/")
    check("S8 http+auth GET via gateway", out.strip() == "ID:auth", out)
    ok = wait_alive(18449, want=True)
    check("S8 http+auth health-check vivo", ok, api(18449, "/proxies"))
    resp = raw(P_AUTH, f"GET http://{TARGET}/ HTTP/1.1\r\nHost: {TARGET}\r\n\r\n")
    check("S8 upstream http exige auth -> 407", "407" in resp, resp[:60])

    # ---------------- S9: validacion/importacion profunda (GWA api)
    val_text = ("﻿1.2.3.4:8080\n"
                "5.6.7.8:8080\r\n"
                "\n"
                "# comentario\n"
                "u:p@9.9.9.9:8081\n"
                "1.1.1.1:8082:admin:pw\n"
                "0:2.2.2.2:8083::\n"
                "https://3.3.3.3\n"
                "socks5://4.4.4.4\n"
                "7.7.7.7:65535\n"
                "7.7.7.8:65536\n"
                "7.7.7.9:0\n"
                "[::1]:8080\n"
                ":8080\n"
                "ftp://1.2.3.4:21\n"
                "basura!!\n"
                "8.8.8.8:8080\n"
                "8.8.8.8:8080\n")
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"text": val_text}), "http://127.0.0.1:18431/validate")
    try:
        v = json.loads(out)
        ok = (v["valid"] == 10 and v["invalid_total"] == 5 and v["duplicates"] == 1
              and v["ignored"] == 3
              and v["protocols"].get("http") == 9 and v["protocols"].get("socks5") == 1)
        check("S9 /validate edge: 10v/5i/1d/3ign", ok, out[:400])
        reasons = {i["text"]: i["reason"] for i in v["invalid"]}
        check("S9 invalidos correctos (:8080, BOM, ftp...)",
              ":8080" in reasons and "ftp://1.2.3.4:21" in reasons and "7.7.7.8:65536" in reasons,
              json.dumps(reasons, ensure_ascii=False)[:300])
    except Exception:
        check("S9 /validate edge: 10v/5i/1d/3ign", False, out[:400])
        check("S9 invalidos correctos (:8080, BOM, ftp...)", False, out[:200])

    with open(os.path.join(WORK, "parity_in.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(val_text)
    panel_html = os.path.join(os.path.dirname(TEMP), "panel.html")
    html = open(panel_html, encoding="utf-8").read()
    s0 = html.rfind("\n", 0, html.index("const SCHEMES")) + 1
    e0 = html.index("function protoChips")
    js_path = os.path.join(os.environ["TEMP"], "opencode", "panel_js.js")
    os.makedirs(os.path.dirname(js_path), exist_ok=True)
    with open(js_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(html[s0:e0])
    js_parity = subprocess.run(
        ["node", "-e",
         "const fs=require('fs');let src=fs.readFileSync(process.argv[1],'utf8');"
         "const s=src.indexOf('const SCHEMES'),e=src.indexOf('function protoChips');"
         "let proxyData=[];eval(src.slice(s,e));"
         "const t=fs.readFileSync(process.argv[2],'utf8');"
         "const r=validateBatch(t);"
         "console.log(JSON.stringify({v:r.valid.length,i:r.invalid.length,d:r.duplicates,g:r.ignored}));",
         js_path,
         os.path.join(WORK, "parity_in.txt")],
        capture_output=True, text=True)
    try:
        pj = json.loads(js_parity.stdout.strip().splitlines()[-1])
        check("S9 paridad Go==JS (10/5/1/3)", pj == {"v": 10, "i": 5, "d": 1, "g": 3},
              js_parity.stdout + js_parity.stderr[:200])
    except Exception:
        check("S9 paridad Go==JS (10/5/1/3)", False, js_parity.stdout + js_parity.stderr[:300])

    code, body = curl_code("-X", "GET", "http://127.0.0.1:18431/validate")
    check("S9 /validate GET -> 405", code == "405", code + " " + body[:60])
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"path": "no_existe_archivo.txt"}),
                   "http://127.0.0.1:18431/validate")
    check("S9 /validate path inexistente -> error", '"ok":false' in out and "no se pudo abrir" in out, out)
    fake_exe = os.path.join(WORK, "malware.exe")
    open(fake_exe, "wb").write(b"MZ")
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"path": fake_exe}), "http://127.0.0.1:18431/validate")
    check("S9 /validate extension .exe rechazada", "extension no permitida" in out, out)
    big_path = os.path.join(WORK, "grande.txt")
    with open(big_path, "w") as f:
        f.write("10.0.0.1:8080\n" * 400000)
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"path": big_path}), "http://127.0.0.1:18431/validate")
    check("S9 /validate archivo >5MB rechazado", "5 MB" in out, out[:150])
    os.remove(big_path)

    # jaula de rutas: archivo .txt valido pero fuera de cwd/exe/listas
    jail_path = os.path.join(os.environ.get("LOCALAPPDATA", os.environ["TEMP"]), "pg_jail_test.txt")
    with open(jail_path, "w") as f:
        f.write("1.2.3.4:8080\n")
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"path": jail_path}), "http://127.0.0.1:18431/validate")
    check("S9 /validate ruta fuera de jaula -> acceso denegado", "acceso denegado" in out, out[:200])
    os.remove(jail_path)

    bom_text = "﻿20.20.20.20:8080"
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"text": bom_text, "name": "bom_test.txt"}),
                   "http://127.0.0.1:18431/import")
    px = api(18431, "/proxies")
    hosts = [p["host"] for p in px]
    check("S9 import BOM: host limpio (sin \\ufeff)", "20.20.20.20" in hosts
          and all(not h.startswith("﻿") for h in hosts), hosts[-3:])

    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"text": "99.99.99.99:9999", "name": "http_prueba.txt"}),
                   "http://127.0.0.1:18431/import")
    try:
        r = json.loads(out)
        check("S9 /import name=http_* -> esquema http",
              r.get("ok") and r.get("protocols", {}).get("http") == 1, out)
    except Exception:
        check("S9 /import name=http_* -> esquema http", False, out)

    t0 = time.time()
    big_lines = "\n".join("10.0.%d.%d:%d" % (i // 256, i % 256, i + 1) for i in range(5000))
    big_body = os.path.join(WORK, "big_import.json")
    with open(big_body, "w", encoding="utf-8") as f:
        json.dump({"text": big_lines, "name": "grande_5k.txt"}, f)
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", "@" + big_body,
                   "http://127.0.0.1:18431/import", timeout=30)
    dt = time.time() - t0
    try:
        r = json.loads(out)
        st = api(18431, "/stats")
        check("S9 /import 5000 lineas <8s", r.get("valid") == 5000 and dt < 8 and st["total"] >= 5000,
              "valid=%s dt=%.1fs total=%d" % (r.get("valid"), dt, st["total"]))
    except Exception:
        check("S9 /import 5000 lineas <8s", False, out[:200])

    with open(l_gwb, "a") as f:
        pass
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json",
                   "-d", json.dumps({"text": "127.0.0.1:%d" % P_ID_C}),
                   "http://127.0.0.1:18433/import")
    check("S9 /import solo duplicados -> ok:false", '"ok":false' in out and "ninguna linea valida" in out, out[:200])
    px = api(18433, "/proxies")
    dead = [p for p in px if p["port"] == P_DEAD][0]
    check("S9 reload preserva estado muerto", not dead["alive"], dead)

    # ---------------- S10: CLI
    p, fo, fe = start_cli(l_gwa, "--strategy", "loco", "--no-browser",
                          stdout_file=os.path.join(WORK, "cli1.out"),
                          stderr_file=os.path.join(WORK, "cli1.err"))
    p.wait(timeout=10)
    err = open(os.path.join(WORK, "cli1.err")).read()
    fo.close(); fe.close()
    check("S10 --strategy invalida exit 2", p.returncode == 2 and "--strategy" in err, "rc=%s err=%s" % (p.returncode, err[:100]))

    p, fo, fe = start_cli(l_gwa, "--http-port", "18430", "--api-port", "18468", "--no-browser",
                          stdout_file=os.path.join(WORK, "cli2.out"),
                          stderr_file=os.path.join(WORK, "cli2.err"))
    p.wait(timeout=10)
    err = open(os.path.join(WORK, "cli2.err")).read()
    fo.close(); fe.close()
    check("S10 puerto ocupado exit 1", p.returncode == 1 and "ya hay otra instancia" in err, "rc=%s" % p.returncode)

    p, fo, fe = start_cli(l_cli, "--check-now", "--test-url", "http://" + TARGET + "/",
                          stdout_file=os.path.join(WORK, "cli3.out"),
                          stderr_file=os.path.join(WORK, "cli3.err"))
    p.wait(timeout=20)
    out = open(os.path.join(WORK, "cli3.out")).read()
    fo.close(); fe.close()
    check("S10 --check-now imprime OK y DEAD, exit 0",
          p.returncode == 0 and "OK   http://127.0.0.1:%d" % P_ID_A in out
          and "DEAD http://127.0.0.1:%d" % P_DEAD in out,
          "rc=%s out=%s" % (p.returncode, out[:200]))

    gdir = os.path.join(WORK, "lists")
    os.makedirs(gdir, exist_ok=True)
    with open(os.path.join(gdir, "a.txt"), "w") as f:
        f.write("10.1.1.1:1080\n10.1.1.2:1080\n")
    with open(os.path.join(gdir, "b.txt"), "w") as f:
        f.write("10.1.1.3:1080\n10.1.1.4:1080\n10.1.1.5:1080\n")
    gp = start_gw(os.path.join(gdir, "*.txt"), 18466, 18467)
    ok = wait_cond(lambda: api(18467, "/stats")["total"] == 5, timeout=6)
    check("S10 glob *.txt expande 2 archivos (5 proxies)", ok, "no llego a 5")
    gp.kill(); gp.wait()

    sdir = os.path.join(WORK, "standalone")
    os.makedirs(sdir, exist_ok=True)
    exe_copy = os.path.join(sdir, "ProxyGateway.exe")
    shutil.copy(GW, exe_copy)
    sout = open(os.path.join(sdir, "run.out"), "w")
    sp = subprocess.Popen([exe_copy, "--http-port", "18468", "--api-port", "18469",
                           "--no-browser", "--no-state"],
                          cwd=sdir, stdout=sout, stderr=sout)
    procs.append(sp)
    time.sleep(1.8)
    sout.close()
    txt = open(os.path.join(sdir, "run.out")).read()
    check("S10 primera ejecucion crea plantilla",
          "primera ejecucion" in txt and "0 proxies cargados" in txt, txt[:250])
    sp.kill(); sp.wait()

    p, fo, fe = start_cli(l_gwe, "--check-now",
                          stdout_file=os.path.join(WORK, "cli4.out"),
                          stderr_file=os.path.join(WORK, "cli4.err"))
    p.wait(timeout=10)
    err = open(os.path.join(WORK, "cli4.err")).read()
    fo.close(); fe.close()
    check("S10 --check-now con lista vacia exit 2", p.returncode == 2 and "no se cargo ningun proxy" in err,
          "rc=%s" % p.returncode)

    # ---------------- S11: ventana WebView2
    ps1 = os.path.join(TEMP, "window_test.ps1")
    pr = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                         "-File", ps1, "-Exe", GW, "-ListFile", l_gwwin,
                         "-HttpPort", "18462", "-ApiPort", "18463"],
                        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    wout = pr.stdout + pr.stderr
    check("S11 ventana: abrir, cerrar limpio y --no-browser", pr.returncode == 0, wout[:600])

    # ---------------- S12: gestor de la lista (/proxy-remove, /proxy-edit)
    code, body = curl_code("-X", "GET", "http://127.0.0.1:18431/proxy-remove")
    check("S12 /proxy-remove GET -> 405", code == "405", code + " " + body[:60])
    code, body = curl_code("-X", "POST", "-d", '{"scope":"all"}', "http://127.0.0.1:18431/proxy-remove")
    check("S12 /proxy-remove sin cabecera panel -> 403", code == "403", code + " " + body[:60])
    code, body = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d", '{"scope":"loco"}',
                           "http://127.0.0.1:18431/proxy-remove")
    check("S12 scope desconocido -> 400", code == "400" and "scope" in body, code + " " + body[:80])
    code, body = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d", "{}",
                           "http://127.0.0.1:18431/proxy-remove")
    check("S12 sin keys ni scope -> 400", code == "400" and "keys" in body, code + " " + body[:80])
    code, body = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d", "no-json",
                           "http://127.0.0.1:18431/proxy-remove")
    check("S12 payload no-JSON -> 400", code == "400", code + " " + body[:60])

    px = api(18431, "/proxies")
    check("S12 /proxies expone key por proxy", len(px) > 0 and all("key" in p and "|" in p["key"] for p in px),
          str(px[:1]))
    total0 = api(18431, "/stats")["total"]
    saved_gwa = open(l_gwa, encoding="utf-8").read()

    rc, out = curl("-X", "POST", "-H", "X-GW-Panel: 1", "-d", '{"scope":"all"}',
                   "http://127.0.0.1:18431/proxy-remove")
    j = json.loads(out)
    check("S12 vaciar todo: SOLO memoria (removed==total, files [], persist false)",
          j.get("ok") and j.get("removed") == total0 and j.get("total") == 0
          and len(j.get("files") or []) == 0 and j.get("persist") is False, out[:220])
    check("S12 vaciar todo NO reescribe el .txt (fuente intacta byte a byte)",
          open(l_gwa, encoding="utf-8").read() == saved_gwa,
          repr(open(l_gwa, encoding="utf-8").read()[:80]))

    code, body = curl_code("-X", "POST", "-H", "X-GW-Panel: 1",
                           "-d", json.dumps({"key": "http|1.1.1.1|8080|", "line": "1.1.1.1:9"}),
                           "http://127.0.0.1:18431/proxy-edit")
    check("S12 /proxy-edit con lista vacia -> 400 no encontrado", code == "400" and "no encontrado" in body,
          code + " " + body[:100])

    curl("-X", "POST", "-H", "X-GW-Panel: 1", "http://127.0.0.1:18431/reload")
    n_reload = api(18431, "/stats")["total"]
    check("S12 /reload REHABILITA la lista desde el .txt (la fuente manda)",
          n_reload == total0, str(n_reload))

    px = api(18431, "/proxies")
    k0 = px[0]["key"]
    rc, out = curl("-X", "POST", "-H", "X-GW-Panel: 1", "-d",
                   json.dumps({"key": k0, "line": "9.9.9.9:9999"}),
                   "http://127.0.0.1:18431/proxy-edit")
    j = json.loads(out)
    check("S12 /proxy-edit cambia host y clave", j.get("ok") and j.get("key") == "http|9.9.9.9|9999|",
          out[:200])

    code, body = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d",
                           json.dumps({"key": "http|9.9.9.9|9999|", "line": "???"}),
                           "http://127.0.0.1:18431/proxy-edit")
    check("S12 /proxy-edit linea invalida -> 400", code == "400" and "invalida" in body,
          code + " " + body[:100])

    curl("-X", "POST", "-H", "X-GW-Panel: 1", "http://127.0.0.1:18431/reload")
    px12 = api(18431, "/proxies")
    old_host, old_port = k0.split("|")[1], int(k0.split("|")[2])
    nuevo = [(p["host"], p["port"]) for p in px12 if p["host"] == "9.9.9.9" and p["port"] == 9999]
    viejo = [(p["host"], p["port"]) for p in px12 if p["host"] == old_host and p["port"] == old_port]
    check("S12 la edicion sobrevive a /reload", len(nuevo) == 1 and len(viejo) == 0
          and "9.9.9.9:9999" in open(l_gwa, encoding="utf-8").read(),
          "nuevo=%s viejo=%s" % (nuevo, viejo))

    rc, out = curl("http://127.0.0.1:18431/")
    check("S12 pagina / (API): marca + tema oscuro + gestor",
          "ESPECTRO PROXY PRO" in out and "#0b0f1a" in out and "/proxy-remove" in out
          and "Volver al panel" in out and "estilo Dataimpulse" not in out, out[:200])

    # ---------------- S13: consola exclusiva se cierra con --window
    s13list = os.path.join(WORK, "s13.txt")
    with open(s13list, "w", encoding="utf-8") as f:
        f.write("10.9.9.1:8080\n10.9.9.2:8080\n")

    # a) estilo doble-click: consola EXCLUSIVA (CREATE_NEW_CONSOLE, sin
    #    redireccion) -> FreeConsole debe ejecutarse y quedar constancia
    #    en la pestaña Log del panel.
    s13 = subprocess.Popen(
        [GW, s13list, "--http-port", "18480", "--api-port", "18481",
         "--check-interval", "0", "--no-state", "--window"],
        cwd=WORK, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
    procs.append(s13)
    logs13, ok13 = [], False
    for _ in range(40):
        time.sleep(0.5)
        try:
            rc, out = curl("http://127.0.0.1:18481/logs", timeout=3)
            logs13 = json.loads(out).get("lines", [])
        except Exception:
            continue
        if any("consola propia cerrada" in l for l in logs13):
            ok13 = True
            break
    tail13 = "; ".join(logs13)[-300:]
    check("S13 doble-click: consola propia cerrada (FreeConsole)", ok13, tail13)
    check("S13 decide 'se cerrara al crearse' antes de abrir la ventana",
          any("la consola terminal se cerrara al crearse" in l for l in logs13), tail13)
    alive13 = s13.poll() is None
    try:
        rc13, _ = curl_code("http://127.0.0.1:18481/stats")
    except Exception:
        rc13 = "?"
    check("S13 sigue vivo y con API tras cerrar la consola",
          alive13 and rc13 == "200", "alive=%s stats=%s" % (alive13, rc13))
    try:
        s13.kill(); s13.wait(timeout=10)
    except Exception:
        pass

    # b) control: lanzado SIN consola propia (pipe, como el resto de tests)
    #    NO debe cerrar nada ni reportar FreeConsole.
    s13b = subprocess.Popen(
        [GW, s13list, "--http-port", "18482", "--api-port", "18483",
         "--check-interval", "0", "--no-state", "--window"],
        cwd=WORK, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    procs.append(s13b)
    logs13b, decidio = [], False
    for _ in range(16):
        time.sleep(0.5)
        try:
            rc, out = curl("http://127.0.0.1:18483/logs", timeout=3)
            logs13b = json.loads(out).get("lines", [])
        except Exception:
            continue
        if any("se cerrara al crearse" in l or "se mantiene la consola" in l
               for l in logs13b):
            decidio = True
            break
    cerrada = any("consola propia cerrada" in l for l in logs13b)
    check("S13 sin consola propia: no la cierra (decide y respeta)",
          decidio and not cerrada, "; ".join(logs13b)[-300:])
    try:
        s13b.kill(); s13b.wait(timeout=10)
        if s13b.stdout:
            s13b.stdout.close()
    except Exception:
        pass

    # ---------------- S14: auditoria - limites de protocolo y permisos
    # (GWA 18430/18431 sigue vivo desde el arranque del bloque S1)
    s14list = os.path.join(WORK, "s14.txt")
    with open(s14list, "w", encoding="utf-8") as f:
        f.write("10.9.9.3:8080\n")

    # a) linea de chunk sin fin en la fase de cuerpo -> 400 rapido.
    #    Sin el cap de memoria, bufio se inflaba sin limite; el half-close
    #    da EOF para que el rechazo se resuelva de inmediato.
    try:
        out14 = raw_shut(18430, "POST http://x/ HTTP/1.1\r\nHost: x\r\n"
                         "Transfer-Encoding: chunked\r\n\r\n" + "f" * 5000, timeout=6)
    except Exception as e:
        out14 = "EXC:" + str(e)
    check("S14 chunk-size sin fin -> 400 rapido sin bloquear", "400" in out14, out14[:120])

    # b) mutantes sin cabecera de panel -> 403 (CSRF); GET -> 405
    code14, body14 = curl_code("-X", "POST", "http://127.0.0.1:18431/proxy-remove")
    check("S14 POST /proxy-remove sin X-GW-Panel -> 403", code14 == "403",
          code14 + " " + body14[:80])
    code14, body14 = curl_code("http://127.0.0.1:18431/proxy-remove")
    check("S14 GET /proxy-remove -> 405", code14 == "405", code14 + " " + body14[:80])

    # c) path traversal en /import -> la jaula lo deniega (.txt valido
    #    para superar el chequeo de extension y llegar a la jaula)
    code14, body14 = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d",
                               json.dumps({"path": "..\\..\\..\\Users\\ADMIN\\Desktop\\nube 1\\socks5.txt"}),
                               "http://127.0.0.1:18431/import")
    check("S14 /import path traversal -> acceso denegado", "denegado" in body14,
          code14 + " " + body14[:160])

    # d) payload de import mayor de 5 MB -> rechazado por MaxBytesReader
    big14 = os.path.join(WORK, "s14_big.json")
    with open(big14, "w", encoding="utf-8") as f:
        f.write(json.dumps({"text": "1.2.3.4:8080\n" * 450000}))
    code14, body14 = curl_code("-X", "POST", "-H", "X-GW-Panel: 1",
                               "--data-binary", "@" + big14,
                               "http://127.0.0.1:18431/import", timeout=30)
    check("S14 /import payload >5MB -> rechazado",
          "JSON invalido" in body14 or "5 MB" in body14, code14 + " " + body14[:160])

    # e) puerto ocupado -> exit 1 con mensaje y sin quedarse en la pausa
    ocup14 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ocup14.bind(("127.0.0.1", 18486))
    ocup14.listen(1)
    try:
        p14 = subprocess.run(
            [GW, s14list, "--http-port", "18486", "--api-port", "18487",
             "--check-interval", "0", "--no-state", "--no-browser"],
            cwd=WORK, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=30, stdin=subprocess.DEVNULL)
        exit14, out14 = p14.returncode, (p14.stdout or "") + (p14.stderr or "")
    except subprocess.TimeoutExpired:
        exit14, out14 = -1, "timeout: la instancia no salio (pausa colgada?)"
    ocup14.close()
    check("S14 puerto ocupado -> exit 1 sin pausa",
          exit14 == 1 and "no se pudo abrir el puerto" in out14,
          "exit=%s %s" % (exit14, out14[:160]))

    # f) /validate (dry) cuenta duplicados sin escribir nada
    code14, body14 = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d",
                               json.dumps({"text": "9.9.9.1:80\n9.9.9.1:80\n9.9.9.1:80"}),
                               "http://127.0.0.1:18431/validate")
    try:
        j14 = json.loads(body14)
    except Exception:
        j14 = {}
    check("S14 /validate: 3 lineas -> 1 valida + 2 duplicadas",
          j14.get("dry") is True and j14.get("valid") == 1 and j14.get("duplicates") == 2,
          body14[:180])

    # g) CRLF en /proxy-edit -> linea invalida (400), sin inyectar cabeceras
    px14 = api(18431, "/proxies")
    k14 = px14[0]["key"] if px14 else "http|1.2.3.4|8080|"
    code14, body14 = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d",
                               json.dumps({"key": k14, "line": "1.2.3.4:80\r\nX-Injected: 1"}),
                               "http://127.0.0.1:18431/proxy-edit")
    check("S14 /proxy-edit con CRLF -> 400 invalida", code14 == "400" and "invalida" in body14,
          code14 + " " + body14[:120])

    # h) path traversal en /checker/start -> la jaula lo deniega
    code14, body14 = curl_code("-X", "POST", "-H", "X-GW-Panel: 1", "-d",
                               json.dumps({"path": "..\\..\\..\\Windows\\win.txt"}),
                               "http://127.0.0.1:18431/checker/start")
    check("S14 /checker/start path traversal -> acceso denegado", "denegado" in body14,
          code14 + " " + body14[:160])

finally:
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass
    time.sleep(1)
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" | "
                    "ForEach-Object { if (-not (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue)) "
                    "{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }"],
                   capture_output=True)

fails = [r for r in results if not r[1]]
skips = [r for r in results if r[2] == "SKIP"]
print("\n=== DEEP: %d/%d OK (%d skip) ===" % (len(results) - len(fails), len(results), len(skips)))
sys.exit(1 if fails else 0)
