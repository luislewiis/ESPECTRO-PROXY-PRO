#!/usr/bin/env python3
"""Test profundo del endpoint sticky + API vs gateway (puertos).

Reproduce el bug del usuario: el panel generaba el enlace sticky con el
puerto de la API (8081) en vez del puerto del gateway (8080), y las
peticiones no llegaban al gateway (Peticiones=0).
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXE = os.path.join(ROOT, "ProxyGateway.exe")
WORK = os.path.join(os.environ["TEMP"], "opencode", "stickytest")
os.makedirs(WORK, exist_ok=True)

GW, API = 18180, 18181          # gateway (proxy) / API (panel)
FAKE_A, FAKE_B = 18190, 18191   # upstreams falsos
PROCS = []
fails = 0

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(url):
    with OPENER.open(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")


def check(name, cond, detail=""):
    global fails
    if cond:
        print("PASS " + name)
    else:
        fails += 1
        print("FAIL " + name + (" | " + str(detail)[:300] if detail else ""))


def curl_proxy(proxy, url, extra=()):
    """curl via proxy SIN heredar env proxy."""
    cmd = ["curl.exe", "-s", "--max-time", "15", "-x", proxy]
    cmd += list(extra)
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return p.returncode, p.stdout


def spawn(script, *args):
    p = subprocess.Popen([sys.executable, os.path.join(HERE, script), *[str(a) for a in args]],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    PROCS.append(p)
    return p


def stats():
    return json.loads(get("http://127.0.0.1:%d/stats" % API))


def wait_api():
    t0 = time.time()
    while time.time() - t0 < 10:
        try:
            get("http://127.0.0.1:%d/stats" % API)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def main():
    global fails
    # ---- infra: 2 upstreams falsos + lista + instancia controlada
    spawn("fake_id_proxy.py", FAKE_A, "A")
    spawn("fake_id_proxy.py", FAKE_B, "B")
    lst = os.path.join(WORK, "sticky_list.txt")
    with open(lst, "w") as f:
        f.write("127.0.0.1:%d\n127.0.0.1:%d\n" % (FAKE_A, FAKE_B))
    gw = subprocess.Popen(
        [EXE, lst, "--http-port", str(GW), "--api-port", str(API),
         "--check-interval", "0", "--no-browser", "--quiet", "--no-state"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    PROCS.append(gw)
    if not wait_api():
        check("arranque instancia", False, "API no responde")
        return

    # ---- T1: stats.gateway apunta al puerto del gateway (8080-analog)
    st = stats()
    check("T1 stats.gateway == http://127.0.0.1:%d" % GW,
          st["gateway"] == "http://127.0.0.1:%d" % GW, st["gateway"])

    # ---- T2: index de la API muestra sticky con el puerto del gateway
    idx = get("http://127.0.0.1:%d/" % API)
    check("T2 index sticky usa puerto gateway (%d)" % GW,
          (":%d</code>" % GW) in idx and "Sesion sticky" in idx, idx[:300])
    check("T2b index auto-refresh 15s", 'http-equiv="refresh"' in idx)

    # ---- T3: /get devuelve el endpoint proxy CORRECTO (puerto gateway)
    j = json.loads(get("http://127.0.0.1:%d/get?session=mikey" % API))
    want = "http://mikey:clave@127.0.0.1:%d" % GW
    check("T3 /get.proxy == %s" % want, j.get("proxy") == want, j)
    check("T3 /get.gateway == puerto gateway", j.get("gateway") == "http://127.0.0.1:%d" % GW, j)
    check("T3 /get.sticky_on asignado", bool(j.get("sticky_on")), j)

    # ---- T4: REPRO DEL USUARIO - usar la API (8081) como proxy
    s0 = stats()
    rc, body = curl_proxy("http://mikey:clave@127.0.0.1:%d" % API, "http://target.test/")
    st1 = stats()
    check("T4 proxy contra puerto API: NO proxied (sin ID:)", "ID:" not in body, body[:200])
    check("T4 responde aviso 'puerto de la API'", "puerto de la API" in body, body[:300])
    check("T4 el gateway NO cuenta peticiones", st1["requests"] == s0["requests"],
          "%d -> %d" % (s0["requests"], st1["requests"]))
    # sin credenciales (solo absolute-form) -> tambien rechazado
    rc, body = curl_proxy("http://127.0.0.1:%d" % API, "http://target.test/")
    st2 = stats()
    check("T4b sin credenciales contra API: 400 y sin contar",
          "puerto de la API" in body and st2["requests"] == s0["requests"], body[:200])

    # ---- T5: USO CORRECTO - proxy contra el puerto del gateway
    rc, body = curl_proxy("http://mikey:clave@127.0.0.1:%d" % GW, "http://target.test/")
    st3 = stats()
    check("T5 proxy via gateway responde del upstream", body.strip() in ("ID:A", "ID:B"), body[:120])
    check("T5 peticion contada (requests+1)", st3["requests"] == s0["requests"] + 1,
          "%d -> %d" % (s0["requests"], st3["requests"]))
    check("T5 bytes_down > 0", st3["bytes_down"] > 0, st3["bytes_down"])

    # ---- T6: sticky real - 5 peticiones con la sesion = mismo upstream
    ids = []
    for i in range(5):
        rc, body = curl_proxy("http://mikey:clave@127.0.0.1:%d" % GW, "http://target.test/")
        ids.append(body.strip())
    check("T6 sticky: 5/5 mismo upstream", len(set(ids)) == 1 and ids[0] in ("ID:A", "ID:B"), ids)
    j = json.loads(get("http://127.0.0.1:%d/get?session=mikey" % API))
    check("T6 /get.sticky_on == upstream fijo", j.get("sticky_on", "").endswith(
        str(FAKE_A) if ids[0] == "ID:A" else str(FAKE_B)), j)

    # ---- T7: password cualquiera aceptada (diseno: solo importa la sesion)
    rc, body = curl_proxy("http://mikey:OTRA_CLAVE@127.0.0.1:%d" % GW, "http://target.test/")
    check("T7 password distinta tambien funciona (diseno actual)", body.strip() in ("ID:A", "ID:B"), body[:120])

    # ---- T8: sin credenciales via gateway -> tambien funciona (rotacion normal)
    rc, body = curl_proxy("http://127.0.0.1:%d" % GW, "http://target.test/")
    check("T8 sin sesion via gateway funciona", body.strip() in ("ID:A", "ID:B"), body[:120])

    # ---- T9: index y /stats coherentes (mismo vivo)
    alive_st = stats()["alive"]
    m = idx.split("<b>")[1].split("</b>")[0] if "<b>" in idx else ""
    idx2 = get("http://127.0.0.1:%d/" % API)
    m2 = idx2.split("<b>")[1].split("</b>")[0] if "<b>" in idx2 else ""
    check("T9 index vivos == stats vivos", m2 == "%d/%d" % (alive_st, stats()["total"]),
          "index=%s stats=%d" % (m2, alive_st))

    # ---- T10: panel - stickyLink usa la base del gateway (no location.port)
    html = open(os.path.join(ROOT, "panel.html"), encoding="utf-8").read()
    i0 = html.index("function stickyLink")
    i1 = html.index("function genLink")
    js = html[i0:i1]
    node = subprocess.run(
        ["node", "-e",
         "const fs=require('fs');" + js +
         ";console.log(stickyLink('mikey','http://127.0.0.1:%d'));" % GW],
        capture_output=True, text=True)
    out = node.stdout.strip()
    check("T10 stickyLink(session, gateway) puerto %d" % GW,
          out == "http://mikey:clave@127.0.0.1:%d" % GW, out + node.stderr[:200])
    check("T10b genLink usa j.proxy (respuesta del servidor)",
          "j.proxy" in html[html.index("function genLink"):html.index("function copyLink")])
    check("T10c refresh guarda lastGW desde stats", "lastGW = st.gateway" in html)
    check("T10d panel sin location.port para el enlace", "location.port" not in html)
    check("T10e pill API -> /", '<a href="/" class="pill">API</a>' in html)

    # ---- T11: la sesion sigue viva tras todo
    st = stats()
    check("T11 sesiones sticky >= 1", st["sessions"] >= 1, st["sessions"])
    check("T11 requests acumulados >= 7", st["requests"] >= 7, st["requests"])


if __name__ == "__main__":
    try:
        main()
    finally:
        for p in PROCS:
            try:
                p.kill()
            except Exception:
                pass
        time.sleep(0.3)
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-CimInstance Win32_Process | "
                        "Where-Object { $_.CommandLine -match 'stickytest|fake_id_proxy' } | "
                        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"],
                       capture_output=True)
    print("\n=== STICKY/API: %d fallos ===" % fails)
    sys.exit(1 if fails else 0)
