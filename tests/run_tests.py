import json, subprocess, sys, time, urllib.request, os

TEMP = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GW = os.path.join(os.path.dirname(TEMP), "ProxyGateway.exe")
GW = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_GW
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (" | " + str(detail)[:200] if detail and not cond else ""))

def curl(*args):
    p = subprocess.run(["curl.exe", "-s", "--max-time", "15", "--noproxy", "", *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout

def start(*args):
    if GW.lower().endswith(".exe") and args and args[0] == GW:
        cmd = [GW, *args[1:], "--no-browser", "--no-state"]
    else:
        cmd = [sys.executable, *args]
    return subprocess.Popen(cmd, cwd=TEMP,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

procs = []
try:
    with open(os.path.join(TEMP, "dead_only.txt"), "w") as f:
        f.write("127.0.0.1:19999\n")
    procs.append(start("target_srv.py", "18000"))
    procs.append(start("fake_upstream.py", "19000"))
    procs.append(start("fake_socks5.py", "19001"))
    procs.append(start(GW, "test_proxies.txt", "--http-port", "18080",
                       "--api-port", "18081", "--check-interval", "0"))
    procs.append(start(GW, "dead_only.txt", "--http-port", "18090",
                       "--api-port", "18091", "--check-interval", "0"))
    time.sleep(2.5)

    # 1. peticion HTTP simple (debe saltar el proxy muerto 19999 y usar 19000)
    rc, out = curl("-x", "http://127.0.0.1:18080", "http://127.0.0.1:18000/")
    check("GET basico via gateway (fallback de muerto)", out.strip() == "PROXY-GATEWAY-OK", f"rc={rc} out={out!r}")

    # 2. CONNECT (tunel) via gateway
    rc, out = curl("-x", "http://127.0.0.1:18080", "--proxytunnel", "http://127.0.0.1:18000/")
    check("CONNECT/tunel via gateway", out.strip() == "PROXY-GATEWAY-OK", f"rc={rc} out={out!r}")

    # 3. rotacion: varias peticiones deben pasar por ambos upstreams (http y socks5)
    oks = []
    for i in range(8):
        rc, out = curl("-x", "http://127.0.0.1:18080", f"http://127.0.0.1:18000/?i={i}")
        oks.append(out.strip() == "PROXY-GATEWAY-OK")
    check("8 peticiones rotadas todas OK", all(oks), oks)

    # 4. POST con cuerpo + header custom
    rc, out = curl("-x", "http://127.0.0.1:18080", "-d", "hola=mundo",
                   "-H", "X-Test: prueba123", "http://127.0.0.1:18000/")
    check("POST con body + header", out.strip() == "POST-ECHO:hola=mundo:H=prueba123", f"out={out!r}")

    # 5. respuesta grande (50KB)
    rc, out = curl("-x", "http://127.0.0.1:18080", "http://127.0.0.1:18000/big")
    check("respuesta grande 50KB", len(out) == 50000, f"len={len(out)}")

    # 6. API /get (enlace magico estilo Dataimpulse)
    rc, out = curl("http://127.0.0.1:18081/get?session=sesion1")
    try:
        j = json.loads(out)
        check("API /get JSON valido", j.get("session") == "sesion1" and "18080" in j.get("proxy", ""), out)
        proxy_url = j.get("proxy", "").replace("clave", "x")
    except Exception as e:
        check("API /get JSON valido", False, out)
        proxy_url = None

    # 7. usar el enlace con sesion (sticky)
    if proxy_url:
        rc, out = curl("-x", proxy_url, "http://127.0.0.1:18000/")
        check("peticion via enlace sticky", out.strip() == "PROXY-GATEWAY-OK", f"out={out!r}")

    # 8. API /stats
    rc, out = curl("http://127.0.0.1:18081/stats")
    try:
        s = json.loads(out)
        check("API /stats", s["total"] == 3 and s["requests"] >= 1, out)
    except Exception:
        check("API /stats", False, out)

    # 9. /proxy.txt y /proxy.txt?format=ob
    rc, out = curl("http://127.0.0.1:18081/proxy.txt")
    lines = [l for l in out.splitlines() if l.strip()]
    check("proxy.txt contiene upstreams vivos",
          "127.0.0.1:19000" in lines and "127.0.0.1:19001" in lines and len(lines) >= 2, out)
    rc, out = curl("http://127.0.0.1:18081/proxy.txt?format=ob")
    ob_line = [l for l in out.splitlines() if ":19000:" in l]
    check("proxy.txt formato OB", bool(ob_line) and ob_line[0].startswith("0:127.0.0.1:19000"), out)

    # 10. pagina /
    rc, out = curl("http://127.0.0.1:18081/")
    check("pagina info /", "ESPECTRO PROXY PRO" in out, out[:100])

    # 11. /reload (POST + cabecera de panel: proteccion CSRF)
    rc, out = curl("-X", "POST", "-H", "X-GW-Panel: 1", "http://127.0.0.1:18081/reload")
    check("API /reload", '"ok":true' in out.replace(" ", ""), out)

    # 12. solo proxies muertos -> 502
    rc, out = curl("-x", "http://127.0.0.1:18090", "http://127.0.0.1:18000/")
    check("502 cuando no hay upstream util", rc == 0 and out.strip() == "" or "502" in out, f"rc={rc} out={out!r}")

    # 13. sesion se mantiene pegada al mismo upstream
    ids = []
    for i in range(4):
        rc, out = curl("-x", "-ses1:x@127.0.0.1:18080".replace("-s", ""), f"http://127.0.0.1:18000/?s={i}")
        ids.append(out.strip())
    check("sticky: 4 peticiones misma sesion OK", all(x == "PROXY-GATEWAY-OK" for x in ids), ids)

    # 14. /validate: valida formatos y protocolos de la lista pegada (incluye IPv6)
    body = json.dumps({"text": "1.2.3.4:8080\nsocks5://1.2.3.4:1080\nbasura!!\n0:5.6.7.8:8080::\n1.2.3.4:8080\n[::1]:8080"})
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json", "-d", body,
                   "http://127.0.0.1:18081/validate")
    try:
        v = json.loads(out)
        ok = (v.get("ok") is True and v.get("valid") == 4 and v.get("duplicates") == 1
              and v.get("invalid_total") == 1
              and (v.get("invalid") or [{}])[0].get("line") == 3
              and v.get("protocols", {}).get("socks5") == 1
              and v.get("protocols", {}).get("http") == 3)
        check("API /validate valida formatos/protocolos/IPv6", ok, out)
    except Exception:
        check("API /validate valida formatos/protocolos/IPv6", False, out)

    # 15. /import: guarda en la lista principal y recarga
    with open(os.path.join(TEMP, "import_list.txt"), "w") as f:
        f.write("10.0.0.1:8000\n")
    procs.append(start(GW, "import_list.txt", "--http-port", "18100",
                       "--api-port", "18101", "--check-interval", "0"))
    time.sleep(1.5)
    body = json.dumps({"text": "10.0.0.2:8001\nsocks5://10.0.0.3:1080\nbasura!!"})
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json", "-d", body,
                   "http://127.0.0.1:18101/import")
    try:
        r = json.loads(out)
        with open(os.path.join(TEMP, "import_list.txt")) as f:
            saved = f.read()
        ok = (r.get("ok") is True and r.get("valid") == 2 and r.get("total") == 3
              and "10.0.0.2:8001" in saved and "basura" not in saved)
        check("API /import guarda y recarga", ok, out + " | saved=" + saved[:120])
    except Exception:
        check("API /import guarda y recarga", False, out)

    # 17. inferencia de esquema por nombre de archivo (socks5_x.txt -> socks5)
    with open(os.path.join(TEMP, "socks5_prueba.txt"), "w") as f:
        f.write("10.9.9.1:1080\n10.9.9.2:1081\nbasura!!\n")
    with open(os.path.join(TEMP, "socks4_prueba.txt"), "w") as f:
        f.write("10.9.8.1:1080\n10.9.8.2:1081\n")
    procs.append(start(GW, "socks5_prueba.txt", "--http-port", "18110",
                       "--api-port", "18111", "--check-interval", "0"))
    time.sleep(1.5)
    rc, out = curl("http://127.0.0.1:18111/proxies")
    try:
        px = json.loads(out)
        sch = sorted({p.get("scheme") for p in px})
        check("CLI: socks5_*.txt carga lineas como socks5", len(px) == 2 and sch == ["socks5"], out[:300])
    except Exception:
        check("CLI: socks5_*.txt carga lineas como socks5", False, out)

    body = json.dumps({"path": os.path.join(TEMP, "socks4_prueba.txt")})
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json", "-d", body,
                   "http://127.0.0.1:18111/validate")
    try:
        v = json.loads(out)
        ok = (v.get("ok") is True and v.get("valid") == 2
              and v.get("protocols", {}).get("socks4") == 2
              and v.get("duplicates") == 0)
        check("/validate {path}: nombre socks4_*.txt aplica socks4", ok, out)
    except Exception:
        check("/validate {path}: nombre socks4_*.txt aplica socks4", False, out)

    body = json.dumps({"text": "10.9.7.1:1080", "name": "socks5_inline.txt"})
    rc, out = curl("-X", "POST", "-H", "Content-Type: application/json", "-d", body,
                   "http://127.0.0.1:18111/import")
    try:
        r = json.loads(out)
        ok = (r.get("ok") is True and r.get("valid") == 1
              and r.get("protocols", {}).get("socks5") == 1
              and r.get("total") == 3)
        check("/import {text,name}: nombre aplica esquema", ok, out)
    except Exception:
        check("/import {text,name}: nombre aplica esquema", False, out)

finally:
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass

fails = [r for r in results if not r[1]]
print(f"\n=== {len(results) - len(fails)}/{len(results)} tests OK ===")
sys.exit(1 if fails else 0)
