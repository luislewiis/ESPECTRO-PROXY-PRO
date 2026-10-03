// tests/test_panel_ui.mjs — pruebas funcion a funcion (vm) y boton a boton (Chrome headless)
// Uso: node tests/test_panel_ui.mjs
// Requiere: ProxyGateway.exe compilado, Chrome del sistema, playwright-core en %TEMP%/opencode/node_pw.
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const EXE = path.join(ROOT, 'ProxyGateway.exe');
const PW_DIR = path.join(os.tmpdir(), 'opencode', 'node_pw');
const TMP = path.join(os.tmpdir(), 'opencode', 'zz_uipanel');
const HTTP_PORT = 19080, API_PORT = 19081;
const BASE = `http://127.0.0.1:${API_PORT}`;
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

let pass = 0, fail = 0;
const failures = [];
function ok(cond, name, extra = '') {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name + (extra ? ' | ' + extra : '')); console.log('FAIL ' + name + (extra ? ' | ' + extra : '')); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function poll(fn, ms = 8000, step = 200) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try { if (await fn()) return true; } catch (e) {}
    await sleep(step);
  }
  return false;
}
async function api(pathname) {
  const r = await fetch(BASE + pathname);
  return r.json();
}

/* ===================== FASE A: funciones puras (vm) ===================== */
function phaseA() {
  console.log('\n===== FASE A: funciones puras =====');
  const html = fs.readFileSync(path.join(ROOT, 'panel.html'), 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  if (!m) { ok(false, 'extraer <script> de panel.html'); return; }
  const mkEl = () => ({
    value: '', textContent: '', innerHTML: '', hidden: false, style: {}, dataset: {},
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    appendChild() {}, remove() {}, addEventListener() {}, click() {},
    querySelector: () => null, querySelectorAll: () => [],
    scrollHeight: 0, scrollTop: 0, clientHeight: 0,
  });
  const els = {};
  const sandbox = {
    document: {
      getElementById: id => (els[id] ||= mkEl()),
      querySelector: () => null,
      querySelectorAll: () => [],
      createElement: () => mkEl(),
      addEventListener() {},
    },
    location: { origin: BASE },
    navigator: { clipboard: { writeText: async () => {}, readText: async () => '' } },
    confirm: () => true,
    fetch: async () => ({ ok: false, status: 500, json: async () => ({}) }),
    setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
    requestAnimationFrame: () => 0, console,
    URL, Set, Map, JSON, Math, Date, String, Number, Array, Object, RegExp, Promise,
    parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent,
  };
  sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  try {
    vm.runInContext(
      m[1] + '\n;globalThis.__F={fmtBytes,esc,splitHP,parsePort,bareScheme,schemeFromName,stickyLink,parseProxyLine,validateBatch,mergeReports,protoChips,massDelProto,massDelLine};globalThis.__setPD=v=>{proxyData=v;};',
      ctx, { filename: 'panel.js' });
  } catch (e) { ok(false, 'evaluar script del panel en vm', String(e)); return; }
  const F = sandbox.__F, setPD = sandbox.__setPD;
  const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  // fmtBytes
  ok(F.fmtBytes(0) === '0 B' && F.fmtBytes(1023) === '1023 B', 'fmtBytes: bytes', F.fmtBytes(1023));
  ok(F.fmtBytes(1024) === '1.0 KB' && F.fmtBytes(1048576 - 1).endsWith('KB'), 'fmtBytes: KB', F.fmtBytes(1024));
  ok(F.fmtBytes(1048576) === '1.0 MB', 'fmtBytes: MB', F.fmtBytes(1048576));
  ok(F.fmtBytes(1073741824) === '1.00 GB', 'fmtBytes: GB', F.fmtBytes(1073741824));

  // esc (XSS)
  ok(F.esc('a"b&c<d>') === 'a&quot;b&amp;c&lt;d&gt;', 'esc: 4 caracteres peligrosos', F.esc('a"b&c<d>'));
  ok(F.esc('<img src=x onerror=1>').startsWith('&lt;img'), 'esc: etiqueta HTML', F.esc('<img src=x onerror=1>'));
  ok(F.esc(123) === '123', 'esc: numero a string', F.esc(123));

  // splitHP / parsePort
  ok(eq(F.splitHP('1.2.3.4:8080'), { host: '1.2.3.4', port: 8080 }), 'splitHP: host:port');
  ok(eq(F.splitHP('[2001:db8::1]:1080'), { host: '2001:db8::1', port: 1080 }), 'splitHP: IPv6');
  ok(F.splitHP('1.2.3.4') === null && F.splitHP('[::1') === null && F.splitHP(':8080') === null, 'splitHP: invalidos -> null');
  ok(F.parsePort('80') === 80 && F.parsePort('1') === 1 && F.parsePort('65535') === 65535, 'parsePort: rangos validos');
  ok(F.parsePort('0') === null && F.parsePort('65536') === null && F.parsePort('abc') === null && F.parsePort('') === null, 'parsePort: invalidos');

  // esquemas
  ok(F.bareScheme('socks5') === 'socks5' && F.bareScheme('socks4a') === 'socks4a' && F.bareScheme('http') === 'http', 'bareScheme: passthrough');
  ok(F.bareScheme('ftp') === 'http' && F.bareScheme(undefined) === 'http', 'bareScheme: default http');
  ok(F.schemeFromName('lista_SOCKS5.txt') === 'socks5' && F.schemeFromName('x_socks4a.txt') === 'socks4a' &&
     F.schemeFromName('a_socks4.txt') === 'socks4' && F.schemeFromName('http.txt') === 'http' && F.schemeFromName('otro.txt') === '', 'schemeFromName: por nombre');

  // stickyLink
  ok(F.stickyLink('S1', 'http://gw:8080') === 'http://S1:clave@gw:8080', 'stickyLink: con gwBase', F.stickyLink('S1', 'http://gw:8080'));
  ok(F.stickyLink('S1') === 'http://S1:clave@127.0.0.1:' + API_PORT, 'stickyLink: usa location.origin', F.stickyLink('S1'));

  // parseProxyLine
  const P = F.parseProxyLine;
  let r = P('http://1.2.3.4:3128', '');
  ok(r.ok && r.scheme === 'http' && r.host === '1.2.3.4' && r.port === 3128, 'parseProxyLine: URL http', JSON.stringify(r));
  r = P('socks5://1.2.3.4', '');
  ok(r.ok && r.scheme === 'socks5' && r.port === 1080, 'parseProxyLine: URL socks5 puerto default 1080', JSON.stringify(r));
  r = P('socks4a://1.2.3.4:1081', '');
  ok(r.ok && r.scheme === 'socks4a', 'parseProxyLine: URL socks4a');
  r = P('ftp://1.2.3.4:21', '');
  ok(!r.ok && /esquema no soportado/.test(r.reason), 'parseProxyLine: ftp rechazado', r.reason);
  r = P('user:pass@1.2.3.4:8080', '');
  ok(r.ok && r.user === 'user' && r.host === '1.2.3.4', 'parseProxyLine: user:pass@host', JSON.stringify(r));
  r = P('[2001:db8::1]:1080', '');
  ok(r.ok && r.host === '2001:db8::1' && r.port === 1080, 'parseProxyLine: IPv6', JSON.stringify(r));
  r = P('0:1.2.3.4:8080::', '');
  ok(r.ok && r.scheme === 'http' && r.host === '1.2.3.4' && r.port === 8080, 'parseProxyLine: formato OB 0:host:port::', JSON.stringify(r));
  r = P('2:1.2.3.4:1080', '');
  ok(r.ok && r.scheme === 'socks5', 'parseProxyLine: OB tipo 2 = socks5', JSON.stringify(r));
  r = P('1.2.3.4:8080', '');
  ok(r.ok && r.user === '' && r.port === 8080, 'parseProxyLine: host:puerto');
  r = P('1.2.3.4:8080:juan', '');
  ok(r.ok && r.user === 'juan', 'parseProxyLine: host:port:user', JSON.stringify(r));
  r = P('1.2.3.4:8080:juan:secret', '');
  ok(r.ok && r.user === 'juan', 'parseProxyLine: host:port:user:pass', JSON.stringify(r));
  r = P('1.2.3.4:70000', '');
  ok(!r.ok && /puerto/.test(r.reason), 'parseProxyLine: puerto fuera de rango', r.reason);
  r = P('basura_sin_formato', '');
  ok(!r.ok && /formato no reconocido/.test(r.reason), 'parseProxyLine: basura', r.reason);
  r = P('1.2.3.4', '');
  ok(!r.ok, 'parseProxyLine: sin puerto -> invalido', JSON.stringify(r));

  // validateBatch
  setPD([{ tag: 'http://5.5.5.5:8080' }]);
  const batch = ['# comentario', '1.1.1.1:8080', '2.2.2.2:8080', '1.1.1.1:8080',
                 'http://5.5.5.5:8080', '3.3.3.3:99999', '', 'garbage_line'].join('\n');
  const vr = F.validateBatch(batch, '');
  ok(vr.valid.length === 2, 'validateBatch: 2 validos', JSON.stringify(vr.valid.length));
  ok(vr.invalid.length === 2, 'validateBatch: 2 invalidos', JSON.stringify(vr.invalid.map(x => x.text)));
  ok(vr.duplicates === 2, 'validateBatch: 2 duplicados (interno + contra lista)', String(vr.duplicates));
  ok(vr.ignored === 2, 'validateBatch: 2 ignorados (comentario + vacia)', String(vr.ignored));
  ok(vr.invalid[0].line === 6 && vr.invalid[1].line === 8, 'validateBatch: numeracion de lineas', JSON.stringify(vr.invalid.map(x => x.line)));

  // mergeReports + protoChips
  const f1 = { name: 'a.txt', report: F.validateBatch('9.9.9.9:1\n8.8.8.8:1', '') };
  const f2 = { name: 'b.txt', report: F.validateBatch('9.9.9.9:1\n7.7.7.7:1', '') };
  const mg = F.mergeReports([f1, f2]);
  ok(mg.valid.length === 3 && mg.duplicates === 1, 'mergeReports: 3 validos + 1 dup entre archivos', JSON.stringify({ v: mg.valid.length, d: mg.duplicates }));
  const chips = F.protoChips([{ scheme: 'http' }, { scheme: 'http' }, { scheme: 'socks5' }]);
  ok(chips.includes('HTTP 2') && chips.includes('SOCKS5 1'), 'protoChips: conteo por esquema', chips);

  /* ---- borrado del input (masivo) ---- */
  const massEl = () => sandbox.document.getElementById('massText');
  const setMass = (txt, caret) => {
    const el = massEl();
    el.value = txt;
    el.selectionStart = el.selectionEnd = (caret === undefined ? txt.length : caret);
  };
  setMass(['# comentario', '1.2.3.4:8080', 'http://5.5.5.5:1', 'https://6.6.6.6:1',
           'socks4://7.7.7.7:1', 'socks4a://8.8.8.8:1', 'socks5://9.9.9.9:1'].join('\n'));
  F.massDelProto('http');
  let mv = massEl().value;
  ok(!/https?:\/\//.test(mv) && /1\.2\.3\.4:8080/.test(mv) && /# comentario/.test(mv),
     'massDelProto http: borra http+https, conserva ip:port y comentarios', mv.replace(/\n/g, '|'));
  F.massDelProto('socks4');
  mv = massEl().value;
  ok(!/socks4a?:\/\//.test(mv) && /socks5:\/\//.test(mv),
     'massDelProto socks4: borra socks4 y socks4a', mv.replace(/\n/g, '|'));
  F.massDelProto('socks5');
  mv = massEl().value;
  ok(!/socks5:\/\//.test(mv) && /1\.2\.3\.4:8080/.test(mv),
     'massDelProto socks5: borra socks5 y deja lo demas', mv.replace(/\n/g, '|'));
  // ip:port sin esquema: no se puede clasificar hasta comprobar -> intactas
  setMass('1.2.3.4:8080\n4.4.4.4:1');
  F.massDelProto('socks5');
  ok(massEl().value.split('\n').length === 2, 'massDelProto: las ip:port sin esquema no se borran', massEl().value);
  // linea del cursor
  setMass('1.1.1.1:1\n2.2.2.2:2\n3.3.3.3:3', '1.1.1.1:1\n'.length + 3);
  F.massDelLine();
  mv = massEl().value;
  ok(!/2\.2\.2\.2/.test(mv) && /1\.1\.1\.1:1/.test(mv) && /3\.3\.3\.3:3/.test(mv),
     'massDelLine: borra solo la linea del cursor', mv.replace(/\n/g, '|'));
  // texto vacio no rompe
  setMass('');
  F.massDelLine();
  ok(massEl().value === '', 'massDelLine: texto vacio sin error', massEl().value);
}

/* ===================== FASE B: navegador ===================== */
async function phaseB() {
  console.log('\n===== FASE B: boton a boton (Chrome headless) =====');
  const req = createRequire(path.join(PW_DIR, 'package.json'));
  const { chromium } = req('playwright-core');

  // --- datos de prueba en dir temporal (cwd del gateway de prueba) ---
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });
  const mkProxies = n => Array.from({ length: n }, (_, i) => `127.0.0.1:${1000 + i}`).join('\n') + '\n';
  fs.writeFileSync(path.join(TMP, 'proxies.txt'), mkProxies(500));
  fs.writeFileSync(path.join(TMP, 'zz_ui_ok.txt'),
    ['10.1.0.1:8080', 'socks5://10.1.0.2:1080', 'badline', '10.1.0.1:8080', '# comentario', 'ftp://x:1'].join('\n') + '\n');
  fs.writeFileSync(path.join(TMP, 'zz_ui_path.txt'), ['10.3.0.1:8080', '10.3.0.2:8080', '10.3.0.3:8080'].join('\n') + '\n');
  fs.writeFileSync(path.join(TMP, 'zz_ui_bad.exe'), 'x');
  fs.writeFileSync(path.join(TMP, 'zz_ui_big.txt'), 'x'.repeat(5 * 1024 * 1024 + 200));

  const gw = spawn(EXE, ['--http-port', String(HTTP_PORT), '--api-port', String(API_PORT),
    '--no-browser', '--check-interval', '0', '--quiet', '--no-state'], { cwd: TMP, stdio: 'ignore', windowsHide: true });
  let browser;
  const pageErrors = [], consoleErrors = [];
  try {
    if (!await poll(async () => { try { const s = await api('/stats'); return s.total === 500; } catch (e) { return false; } }, 15000))
      { ok(false, 'gateway de prueba arranca con 500 proxies'); return; }
    ok(true, 'gateway de prueba arranca (19080/19081, 500 proxies)');

    browser = await chromium.launch({
      executablePath: CHROME, headless: true,
      args: ['--disable-gpu', '--disable-dev-shm-usage', '--no-sandbox'],
    });
    const bc = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    try { await bc.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE }); } catch (e) {}
    const page = await bc.newPage();
    page.on('pageerror', e => pageErrors.push(String(e)));
    page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
    page.on('dialog', async d => {
      // confirm() de Vaciar/borrar se acepta; prompt() de Editar se acepta
      // con un host nuevo para poder probar la edicion de proxies.
      if (d.type() === 'prompt') await d.accept('127.0.0.1:19999').catch(() => {});
      else await d.accept().catch(() => {});
    });

    const T = (sel) => page.locator(sel);
    const txtOf = async sel => ((await T(sel).first().textContent()) || '').trim();
    const nRows = async () => T('#ptbody tr').count();
    const pgInfo = () => txtOf('#pgInfo');
    const expectToast = async (frag, isErr = false, timeout = 6000) => {
      // Poll via evaluate (independiente de la semantica de visibilidad):
      const t0 = Date.now();
      let seen = [];
      while (Date.now() - t0 < timeout) {
        seen = await page.evaluate(() => [...document.querySelectorAll('.toast-msg')]
          .map(t => ({ txt: t.textContent, err: t.classList.contains('err') })));
        if (seen.some(x => x.txt.includes(frag) && (isErr ? x.err : true))) return true;
        await sleep(120);
      }
      console.log('  [debug toast "' + frag + '" no visto; toasts=' + JSON.stringify(seen) +
        '; wrap=' + JSON.stringify(await page.evaluate(() => document.getElementById('toast').innerHTML)) + ']');
      return false;
    };
    const firstIdx = async () => txtOf('#ptbody tr:first-child td.idx');

    /* ---- B1: carga + KPIs ---- */
    const resp = await page.goto(BASE + '/panel', { waitUntil: 'load', timeout: 15000 });
    ok(resp && resp.status() === 200, 'B1 /panel responde 200', String(resp && resp.status()));
    const tok = await page.locator('meta[name=gw-token]').count();
    const tokContent = tok ? await page.locator('meta[name=gw-token]').getAttribute('content') : null;
    ok(tok === 1 && tokContent !== '__GW_TOKEN__', 'B1 meta gw-token inyectado (no placeholder)', String(tokContent));
    ok(await poll(() => pgInfo().then(t => t.includes('de 500')), 8000), 'B1 tabla pagina 1: pgInfo "1-200 de 500"', await pgInfo());
    ok((await nRows()) === 200, 'B1 renderiza 200 filas (limite de pagina)', String(await nRows()));
    ok(/\d+\/\d+/.test(await txtOf('#cAlive')), 'B1 cAlive relleno', await txtOf('#cAlive'));
    ok((await txtOf('#statusTxt')).includes('vivos'), 'B1 statusTxt con vivos', await txtOf('#statusTxt'));
    ok((await txtOf('#stratPill')).includes('round-robin'), 'B1 stratPill round-robin', await txtOf('#stratPill'));
    ok(await page.locator('#statusPill.ok').count() === 1, 'B1 pill estado ok');
    ok(/\d+%/.test(await page.locator('#hbar').getAttribute('style') || ''), 'B1 healthbar con %');
    ok(/\d+:\d{2}:\d{2}/.test(await txtOf('#updated')), 'B1 updated con hora', await txtOf('#updated'));
    ok((await txtOf('#fPanel')).includes('/panel'), 'B1 footer panel', await txtOf('#fPanel'));
    ok((await txtOf('#fFiles')).includes('proxies.txt'), 'B1 footer listas', await txtOf('#fFiles'));
    ok((await txtOf('#fGw')) !== '—', 'B1 footer gateway', await txtOf('#fGw'));
    ok(await page.locator('#empty').isHidden(), 'B1 bloque vacio oculto con 500 proxies');
    /* ---- Info de arranque (el viejo banner de consola, ahora adentro del panel) ---- */
    ok(await page.locator('#bootInfo').count() === 1, 'B1 bloque Info de arranque presente');
    ok(await poll(() => txtOf('#bootInfo').then(t => t.includes('ESPECTRO PROXY PRO listo')), 8000),
      'B1 bootInfo con la marca', await txtOf('#bootInfo'));
    const bootTxt = await txtOf('#bootInfo');
    ok(bootTxt.includes('/get?session=MI_SESION') && bootTxt.includes('/proxy.txt'),
      'B1 bootInfo con enlace magico y lista viva', bootTxt.replace(/\s+/g, ' '));
    ok(bootTxt.includes('round-robin') && bootTxt.includes('Estado persistente') &&
       bootTxt.includes('health-check cada'), 'B1 bootInfo con estrategia/estado/health-check',
      bootTxt.replace(/\s+/g, ' '));
    const row1 = await txtOf('#ptbody tr:first-child');
    ok(row1.includes('127.0.0.1:1000') && row1.includes('SIN VERIFICAR'), 'B1 primera fila: 127.0.0.1:1000 sin verificar (sin check previo)', row1.replace(/\s+/g, ' '));
    ok((await nRows()) <= 200, 'B1 jamas mas de 200 filas');

    /* ---- B12a: filtros con todos vivos ---- */
    await T('.fchip[data-f="dead"]').click();
    ok((await page.locator('#ptbody .emptyrow').count()) === 1, 'B12 filtro Muertos (0 muertos): fila vacia');
    await T('.fchip[data-f="alive"]').click();
    ok((await nRows()) === 200, 'B12 filtro Vivos: 200 filas', String(await nRows()));
    await T('.fchip[data-f="all"]').click();
    ok((await nRows()) === 200 && (await txtOf('#nAll')) === '200', 'B12 filtro Todos: 200 (contador por pagina)', await txtOf('#nAll'));

    /* ---- B5: generar enlace sticky ---- */
    await T('#sess').fill('sesion_ui_1');
    await T('button:has-text("Generar enlace")').click();
    ok(await page.locator('#linkbox').isVisible(), 'B5 linkbox visible al generar');
    ok((await txtOf('#linktext')).includes('sesion_ui_1:clave@'), 'B5 enlace con sesion', await txtOf('#linktext'));
    ok((await txtOf('#linkapi')).includes('/get?session=sesion_ui_1'), 'B5 ruta JSON en panel', await txtOf('#linkapi'));
    ok(await poll(() => txtOf('#linkapi').then(t => t.includes('fijo en')), 5000), 'B5 /get fija la sesion (sticky_on)', await txtOf('#linkapi'));
    ok((await txtOf('#linktext')).includes('sesion_ui_1:clave@127.0.0.1'), 'B5 proxy de la sesion resuelto', await txtOf('#linktext'));
    ok(await poll(() => txtOf('#cSess').then(t => parseInt(t, 10) >= 1), 5000), 'B5 contador de sesiones sticky >= 1', await txtOf('#cSess'));

    /* ---- B6: copiar + cerrar ---- */
    const clipBefore = pageErrors.length;
    await T('button:has-text("Copiar enlace")').click();
    ok(await expectToast('Enlace copiado'), 'B6 toast "Enlace copiado"');
    try {
      const clip = await page.evaluate(() => navigator.clipboard.readText());
      ok(clip === (await txtOf('#linktext')), 'B6 clipboard == enlace mostrado');
    } catch (e) { ok(true, 'B6 clipboard no legible en headless (toast ya verificado)'); }
    await T('#linkbox button:has-text("Cerrar")').click();
    ok(await page.locator('#linkbox').isHidden(), 'B6 linkbox cerrado');

    // sesion larga > 64 (negativo, no debe romper)
    await T('#sess').fill('L'.repeat(70));
    await T('button:has-text("Generar enlace")').click();
    await sleep(1200);
    ok((await txtOf('#linkbox')).length > 0 && !(await txtOf('#linkapi')).includes('fijo en'),
      'B5 sesion >64: /get 400 manejado sin romper', await txtOf('#linkapi'));
    ok(pageErrors.length === clipBefore, 'B5 sesion larga sin pageerror');
    await T('#linkbox button:has-text("Cerrar")').click();

    /* ---- B2: estrategia ---- */
    for (const s of ['random', 'sticky', 'round-robin']) {
      await T('#strategy').selectOption(s);
      await T('button:has-text("Aplicar")').click();
      ok(await expectToast('Estrategia: ' + s), 'B2 toast estrategia ' + s);
      ok(await poll(async () => (await api('/stats')).strategy === s, 5000), 'B2 /stats.strategy = ' + s);
      ok(await poll(() => txtOf('#stratPill').then(t => t.includes(s)), 5000), 'B2 stratPill = ' + s);
    }

    /* ---- B4: Check ahora ---- */
    await T('button:has-text("Check ahora")').click();
    ok(await expectToast('Health-check lanzado'), 'B4 toast health-check lanzado');
    ok(await poll(async () => { const s = await api('/stats'); return s.alive === 0 && s.total === 500; }, 60000, 500),
      'B4 /check marca los 500 muertos (127.0.0.1 cerrado)');
    ok(await poll(async () => (await api('/logs')).lines.some(l => l.includes('health-check:')), 8000),
      'B4 resumen health-check en /logs');
    ok(await poll(() => txtOf('#statusTxt').then(t => t.includes('caídos') || t.includes('caidos')), 8000),
      'B4 statusTxt "todos caídos"', await txtOf('#statusTxt'));

    /* ---- B12b: filtros con todos muertos ---- */
    ok(await poll(() => txtOf('#nAlive').then(t => t === '0'), 12000),
      'B12b tabla sincronizada tras el check (nAlive=0)', await txtOf('#nAlive'));
    await T('.fchip[data-f="alive"]').click();
    ok((await page.locator('#ptbody .emptyrow').count()) === 1, 'B12b filtro Vivos (0 vivos): fila vacia');
    await T('.fchip[data-f="dead"]').click();
    ok((await nRows()) === 200 && (await txtOf('#nDead')) === '200', 'B12b filtro Muertos: 200', await txtOf('#nDead'));
    ok((await txtOf('#ptbody tr:first-child')).includes('MUERTO'), 'B12b badge MUERTO en fila');
    await T('.fchip[data-f="all"]').click();

    /* ---- B12c: badges mixtos + fails via respuesta simulada ---- */
    await page.route('**/proxies*', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        proxies: [
          { scheme: 'http', host: '2.2.2.2', port: 8080, alive: true, fails: 0, checked: true, ping_ms: 42, tag: 'http://2.2.2.2:8080' },
          { scheme: 'socks5', host: '3.3.3.3', port: 1080, alive: false, fails: 7, checked: true, ping_ms: 0, tag: 'socks5://3.3.3.3:1080' }],
        total: 2, offset: 0, limit: 200 }),
    }));
    await page.evaluate(() => refreshProxies());
    ok(await poll(() => nRows().then(n => n === 2), 5000), 'B12c respuesta simulada: 2 filas');
    const rAlive = await txtOf('#ptbody tr:first-child');
    const rDead = await txtOf('#ptbody tr:nth-child(2)');
    ok(rAlive.includes('VIVO') && rAlive.includes('2.2.2.2:8080'), 'B12c badge VIVO + host', rAlive.replace(/\s+/g, ' '));
    ok(rAlive.includes('42 ms'), 'B12c columna ping muestra 42 ms', rAlive.replace(/\s+/g, ' '));
    ok(rDead.includes('MUERTO') && rDead.includes('3.3.3.3:1080'), 'B12c badge MUERTO + host', rDead.replace(/\s+/g, ' '));
    ok(await page.locator('#ptbody tr:nth-child(2) td.fails.hot').count() === 1, 'B12c fails>0 con clase hot');
    await page.unroute('**/proxies*');
    await page.evaluate(() => refreshProxies());
    await poll(() => nRows().then(n => n === 200), 5000);

    /* ---- B13: busqueda ---- */
    await T('#search').fill('zzz_no_existe');
    ok((await page.locator('#ptbody .emptyrow').count()) === 1, 'B13 busqueda sin resultados');
    await T('#search').fill('127.0.0.1:100');
    const found = await nRows();
    ok(found > 0 && found <= 200 && (await page.locator('#ptbody .emptyrow').count()) === 0,
      'B13 busqueda con resultados (' + found + ')');
    await T('#search').fill('');
    ok((await nRows()) === 200, 'B13 busqueda limpiada restaura 200');

    /* ---- B14: paginacion ---- */
    ok((await pgInfo()) === '1-200 de 500', 'B14 pgInfo inicial 1-200 de 500', await pgInfo());
    await T('#pgNext').click();
    await poll(() => pgInfo().then(t => t === '201-400 de 500'), 5000);
    ok((await pgInfo()) === '201-400 de 500', 'B14 pgNext -> 201-400 de 500', await pgInfo());
    ok((await firstIdx()) === '201', 'B14 indice global de primera fila en pagina 2 (bug: era 1)', await firstIdx());
    ok((await nRows()) === 200, 'B14 pagina 2: 200 filas');
    await T('#pgNext').click();
    await poll(() => pgInfo().then(t => t === '401-500 de 500'), 5000);
    ok((await pgInfo()) === '401-500 de 500' && (await nRows()) === 100, 'B14 pagina 3: 401-500 (100 filas)', await pgInfo());
    ok((await firstIdx()) === '401', 'B14 indice global pagina 3', await firstIdx());
    await T('#pgNext').click();
    ok((await pgInfo()) === '401-500 de 500', 'B14 pgNext al final: sin salto', await pgInfo());
    await T('#pgPrev').click();
    await poll(() => pgInfo().then(t => t === '201-400 de 500'), 5000);
    await T('#pgPrev').click();
    await poll(() => pgInfo().then(t => t === '1-200 de 500'), 5000);
    ok((await pgInfo()) === '1-200 de 500', 'B14 pgPrev de vuelta a pagina 1', await pgInfo());
    await T('#pgPrev').click();
    ok((await pgInfo()) === '1-200 de 500', 'B14 pgPrev en pagina 1: no se va a -1');

    /* ---- B14b: la lista encoge y el offset queda fuera de rango ---- */
    await T('#pgNext').click(); await T('#pgNext').click();
    await poll(() => pgInfo().then(t => t === '401-500 de 500'), 5000);
    fs.writeFileSync(path.join(TMP, 'proxies.txt'), mkProxies(50));
    await T('.toolbar button:has-text("Recargar listas")').click();
    ok(await poll(() => pgInfo().then(t => t === '1-50 de 50'), 8000),
      'B14b recarga con lista reducida: offset clamped a 1-50 de 50', await pgInfo());
    ok((await nRows()) === 50 && (await page.locator('#ptbody .emptyrow').count()) === 0,
      'B14b 50 filas reales (no mensaje "sin proxies")', String(await nRows()));
    fs.writeFileSync(path.join(TMP, 'proxies.txt'), mkProxies(500));
    await T('.toolbar button:has-text("Recargar listas")').click();
    ok(await poll(() => pgInfo().then(t => t === '1-200 de 500'), 8000),
      'B14b lista restaurada: 1-200 de 500', await pgInfo());

    /* ---- B15: descargas ---- */
    const obHref = await page.locator('a[href="/proxy.txt?format=ob"]').getAttribute('href');
    const rawHref = await page.locator('a[href="/proxy.txt"]').getAttribute('href');
    ok(rawHref === '/proxy.txt' && obHref === '/proxy.txt?format=ob', 'B15 enlaces de descarga correctos');
    const raw = await (await fetch(BASE + '/proxy.txt')).text();
    const rawLines = raw.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#'));
    const st15 = await api('/stats');
    // /proxy.txt exporta la lista de VIVOS (AliveList) por diseno.
    ok(rawLines.length === st15.alive && rawLines[0].startsWith('127.0.0.1:'),
      'B15 proxy.txt: ' + st15.alive + ' vivos exportados', String(rawLines.length));
    const ob = await (await fetch(BASE + '/proxy.txt?format=ob')).text();
    const obLines = ob.split(/\r?\n/).filter(l => l.trim());
    ok(obLines.length === st15.alive && obLines[0].startsWith('0:127.0.0.1:'),
      'B15 formato OB: mismos vivos en formato 0:host:puerto', obLines[0]);

    /* ---- B7: pestañas de importar ---- */
    await T('button.itab[data-t="text"]').click();
    ok(await page.locator('#itab-text').isVisible() && await page.locator('#itab-file').isHidden() &&
       await page.locator('#itab-path').isHidden(), 'B7 pestaña Pegar texto visible, otras ocultas');
    ok(await page.locator('#valReport').isHidden(), 'B7 cambio de pestaña limpia informe');
    ok(await T('#btnImport').isDisabled() && (await txtOf('#btnImport')) === 'Importar', 'B7 boton Importar reseteado');
    await T('button.itab[data-t="path"]').click();
    ok(await page.locator('#itab-path').isVisible() && await page.locator('#itab-file').isHidden(), 'B7 pestaña Pegar ruta visible');
    await T('button.itab[data-t="file"]').click();
    ok(await page.locator('#itab-file').isVisible(), 'B7 pestaña Examinar visible');

    /* ---- B8: archivo (valido / extension / tamano / quitar) ---- */
    await T('#fileInput').setInputFiles(path.join(TMP, 'zz_ui_ok.txt'));
    ok(await poll(() => T('#fileList .filerow').count().then(n => n === 1), 5000), 'B8 archivo cargado en la lista');
    ok((await txtOf('#valChips')).includes('✓ 2') && (await txtOf('#valChips')).includes('✗ 2') &&
       (await txtOf('#valChips')).includes('⧉ 1') && (await txtOf('#valChips')).includes('○ 2'),
      'B8 chips 2 validos / 2 invalidos / 1 dup / 2 ignorados (comentario + linea final vacia)', await txtOf('#valChips'));
    const errTxt = await txtOf('#valErrors');
    ok(errTxt.includes('L3') && errTxt.includes('badline') && errTxt.includes('L6') && errTxt.includes('esquema no soportado'),
      'B8 errores con numero de linea y motivo', errTxt.replace(/\s+/g, ' ').slice(0, 160));
    ok((await txtOf('#btnImport')) === 'Importar 2 proxies' && await T('#btnImport').isEnabled(),
      'B8 boton "Importar 2 proxies" habilitado', await txtOf('#btnImport'));
    await T('#fileInput').setInputFiles(path.join(TMP, 'zz_ui_bad.exe'));
    ok(await expectToast('extensión no permitida', true), 'B8 .exe rechazado con toast de error');
    ok((await T('#fileList .filerow').count()) === 1, 'B8 .exe no anadido a la lista');
    await T('#fileInput').setInputFiles(path.join(TMP, 'zz_ui_big.txt'));
    ok(await expectToast('supera 5 MB', true), 'B8 archivo >5MB rechazado con toast');
    ok((await T('#fileList .filerow').count()) === 1, 'B8 archivo grande no anadido');
    await T('#fileList .x').click();
    ok((await T('#fileList .filerow').count()) === 0, 'B8 quitar archivo (x)');
    ok(await page.locator('#valReport').isHidden() && await T('#btnImport').isDisabled() &&
       (await txtOf('#btnImport')) === 'Importar', 'B8 al vaciar: informe oculto y boton deshabilitado');

    /* ---- B9: texto en vivo ---- */
    await T('button.itab[data-t="text"]').click();
    const textMix = ['7.7.7.7:8080', '8.8.8.8:1080', 'user:pw@9.9.9.9:3128', '[2001:db8::2]:1080',
                     '0:6.6.6.6:8080::', 'socks4://5.5.5.5:1080', 'no_valid_line', '2.2.2.2:70000'].join('\n');
    await T('#rawText').fill(textMix);
    ok(await poll(() => txtOf('#btnImport').then(t => t === 'Importar 6 proxies'), 4000),
      'B9 validacion en vivo: 6 validos de 8 lineas', await txtOf('#btnImport'));
    const chips9 = await txtOf('#valChips');
    ok(chips9.includes('✓ 6') && chips9.includes('✗ 2'), 'B9 chips 6/2', chips9);
    await T('#rawText').fill('');
    ok(await poll(() => page.locator('#valReport').isHidden().then(h => h), 4000) &&
       await T('#btnImport').isDisabled(), 'B9 texto vacio: informe oculto y boton disabled');
    ok((await txtOf('#impHint')).length > 0, 'B9 hint de estado presente', await txtOf('#impHint'));

    /* ---- B10: ruta (server-side) ---- */
    await T('button.itab[data-t="path"]').click();
    await T('#pathInput').fill('C:\\no_existe_zz\\nada.txt');
    await T('#itab-path button:has-text("Validar ruta")').click();
    ok(await poll(() => txtOf('#valChips').then(t => t.includes('✗') && t.length > 1), 6000),
      'B10 ruta inexistente: chip de error', await txtOf('#valChips'));
    ok((await txtOf('#impHint')) === 'ruta no válida', 'B10 hint "ruta no valida"', await txtOf('#impHint'));
    ok(await T('#btnImport').isDisabled(), 'B10 boton deshabilitado con ruta mala');
    await T('#pathInput').fill(path.join(TMP, 'zz_ui_bad.exe'));
    await T('#itab-path button:has-text("Validar ruta")').click();
    ok(await poll(() => txtOf('#valChips').then(t => t.includes('extension no permitida')), 6000),
      'B10 .exe rechazado por el servidor', await txtOf('#valChips'));
    await T('#pathInput').fill(path.join(TMP, 'zz_ui_ok.txt'));
    await T('#pathInput').press('Enter'); // Enter dispara validatePath
    ok(await poll(() => txtOf('#valChips').then(t => t.includes('✓ 2') && t.includes('✗ 2')), 6000),
      'B10 Enter valida la ruta: 2 validos / 2 invalidos', await txtOf('#valChips'));
    ok((await txtOf('#impHint')).includes('validado por el servidor'), 'B10 hint de validado por servidor', await txtOf('#impHint'));
    ok((await txtOf('#btnImport')) === 'Importar 2 proxies', 'B10 boton habilitado con ruta valida', await txtOf('#btnImport'));

    /* ---- B11: importar ---- */
    // 1) texto: 5 validos + 1 invalido
    const st0 = await api('/stats');
    ok(st0.total === 500, 'B11 estado previo: total 500', String(st0.total));
    await T('button.itab[data-t="text"]').click();
    const impText = ['10.2.0.1:8080', '10.2.0.2:8080', '10.2.0.3:8080', '10.2.0.4:8080', '10.2.0.5:8080', 'zz_invalid'].join('\n');
    await T('#rawText').fill(impText);
    await poll(() => txtOf('#btnImport').then(t => t === 'Importar 6 proxies'), 4000);
    await T('#btnImport').click();
    ok(await expectToast('Importados 5 proxies'), 'B11b texto: toast de exito');
    ok(await poll(() => T('#impResult').isVisible().then(v => v), 6000), 'B11b caja de resultado visible');
    const resTxt = await txtOf('#impResult');
    ok(resTxt.includes('5') && resTxt.includes('inválidos omitidos: 1') && resTxt.includes('505'),
      'B11b resultado 5 importados / 1 omitido / total 505', resTxt.replace(/\s+/g, ' ').slice(0, 200));
    ok((await T('#rawText').inputValue()) === '' && await page.locator('#valReport').isHidden(),
      'B11b tras importar: texto limpio e informe oculto');
    // el bug era que la tabla no se refrescaba: ahora pgInfo debe decir 505
    ok(await poll(() => pgInfo().then(t => t.includes('de 505')), 6000),
      'B11b tabla refrescada tras importar (pgInfo total 505)', await pgInfo());
    // 2) archivo: 2 validos
    await T('button.itab[data-t="file"]').click();
    await T('#fileInput').setInputFiles(path.join(TMP, 'zz_ui_ok.txt'));
    await poll(() => txtOf('#btnImport').then(t => t === 'Importar 2 proxies'), 5000);
    await T('#btnImport').click();
    ok(await expectToast('Importados 2 proxies'), 'B11b archivo: toast de exito');
    ok(await poll(async () => (await api('/stats')).total >= 507, 6000),
      'B11b archivo importado: total >= 507', String((await api('/stats')).total));
    ok((await T('#fileList .filerow').count()) === 0, 'B11b tras importar: archivos limpiados');
    // 3) ruta: 3 validos
    await T('button.itab[data-t="path"]').click();
    await T('#pathInput').fill(path.join(TMP, 'zz_ui_path.txt'));
    await T('#itab-path button:has-text("Validar ruta")').click();
    await poll(() => txtOf('#btnImport').then(t => t === 'Importar 3 proxies'), 6000);
    await T('#btnImport').click();
    ok(await expectToast('Importados 3 proxies'), 'B11b ruta: toast de exito');
    ok(await poll(async () => (await api('/stats')).total === 510, 6000),
      'B11b ruta importada: total 510', String((await api('/stats')).total));
    // 4) solo duplicados -> boton deshabilitado
    await T('button.itab[data-t="text"]').click();
    await T('#rawText').fill('127.0.0.1:1000\n127.0.0.1:1001');
    await poll(() => txtOf('#valChips').then(t => t.includes('✓ 0')), 4000);
    ok(await T('#btnImport').isDisabled(), 'B11b solo duplicados: boton deshabilitado');
    ok((await txtOf('#valChips')).includes('⧉ 2') || (await txtOf('#valChips')).includes('⧉'),
      'B11b duplicados contados en chips', await txtOf('#valChips'));
    await T('#rawText').fill('');
    // 5) red caida durante import
    await page.route('**/import', route => route.abort('failed'));
    await T('#rawText').fill('10.9.0.1:8080');
    await poll(() => txtOf('#btnImport').then(t => t === 'Importar 1 proxies'), 4000);
    await T('#btnImport').click();
    ok(await expectToast('Error de red importando', true), 'B11b red caida: toast de error');
    await page.unroute('**/import');
    await T('#rawText').fill('');

    /* ---- B3: bloque vacio (stats simulado total 0) ---- */
    await page.route('**/stats', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ requests: 0, errors: 0, bytes_up: 0, bytes_down: 0, alive: 0, dead: 0,
        total: 0, sessions: 0, strategy: 'round-robin', files: [], gateway: '' }),
    }));
    await T('.toolbar button:has-text("Recargar listas")').click();
    ok(await poll(() => page.locator('#empty').isVisible(), 8000), 'B3 con total 0: bloque vacio visible');
    ok((await txtOf('#statusTxt')).includes('sin proxies'), 'B3 statusTxt "sin proxies"', await txtOf('#statusTxt'));
    await T('#empty button:has-text("Recargar listas")').click();
    ok(await expectToast('Listas recargadas'), 'B3 boton del bloque vacio funciona');
    await page.unroute('**/stats');
    await T('.toolbar button:has-text("Recargar listas")').click();
    ok(await poll(() => page.locator('#empty').isHidden(), 8000), 'B3 bloque vacio oculto de nuevo');

    /* ---- B16: XSS en log y en filas ---- */
    await page.route('**/logs', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ lines: ['[gw] <img src=x onerror="window.__xss=1">', '[gw] <script>window.__xss2=1</script>'] }),
    }));
    ok(await poll(() => txtOf('#logs').then(t => t.includes('onerror')), 8000),
      'B16 XSS en log: respuesta simulada pintada');
    ok(await poll(() => page.locator('#logs img, #logs script').count().then(n => n === 0), 4000),
      'B16 XSS en log: no se inyectan elementos');
    const logTxt = await txtOf('#logs');
    ok(logTxt.includes('<img src=x'), 'B16 XSS en log: se muestra como texto', logTxt.replace(/\s+/g, ' ').slice(0, 120));
    ok(await page.evaluate(() => typeof window.__xss === 'undefined' && typeof window.__xss2 === 'undefined'),
      'B16 XSS en log: onerror/script no ejecutados');
    await page.route('**/proxies*', route => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        proxies: [{ scheme: 'http', host: '<img src=x onerror="window.__xss=1">', port: 80, alive: true, fails: 0,
                    tag: 'http://x:80' }],
        total: 1, offset: 0, limit: 200 }),
    }));
    await page.evaluate(() => refreshProxies());
    ok(await poll(() => T('#ptbody tr td.mono img').count().then(n => n === 0), 5000),
      'B16 XSS en fila: no se inyecta img en la tabla');
    const cellTxt = await txtOf('#ptbody td.mono');
    ok(cellTxt.includes('<img'), 'B16 XSS en fila: host peligroso como texto', cellTxt);
    ok(await page.evaluate(() => typeof window.__xss === 'undefined'), 'B16 XSS en fila: onerror no ejecutado');
    await page.unroute('**/proxies*');
    await page.unroute('**/logs');
    await page.evaluate(() => refreshProxies());

    /* ---- B17: resiliencia ---- */
    await page.route('**/stats', route => route.abort('failed'));
    await T('.toolbar button:has-text("Recargar listas")').click();
    ok(await poll(() => txtOf('#statusTxt').then(t => t.includes('sin conexión')), 8000),
      'B17 /stats caido: "sin conexion"', await txtOf('#statusTxt'));
    await page.unroute('**/stats');
    await page.route('**/reload', route => route.fulfill({ status: 500, body: 'boom' }));
    await T('.toolbar button:has-text("Recargar listas")').click();
    ok(await expectToast('Listas recargadas (fallo)', true), 'B17 /reload 500: toast (fallo)');
    await page.unroute('**/reload');
    // doble clic en Aplicar sin errores
    const pe0 = pageErrors.length;
    await T('button:has-text("Aplicar")').click();
    await T('button:has-text("Aplicar")').click();
    await sleep(500);
    ok(pageErrors.length === pe0, 'B17 doble clic en Aplicar sin pageerror', String(pageErrors.length - pe0));

    /* ---- B18: Checker Masivo (seccion nueva) ---- */
    ok((await page.locator('#massSection').count()) === 1, 'B18 seccion #massSection presente');
    ok((await page.locator('#btnMassStart').count()) === 1, 'B18 boton #btnMassStart presente');
    ok((await page.locator('#massDrop').count()) === 1, 'B18 dropzone de archivos presente');
    ok(await page.locator('#massProgress').isHidden() && await page.locator('#massHitsWrap').isHidden(),
      'B18 progreso y hits ocultos sin job');
    // pestañas de la seccion (no deben tocar las de importar)
    const importVisibleAntes = await page.locator('#itab-text').isVisible();
    await T('#massSection button[data-mt="path"]').click();
    ok(await page.locator('#mtab-path').isVisible() && await page.locator('#mtab-text').isHidden() &&
       await page.locator('#mtab-file').isHidden() &&
       (await page.locator('#itab-text').isVisible()) === importVisibleAntes,
      'B18 pestana Ruta visible y pestanas de importar intactas',
      'importText antes=' + importVisibleAntes);
    await T('#massSection button[data-mt="text"]').click();
    ok(await page.locator('#mtab-text').isVisible(), 'B18 pestana Pegar listas visible');
    // sin texto: toast de error y sin job
    await T('#btnMassStart').click();
    ok(await expectToast('Pega tu lista', true), 'B18 start sin texto: toast de error');
    ok((await api('/checker/status')).done === false && (await api('/checker/status')).running === false,
      'B18 sin job en el servidor tras start invalido');
    // sin filtro de locales: 127.0.0.1 debe evaluarse (los puertos cerrados
    // fallan en cascade al instante -> job corto, offline-safe)
    await T('#massSkipLocal').uncheck();
    await T('#massText').fill('127.0.0.1:1\nsocks5://127.0.0.1:2\n127.0.0.1:3');
    await T('#massTimeout').fill('400');
    await T('#massRetries').fill('0');
    await T('#btnMassStart').click();
    ok(await expectToast('Checker masivo iniciado'), 'B18 toast de job iniciado');
    ok(await poll(async () => (await api('/checker/status')).done === true, 20000),
      'B18 job finalizado (offline-safe)', JSON.stringify(await api('/checker/status')));
    const ms = await api('/checker/status');
    ok(ms.total === 3 && ms.tested === 3 && ms.alive === 0 && ms.bad === 3,
      'B18 3 evaluados / 0 vivos / 3 muertos', JSON.stringify(ms));
    ok((ms.out_dir || '').includes('Resultados'), 'B18 carpeta de sesion en Resultados', ms.out_dir);
    await poll(() => txtOf('#massStats').then(t => t.includes('finalizado')), 6000);
    ok((await txtOf('#massStats')).includes('finalizado'), 'B18 #massStats muestra "finalizado"',
      await txtOf('#massStats'));
    ok(await T('#btnMassStart').isEnabled() && await T('#btnMassCancel').isDisabled(),
      'B18 tras terminar: Iniciar habilitado y Cancelar deshabilitado');
    // export + report responden
    const expResp = await fetch(BASE + '/checker/export?proto=all&format=full');
    ok(expResp.status === 200, 'B18 /checker/export 200', String(expResp.status));
    const repResp = await fetch(BASE + '/checker/report');
    ok(repResp.status === 200, 'B18 /checker/report 200', String(repResp.status));
    const rep18 = await repResp.json();
    ok(rep18.TotalEvaluados === 3 && rep18.Vivos.Total === 0,
      'B18 report TotalEvaluados=3 Vivos=0', JSON.stringify(rep18));
    ok(await page.locator('#massHitsWrap').isVisible(), 'B18 tabla de hits visible tras correr');
    ok((await page.locator('#massHitsBody .emptyrow').count()) === 1, 'B18 sin vivos: fila vacia');
    // cancel de un job nuevo via UI: listener TCP mudo (acepta y no responde)
    // -> cada probe bloquea hasta el timeout, el job dura lo suficiente
    const silentSocks = [];
    const silentSrv = net.createServer(s => { silentSocks.push(s); });
    await new Promise(r => silentSrv.listen(0, '127.0.0.1', r));
    const silentPort = silentSrv.address().port;
    const slowLines = Array.from({length: 12}, (_, i) =>
      'u' + i + '@127.0.0.1:' + silentPort).join('\n');
    await T('#massText').fill(slowLines);
    await T('#massTimeout').fill('500');
    await T('#massRetries').fill('0');
    await T('#massThreads').fill('1');
    await T('#btnMassStart').click();
    ok(await poll(async () => (await api('/checker/status')).running === true, 4000),
      'B18 segundo job en marcha', JSON.stringify(await api('/checker/status')));
    await T('#btnMassCancel').click();
    ok(await poll(async () => { const s = await api('/checker/status'); return s.done && s.cancelled; }, 25000),
      'B18 cancel via UI: done+cancelled', JSON.stringify(await api('/checker/status')));
    ok(await poll(async () =>
      await T('#btnMassStart').isEnabled() && await T('#btnMassCancel').isDisabled(), 8000),
      'B18 tras cancel: botones reseteados');
    silentSocks.forEach(s => s.destroy());
    silentSrv.close();
    await T('#massThreads').fill('0');

    /* ---- B19: marca ESPECTRO PROXY PRO + borrado (input y vivos) ---- */
    const h1txt = await txtOf('header h1');
    ok(h1txt.includes('ESPECTRO') && h1txt.includes('PROXY PRO'),
      'B19 cabecera con la marca ESPECTRO PROXY PRO', h1txt);
    ok((await page.title()) === 'ESPECTRO PROXY PRO - Panel', 'B19 <title> del panel', await page.title());
    const need19 = ['btnMassDelLine', 'btnMassDelHttp', 'btnMassDelSocks4', 'btnMassDelSocks5',
      'btnMassClearText', 'btnMassClearFiles', 'btnMassClearAll', 'mfAll', 'mfHttp', 'mfSocks4',
      'mfSocks5', 'btnMassRemoveSel', 'btnMassClearHits', 'massCkAll', 'expFull', 'expPlain'];
    const miss19 = [];
    for (const id of need19) if ((await page.locator('#' + id).count()) !== 1) miss19.push(id);
    ok(miss19.length === 0, 'B19 controles de borrado presentes', miss19.join(','));
    ok((await page.locator('#massHitsWrap thead th').count()) === 7,
      'B19 tabla de vivos con columna de seleccion y ×');

    // --- borrado por protocolo en el input ---
    await T('#massSection button[data-mt="text"]').click();
    await T('#massText').fill(['# comentario', '1.2.3.4:8080', 'http://5.5.5.5:1', 'https://6.6.6.6:1',
      'socks4://7.7.7.7:1', 'socks4a://8.8.8.8:1', 'socks5://9.9.9.9:1'].join('\n'));
    await T('#btnMassDelHttp').click();
    let v19 = await page.inputValue('#massText');
    ok(!/https?:\/\//.test(v19) && /1\.2\.3\.4:8080/.test(v19) && /# comentario/.test(v19),
      'B19 borrar HTTP en input (http+https)', v19.replace(/\n/g, '|'));
    ok(await expectToast('borrada'), 'B19 toast de borrado HTTP');
    await T('#btnMassDelSocks4').click();
    v19 = await page.inputValue('#massText');
    ok(!/socks4a?:\/\//.test(v19) && /socks5:\/\//.test(v19),
      'B19 borrar SOCKS4 incluye socks4a', v19.replace(/\n/g, '|'));
    await T('#btnMassDelSocks5').click();
    v19 = await page.inputValue('#massText');
    ok(!/socks5:\/\//.test(v19) && /1\.2\.3\.4:8080/.test(v19),
      'B19 borrar SOCKS5 deja ip:port sin esquema', v19.replace(/\n/g, '|'));
    // sin esquema: el protocolo no se conoce hasta comprobar -> no se borra
    await T('#massText').fill('1.2.3.4:8080\n4.4.4.4:1');
    await T('#btnMassDelSocks5').click();
    ok((await page.inputValue('#massText')).split('\n').length === 2,
      'B19 ip:port sin esquema no se borran por protocolo', await page.inputValue('#massText'));
    ok(await expectToast('sin esquema', true), 'B19 aviso "sin esquema" en el toast de error');
    // línea del cursor
    await T('#massText').fill('1.1.1.1:1\n2.2.2.2:2\n3.3.3.3:3');
    await page.evaluate(() => { const t = document.getElementById('massText'); t.focus(); t.setSelectionRange(13, 13); });
    await T('#btnMassDelLine').click();
    v19 = await page.inputValue('#massText');
    ok(!/2\.2\.2\.2/.test(v19) && /1\.1\.1\.1:1/.test(v19) && /3\.3\.3\.3:3/.test(v19),
      'B19 borrar la línea del cursor', v19.replace(/\n/g, '|'));
    // vaciar todo el texto (confirm aceptado por el listener de dialogs)
    await T('#btnMassClearText').click();
    ok((await page.inputValue('#massText')) === '', 'B19 Vaciar todo el texto',
      await page.inputValue('#massText'));
    // vaciar archivos del masivo
    await T('#massSection button[data-mt="file"]').click();
    await T('#btnMassClearFiles').click();
    ok(await expectToast('Sin archivos cargados', true), 'B19 vaciar archivos vacío: toast error');
    await T('#massFileInput').setInputFiles(path.join(TMP, 'zz_ui_ok.txt'));
    ok(await poll(() => T('#massFileList .filerow').count().then(n => n === 1), 5000),
      'B19 archivo cargado en el masivo');
    await T('#btnMassClearFiles').click();
    ok(await poll(() => T('#massFileList .filerow').count().then(n => n === 0), 5000),
      'B19 Vaciar archivos deja la lista vacía');
    // Vaciar todo (global)
    await T('#massSection button[data-mt="text"]').click();
    await T('#massText').fill('9.9.9.9:1');
    await T('#btnMassClearAll').click();
    ok((await page.inputValue('#massText')) === '', 'B19 Vaciar todo limpia el input');
    ok(await poll(() => T('#massFileList .filerow').count().then(n => n === 0), 4000),
      'B19 Vaciar todo deja los archivos vacíos');

    // --- endpoint /checker/remove: validaciones ---
    const r403 = await fetch(BASE + '/checker/remove',
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"proto":"all"}' });
    ok(r403.status === 403, 'B19 /checker/remove sin X-GW-Panel -> 403', String(r403.status));
    const r400 = await fetch(BASE + '/checker/remove',
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-GW-Panel': '1' },
        body: '{"proto":"ftp"}' });
    ok(r400.status === 400, 'B19 protocolo desconocido -> 400', String(r400.status));
    const rEmpty = await fetch(BASE + '/checker/remove',
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-GW-Panel': '1' }, body: '{}' });
    ok(rEmpty.status === 400, 'B19 sin line ni proto -> 400', String(rEmpty.status));

    // --- vivo real local: juez + relay, y borrado de la tabla de vivos ---
    const judgeSrv = http.createServer((q, s) => {
      s.writeHead(200, { 'Content-Type': 'application/json' });
      s.end('{"country":"Espania","query":"127.0.0.1"}');
    });
    await new Promise(r => judgeSrv.listen(0, '127.0.0.1', r));
    const judgeUrl = 'http://127.0.0.1:' + judgeSrv.address().port + '/json';
    const relaySrv = net.createServer(sock => {
      let buf = Buffer.alloc(0), up = null;
      sock.on('error', () => {});
      sock.on('data', d => {
        if (up) { up.write(d); return; }
        buf = Buffer.concat([buf, d]);
        const i = buf.indexOf('\r\n\r\n');
        if (i < 0) return;
        const head = buf.slice(0, i).toString('latin1');
        const rest = buf.slice(i + 4);
        const first = (head.split('\r\n')[0] || '');
        const mm = first.match(/^[A-Za-z]+ (\S+) HTTP\/1\.[01]$/);
        if (!mm || !/^https?:\/\//.test(mm[1])) { sock.destroy(); return; }
        const u = new URL(mm[1]);
        up = net.connect(Number(u.port) || 80, u.hostname, () => {
          up.write('GET ' + u.pathname + u.search + ' HTTP/1.1\r\nHost: ' + u.host +
            '\r\nConnection: close\r\n\r\n');
          if (rest.length) up.write(rest);
        });
        up.on('data', d2 => sock.write(d2));
        up.on('end', () => sock.end());
        up.on('error', () => sock.destroy());
      });
    });
    await new Promise(r => relaySrv.listen(0, '127.0.0.1', r));
    const relayPort = relaySrv.address().port;

    const runVivoJob = async (tag) => {
      await T('#massSection button[data-mt="text"]').click();
      await T('#massText').fill('http://127.0.0.1:' + relayPort);
      await page.evaluate(() => { document.getElementById('massSkipLocal').checked = false; });
      await T('#massJudge').fill(judgeUrl);
      await T('#massTimeout').fill('3000');
      await T('#massRetries').fill('0');
      await T('#massThreads').fill('2');
      await T('#btnMassStart').click();
      let started = await poll(async () => (await api('/checker/status')).running === true, 8000);
      if (!started) {
        // job de 1 linea: puede terminar antes de la primera consulta
        started = (await api('/checker/status')).done === true;
      }
      ok(started, tag + ' job en marcha', JSON.stringify(await api('/checker/status')));
      const done = await poll(async () => (await api('/checker/status')).done === true, 30000);
      ok(done, tag + ' job finalizado', JSON.stringify(await api('/checker/status')));
      const st = await api('/checker/status');
      ok(st.alive === 1 && st.http === 1, tag + ' 1 vivo http via relay local', JSON.stringify(st));
      await page.evaluate(() => refreshMass());
      return st;
    };

    await runVivoJob('B19a');
    ok(await poll(() => T('#massHitsBody tr:not(.emptyrow)').count().then(n => n === 1), 8000),
      'B19a fila de vivo renderizada en la tabla');
    ok((await page.locator('#massHitsBody .xbtn').count()) === 1, 'B19a botón × en la fila del vivo');
    // filtro de protocolo + export ligado al filtro
    await T('#mfHttp').click();
    ok(await page.locator('#mfHttp').evaluate(e => e.classList.contains('active')),
      'B19 filtro http queda activo');
    ok((await T('#expFull').getAttribute('href')).includes('proto=http'),
      'B19 enlace de export sigue al filtro', await T('#expFull').getAttribute('href'));
    await T('#mfSocks5').click();
    ok((await page.locator('#massHitsBody .emptyrow').count()) === 1,
      'B19 filtro socks5 sin vivos: fila vacía');
    await T('#mfAll').click();
    // borrar una fila con el ×
    await T('#massHitsBody .xbtn').click();
    ok(await expectToast('Vivo borrado'), 'B19 toast al borrar con ×');
    ok(await poll(async () => (await api('/checker/status')).alive === 0, 8000),
      'B19 alive 0 tras borrar con ×', JSON.stringify(await api('/checker/status')));
    ok(await poll(() => T('#massHitsBody .emptyrow').count().then(n => n === 1), 8000),
      'B19 tabla vacía tras borrar con ×');
    // borrar la selección (checkbox "seleccionar todo")
    await runVivoJob('B19b');
    await poll(() => T('#massHitsBody tr:not(.emptyrow)').count().then(n => n === 1), 8000);
    await T('#massCkAll').check();
    ok(await poll(() => T('#massHitsBody .mck:checked').count().then(n => n === 1), 5000),
      'B19 seleccionar todo marca la fila');
    await T('#btnMassRemoveSel').click();
    ok(await expectToast('Borrados 1'), 'B19 toast de borrar selección');
    ok(await poll(async () => (await api('/checker/status')).alive === 0, 8000),
      'B19 alive 0 tras borrar selección', JSON.stringify(await api('/checker/status')));
    // vaciar todos los vivos
    await runVivoJob('B19c');
    await T('#btnMassClearHits').click();
    ok(await expectToast('Vivos vaciados'), 'B19 toast de vaciar vivos');
    ok(await poll(async () => (await api('/checker/status')).alive === 0, 8000),
      'B19 alive 0 tras vaciar vivos', JSON.stringify(await api('/checker/status')));
    const st19 = await api('/checker/status');
    ok(st19.removed >= 1 && st19.hits === 0, 'B19 contador removed + hits a 0', JSON.stringify(st19));
    const exp19 = await (await fetch(BASE + '/checker/export?proto=all&format=plain')).text();
    ok(exp19.trim() === '', 'B19 export vacío tras borrar los vivos', JSON.stringify(exp19));
    relaySrv.close();
    judgeSrv.close();
    await T('#massJudge').fill('');
    await T('#massThreads').fill('0');

    /* ---- B20: gestor de la lista (borrar/editar con persistencia) ---- */
    // filtro a "Todos" y pagina 1 por si un bloque anterior lo dejo distinto
    await T('.fchip[data-f="all"]').click();
    await page.evaluate(() => { proxyOffset = 0; return refreshProxies(); });
    ok(await poll(() => pgInfo().then(t => t.startsWith('1-200')), 6000),
      'B20 en pagina 1 antes de probar el gestor', await pgInfo());
    ok(await T('#btnDelDead').count() === 1 && await T('#btnDelAlive').count() === 1 &&
      await T('#btnDelAll').count() === 1, 'B20 botones borrar muertos / vivos / vaciar todo');
    ok((await T('table:has(#ptbody) thead th').count()) === 7, 'B20 tabla con columna Acciones (7 th)');
    ok((await T('#ptbody .rowbtn').count()) === (await nRows()) * 2,
      'B20 cada fila tiene editar + borrar', String(await T('#ptbody .rowbtn').count()));
    const stB20 = await api('/stats');
    ok(stB20.total >= 500, 'B20 lista con al menos 500 antes del gestor', String(stB20.total));

    // --- borrar 1 proxy de la fila 1 (persiste en disco) ---
    const b20host = await txtOf('#ptbody tr:first-child td.mono');
    await T('#ptbody tr:first-child .rowbtn.del').click();  // confirm aceptado
    ok(await expectToast('lista en disco actualizada'), 'B20 toast al borrar 1 proxy');
    const t1 = stB20.total - 1;
    ok(await poll(async () => (await api('/stats')).total === t1, 6000),
      'B20 total -1 tras borrar 1', String((await api('/stats')).total));
    const f20a = fs.readFileSync(path.join(TMP, 'proxies.txt'), 'utf8');
    ok(!f20a.includes(b20host + '\n') && f20a.includes('127.0.0.1:1001\n'),
      'B20 la fila desaparecio del .txt en disco', b20host);
    ok(await poll(() => pgInfo().then(t => t.endsWith('de ' + t1)), 6000),
      'B20 pgInfo refleja el total-1', await pgInfo());

    // --- borrar muertos (los hay si algun bloque anterior los verifico) ---
    const deadNow = (await api('/stats')).dead;
    const beforeDel = (await api('/stats')).total;
    await T('#btnDelDead').click();
    if (deadNow > 0) {
      ok(await expectToast('borrados'), 'B20 toast al borrar muertos');
      ok(await poll(async () => (await api('/stats')).total === beforeDel - deadNow, 6000),
        'B20 se borraron exactamente los muertos', String((await api('/stats')).total));
    } else {
      ok(await expectToast('no hay muertos'), 'B20 borrar muertos (0): aviso sin borrar');
      ok((await api('/stats')).total === beforeDel, 'B20 nada cambió al borrar muertos vacío',
        String((await api('/stats')).total));
    }

    // --- editar la primera fila (prompt con host nuevo) ---
    const beforeEdit = (await api('/stats')).total;
    await T('#ptbody tr:first-child .rowbtn').first().click();  // ✎
    ok(await expectToast('proxy editado'), 'B20 toast al editar proxy');
    const f20b = await poll(() =>
      Promise.resolve(fs.readFileSync(path.join(TMP, 'proxies.txt'), 'utf8'))
        .then(t => t.includes('127.0.0.1:19999')), 6000);
    ok(f20b, 'B20 la edicion se reescribio en disco');
    ok((await api('/stats')).total === beforeEdit, 'B20 la edicion no cambia el total',
      String((await api('/stats')).total));

    // --- vaciar toda la lista (SOLO memoria: el .txt fuente NO se toca) ---
    const fAntesVaciar = fs.readFileSync(path.join(TMP, 'proxies.txt'), 'utf8');
    const totalAntesVaciar = (await api('/stats')).total;
    await T('#btnDelAll').click();  // confirm aceptado
    ok(await expectToast('lista vaciada'), 'B20 toast al vaciar todo');
    ok(await poll(async () => (await api('/stats')).total === 0, 6000),
      'B20 lista vacía tras vaciar todo', String((await api('/stats')).total));
    ok(fs.readFileSync(path.join(TMP, 'proxies.txt'), 'utf8') === fAntesVaciar,
      'B20 .txt intacto tras vaciar todo (solo memoria)');
    ok(await poll(() => T('#ptbody .emptyrow').count().then(n => n === 1), 6000),
      'B20 emptyrow "sin proxies" tras vaciar');

    // --- restaurar desde la fuente (/reload): el .txt manda ---
    await fetch(BASE + '/reload', {
      method: 'POST', headers: { 'X-GW-Panel': '1' },
    });
    ok(await poll(async () => (await api('/stats')).total === totalAntesVaciar, 8000),
      'B20 lista restaurada desde el .txt con /reload', String((await api('/stats')).total));
    await page.evaluate(() => refreshProxies());

    // --- pagina del botón API (era texto crudo en blanco) ---
    ok((await T('a.pill[href="/"]').count()) >= 1, 'B20 cabecera con botón API');
    const apiPage = await bc.newPage();
    try {
      const rApi = await apiPage.goto(BASE + '/', { waitUntil: 'load', timeout: 15000 });
      ok(rApi && rApi.status() === 200, 'B20 / (API) responde 200', String(rApi && rApi.status()));
      ok((await apiPage.title()) === 'ESPECTRO PROXY PRO', 'B20 / titulo de marca',
        await apiPage.title());
      const bg = await apiPage.evaluate(() => getComputedStyle(document.body).backgroundColor);
      ok(bg === 'rgb(11, 15, 26)', 'B20 / con tema oscuro (fondo #0b0f1a)', bg);
      const backTxt = ((await apiPage.locator('a[href="/panel"]').first().textContent()) || '').trim();
      ok(backTxt.includes('Volver al panel'), 'B20 / enlace "Volver al panel"', backTxt);
      const htmlApi = await apiPage.content();
      ok(htmlApi.includes('/proxy-remove') && !htmlApi.includes('estilo Dataimpulse'),
        'B20 / documenta el gestor y ya no es texto crudo');
    } finally {
      await apiPage.close().catch(() => {});
    }

    /* ---- global: 0 errores JS ---- */
    ok(pageErrors.length === 0, 'GLOBAL 0 pageerror en toda la sesion',
      pageErrors.slice(0, 3).join(' || '));
    const realConsoleErrors = consoleErrors.filter(e =>
      !/Failed to load resource|net::ERR_/i.test(e));
    ok(realConsoleErrors.length === 0, 'GLOBAL 0 errores de consola reales',
      realConsoleErrors.slice(0, 3).join(' || '));
  } finally {
    if (browser) await browser.close().catch(() => {});
    gw.kill();
    await sleep(300);
    try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (e) {}
  }
}

/* ===================== main ===================== */
try {
  if (!fs.existsSync(EXE)) { console.log('Falta ProxyGateway.exe — compila antes de correr esta suite.'); process.exit(1); }
  phaseA();
  await phaseB();
} catch (e) {
  fail++; failures.push('excepcion inesperada: ' + (e && e.stack || e));
  console.log('FAIL excepcion inesperada: ' + (e && e.stack || e));
}

console.log('\n===== PANEL UI: ' + pass + ' pass / ' + fail + ' fail =====');
if (failures.length) console.log('FALLOS:\n - ' + failures.join('\n - '));
process.exit(fail > 0 ? 1 : 0);
