// "Receive a file" end to end on this machine: the real Drop (a debug build
// with the native-acceptance driver), its Rust engine and its real hidden
// webview window running desktop/ui/direct.js, against the web project's
// /send page in Chromium playing the phone. The page is built from the same
// wildbloom commit as the vendored bundle. Loopback services come from the
// Rust `direct_receive_services` test: a Nostr relay and NIP-46 signer (to
// approve this computer), a Foregather live relay, and an online node that
// issues TURN credentials. Both ends run with their addresses shown (host
// candidates), because WebKit gathers no relay candidates from a loopback
// TURN server; nothing listens at the TURN URL. Synthetic keys only, and the
// app runs with HOME in a temporary folder, so the Received folder is too.
//
// Journeys: a file arrives byte for byte and is kept in the Received folder;
// the page is closed mid-transfer; the phone's browser is killed mid-transfer
// (no goodbye, so the end comes from the connection state and Drop's
// give-up); the owner declines. The last three keep nothing and leave
// nothing in Drop's temporary folder, and a decline never opens the hidden
// window or a peer connection on either side.
//
// Build first (from the repository root):
//   cargo build --locked -p wildbloomd --bin wildbloomd          (needs --turn-issuer)
//   cargo build --locked --manifest-path desktop/src-tauri/Cargo.toml --features native-acceptance
//   cargo test --locked --manifest-path desktop/src-tauri/Cargo.toml --bin wildbloom-desktop --no-run
// Then:
//   WILDBLOOM_CHECKOUT=../wildbloom FOREGATHER_SERVER_BIN=/path/to/foregather-server \
//     node desktop/tests/direct-receive-native.mjs
//
//   WILDBLOOM_CHECKOUT            a wildbloom checkout with node_modules; the page is built from the
//                                 vendored bundle's commit with `git archive`, so its branch is untouched
//   FOREGATHER_SERVER_BIN         foregather-server with live mode (the kit at 5f18449 or later)
//   WILDBLOOMD_BIN                defaults to target/debug/wildbloomd
//   WILDBLOOM_BROWSER_EXECUTABLE  Chromium or Chrome (macOS default is Chrome)
//   DIRECT_E2E_BYTES              the kept file's size (default 32 MiB + 4321)
//   DIRECT_KEEP=1                 keep the temporary folder
//
// Never prints a link, words, a bunker URI, a credential or an SDP.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { closeSync, existsSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, devices } from 'playwright-core';

assert.equal(process.platform, 'darwin', 'This journey drives the macOS webview.');
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const checkout = resolve(process.env.WILDBLOOM_CHECKOUT ?? '');
assert.ok(existsSync(join(checkout, 'node_modules/vite')), 'Set WILDBLOOM_CHECKOUT to a wildbloom checkout with node_modules.');
const foregather = process.env.FOREGATHER_SERVER_BIN ?? '';
assert.ok(existsSync(foregather), 'Set FOREGATHER_SERVER_BIN to a foregather-server executable.');
const daemon = resolve(process.env.WILDBLOOMD_BIN ?? join(repo, 'target/debug/wildbloomd'));
const appBinary = join(repo, 'desktop/src-tauri/target/debug/wildbloom-desktop');
for (const file of [daemon, appBinary]) assert.ok(existsSync(file), `Build ${file} first (see the header).`);
const provenance = JSON.parse(readFileSync(join(repo, 'desktop/ui/vendor/wildbloom-direct.provenance.json'), 'utf8'));
const KEPT_BYTES = Number(process.env.DIRECT_E2E_BYTES ?? 32 * 1024 * 1024 + 4321);
const CLOSED_BYTES = 200_000_000;

const root = mkdtempSync(join(tmpdir(), 'wildbloom-direct-native-'));
const home = join(root, 'home');
const handoff = join(root, 'handoff');
for (const dir of [home, handoff, join(root, 'bin')]) mkdirSync(dir, { recursive: true });
const received = join(home, 'Downloads', 'Wildbloom Received');
const children = [];
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const evidence = {
  schema: 'wildbloom.direct-receive-native.v1', passed: false,
  scope: 'macOS debug app with the native-acceptance driver: real Rust engine, real IPC and hidden WKWebView window; phone is the /send page in headless Chrome; loopback services; host candidates (no TURN relay)',
  source_commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(),
  source_dirty: execFileSync('git', ['status', '--porcelain', '--', 'desktop', 'scripts'], { cwd: repo, encoding: 'utf8' }).trim().length > 0,
  wildbloom_commit: provenance.commit, bundle_sha256: provenance.sha256,
  os_version: execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim(),
  app_sha256: sha256(readFileSync(appBinary)), daemon_sha256: sha256(readFileSync(daemon)), foregather_sha256: sha256(readFileSync(foregather)),
  journeys: [],
};
const log = (line) => process.stdout.write(`${line}\n`);

async function freePort(kind = 'tcp') {
  if (kind === 'udp') {
    const probe = dgram.createSocket('udp4');
    probe.bind(0, '127.0.0.1');
    await once(probe, 'listening');
    const port = probe.address().port;
    probe.close();
    return port;
  }
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise((done) => probe.close(done));
  return port;
}
async function until(check, what, timeout = 30_000, every = 100) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error(`Timed out waiting for ${typeof what === 'function' ? await what() : what}`);
    await pause(every);
  }
}
/** What a transfer left in Drop's temporary folder: anything but the folder's own lock. */
const leftIn = (dir) => filesUnder(dir).filter((path) => !path.endsWith('/.wildbloom-temp.lock'));
function filesUnder(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => (entry.isDirectory() ? filesUnder(join(dir, entry.name)) : [join(dir, entry.name)]));
}

// ------------------------------------------------------------- the phone page

const pagePort = await freePort();
const pageOrigin = `http://127.0.0.1:${pagePort}`;
const turnUrl = `turn:127.0.0.1:${await freePort('udp')}?transport=udp`;
{
  const web = join(root, 'wildbloom');
  mkdirSync(web);
  execFileSync('git', ['-C', checkout, 'archive', '--format=tar', '-o', join(root, 'wildbloom.tar'), provenance.commit]);
  execFileSync('tar', ['-xf', join(root, 'wildbloom.tar'), '-C', web]);
  symlinkSync(join(checkout, 'node_modules'), join(web, 'node_modules'));
  execFileSync(process.execPath, [join(checkout, 'node_modules/vite/bin/vite.js'), 'build', '--outDir', join(root, 'send-dist'), '--emptyOutDir', '--logLevel', 'error'], {
    cwd: web, stdio: ['ignore', 'ignore', 'inherit'],
    env: { ...process.env, VITE_WILDBLOOM_PAIR_RELAY: `${pageOrigin}/pair/v1/`, VITE_WILDBLOOM_DIRECT_ICE: turnUrl },
  });
  assert.ok(existsSync(join(root, 'send-dist/send.html')), 'The build has the /send page.');
  log(`ok  built /send from wildbloom ${provenance.commit.slice(0, 7)}, the vendored bundle's commit`);
}

let upstream;
const relayLog = [];
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.png': 'image/png', '.txt': 'text/plain', '.json': 'application/json' };
const dist = join(root, 'send-dist');
const pageServer = createServer(async (request, response) => {
  const url = new URL(request.url, pageOrigin);
  if (url.pathname === '/send/') { response.writeHead(301, { Location: '/send' }).end(); return; }
  if (url.pathname.startsWith('/pair/v1/')) {
    relayLog.push(`${request.method} ${url.pathname.replace(/[A-Za-z0-9_-]{22,}/gu, '<id>')}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const headers = {};
    for (const name of ['authorization', 'content-type', 'accept']) if (request.headers[name]) headers[name] = request.headers[name];
    try {
      const answer = await fetch(`${upstream}/v1/${url.pathname.slice('/pair/v1/'.length)}`, {
        method: request.method, headers, redirect: 'error', body: ['POST', 'PUT'].includes(request.method) ? Buffer.concat(chunks) : undefined,
      });
      response.writeHead(answer.status, { 'Content-Type': answer.headers.get('content-type') ?? 'application/json', 'Cache-Control': 'no-store' });
      response.end(Buffer.from(await answer.arrayBuffer()));
    } catch {
      response.writeHead(502).end();
    }
    return;
  }
  const file = url.pathname === '/send' ? 'send.html' : normalize(url.pathname).replace(/^\/+/u, '');
  const path = join(dist, file);
  if (!path.startsWith(dist) || !existsSync(path) || !statSync(path).isFile()) { response.writeHead(404).end(); return; }
  response.writeHead(200, { 'Content-Type': types[extname(path)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
  response.end(readFileSync(path));
});
pageServer.listen(pagePort, '127.0.0.1');
await once(pageServer, 'listening');

// ---------------------------------------------------------- loopback services

symlinkSync(daemon, join(root, 'bin/wildbloomd-grants'));
symlinkSync(resolve(foregather), join(root, 'bin/foregather-server'));
const services = spawn('cargo', ['test', '--locked', '--manifest-path', 'desktop/src-tauri/Cargo.toml', '--bin', 'wildbloom-desktop', 'direct_receive_services', '--', '--ignored', '--nocapture'], {
  cwd: repo, detached: true, stdio: ['ignore', 'ignore', 'pipe'],
  env: { ...process.env, WILDBLOOM_E2E_BIN_DIR: join(root, 'bin'), WILDBLOOM_E2E_HANDOFF: handoff, WILDBLOOM_E2E_TURN_URL: turnUrl },
});
let servicesLog = '';
services.stderr.on('data', (chunk) => { servicesLog = (servicesLog + chunk).slice(-4000); });
children.push(services);

let app;
let browser;
let passed = false;
try {
  const svc = await until(() => {
    assert.equal(services.exitCode, null, `The services host exited:\n${servicesLog}`);
    const path = join(handoff, 'services.json');
    return existsSync(path) && JSON.parse(readFileSync(path, 'utf8'));
  }, 'the loopback services', 300_000, 250);
  upstream = svc.relayUpstream;
  log('ok  loopback services: Nostr relay and signer, Foregather live relay, online node issuing TURN credentials');

  // ---------------------------------------------------------------- the app
  const runId = randomBytes(16).toString('hex');
  let directLoads = 0;
  app = (() => {
    const child = spawn(appBinary, [], {
      env: {
        ...process.env, HOME: home, WILDBLOOM_ACCEPTANCE_ID: runId, WILDBLOOM_ACCEPTANCE_KEYCHAIN: 'memory',
        WILDBLOOM_DROP_LOOPBACK: '1', WILDBLOOM_DROP_RELAY: svc.relayApi, WILDBLOOM_DROP_SEND_BASE: `${pageOrigin}/send/`,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    children.push(child);
    let serial = 0;
    let buffer = '';
    let ready = false;
    const pending = new Map();
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let end;
      while ((end = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        let reply;
        try { reply = JSON.parse(line); } catch { continue; }
        if (reply.id === 0 && reply.value?.webview_ready) ready = true;
        if (reply.id === 0 && reply.value?.page_loaded === 'direct') directLoads += 1;
        const wait = pending.get(reply.id);
        if (wait) { pending.delete(reply.id); clearTimeout(wait.timer); wait.resolve(reply.value); }
      }
    });
    // Native output may carry diagnostics; it is never copied anywhere.
    child.stderr.resume();
    child.on('exit', (code, signal) => {
      for (const wait of pending.values()) { clearTimeout(wait.timer); wait.reject(new Error(`The app exited during ${wait.op}: ${code ?? signal}`)); }
      pending.clear();
    });
    const command = (op, script = '', window = undefined) => new Promise((done, fail) => {
      const id = ++serial;
      const timer = setTimeout(() => { pending.delete(id); fail(new Error(`Driver timed out: ${op}`)); }, 15_000);
      pending.set(id, { resolve: done, reject: fail, timer, op });
      child.stdin.write(`${JSON.stringify(window ? { id, op, script, window } : { id, op, script })}\n`);
    });
    const evaluate = async (script, window = 'drop') => {
      const value = await command('eval', `(()=>{try{return (${script});}catch(e){return {driver_error:String(e)}}})()`, window);
      if (value && typeof value === 'object' && 'driver_error' in value) throw new Error(`In the ${window} window: ${value.driver_error}`);
      return value;
    };
    return { child, command, evaluate, ready: () => ready };
  })();
  const status = await app.command('status');
  for (const path of [status.data_dir, status.config_dir]) {
    assert.ok(path.startsWith(home) && path.endsWith(`run${runId}`), 'Only the disposable profile under the temporary HOME is used.');
  }
  const tempDir = join(status.data_dir, 'drop-temp');
  await until(app.ready, 'the node window', 60_000);
  await until(async () => (await app.evaluate('!!window.__TAURI__?.core')) === true, 'the Drop window', 60_000);

  // Drive the Drop window's commands directly; the sheet is not needed for this.
  await app.evaluate(`(() => { if (window.__e2e) return true; const t = { states: [], results: {} }; window.__e2e = t;
    window.__TAURI__.event.listen('receive://state', (e) => { t.states.push({ at: Date.now(), ...e.payload }); });
    t.call = (key, cmd, args) => { t.results[key] = { pending: true };
      window.__TAURI__.core.invoke(cmd, args).then((v) => { t.results[key] = { ok: v ?? null }; }, (e) => { t.results[key] = { err: e ?? null }; }); return true; };
    return true; })()`);
  let calls = 0;
  async function call(cmd, args = undefined, window = 'drop') {
    const key = `c${++calls}`;
    if (window !== 'drop') {
      await app.evaluate(`(() => { window.__e2eResults ??= {}; window.__e2eResults[${JSON.stringify(key)}] = { pending: true };
        window.__TAURI__.core.invoke(${JSON.stringify(cmd)}, ${JSON.stringify(args ?? null)} ?? undefined).then((v) => { window.__e2eResults[${JSON.stringify(key)}] = { ok: v ?? null }; }, (e) => { window.__e2eResults[${JSON.stringify(key)}] = { err: e ?? null }; }); return true; })()`, window);
      const result = await until(async () => { const r = await app.evaluate(`window.__e2eResults[${JSON.stringify(key)}]`, window); return r && !r.pending && r; }, cmd);
      assert.ok(!('err' in result), `${cmd} was refused: ${JSON.stringify(result.err)}`);
      return result.ok;
    }
    await app.evaluate(`window.__e2e.call(${JSON.stringify(key)}, ${JSON.stringify(cmd)}, ${JSON.stringify(args ?? null)} ?? undefined)`);
    const result = await until(async () => { const r = await app.evaluate(`window.__e2e.results[${JSON.stringify(key)}]`); return r && !r.pending && r; }, cmd, 60_000);
    assert.ok(!('err' in result), `${cmd} was refused: ${JSON.stringify(result.err)}`);
    return result.ok;
  }
  const stateCount = () => app.evaluate('window.__e2e.states.length');
  const lastState = () => app.evaluate('(() => { const s = window.__e2e.states.at(-1); return s ? { state: s.state, reason: s.reason ?? null, by: s.by ?? null, acknowledged: s.acknowledged ?? null } : null; })()');
  async function waitState(from, states, timeout = 60_000) {
    return until(async () => app.evaluate(`(() => { const want = ${JSON.stringify(states)}; return window.__e2e.states.slice(${from}).find((s) => want.includes(s.state)) ?? false; })()`),
      async () => `${states.join(' or ')} (last: ${JSON.stringify(await lastState())})`, timeout, 100);
  }

  // First run: the online node, approval through the signer, the recovery key.
  await call('check_online_node', { url: svc.onlineUrl });
  await call('set_online_node', { url: svc.onlineUrl });
  await call('approve_device', { bunkerUrl: svc.bunker });
  await until(async () => {
    const approval = await call('approval_status');
    assert.ok(approval.state === 'waiting' || approval.state === 'approved', `approval ${approval.state}`);
    return approval.state === 'approved';
  }, 'the signer to approve this computer', 90_000, 500);
  await call('recovery_key_for_display');
  await call('confirm_recovery_saved');
  // Both ends show their addresses for this run (host candidates).
  await call('set_receiving', { hideAddress: false }, 'main');
  log('ok  the app is set up: online node approved through the NIP-46 signer, hiding off');

  // ---------------------------------------------------------------- the phone
  const executablePath = process.env.WILDBLOOM_BROWSER_EXECUTABLE ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  browser = await chromium.launch({ headless: true, executablePath, args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] });
  async function openPhone(link, on = browser) {
    const context = await on.newContext({ ...devices['Pixel 7'], acceptDownloads: false });
    await context.addInitScript(() => {
      const Original = window.RTCPeerConnection;
      window.__rtc = [];
      window.__rtcConfigs = [];
      window.RTCPeerConnection = class extends Original {
        constructor(configuration, ...rest) {
          super(configuration, ...rest);
          window.__rtc.push(this);
          window.__rtcConfigs.push({ policy: configuration?.iceTransportPolicy ?? 'all', urls: (configuration?.iceServers ?? []).flatMap((s) => [].concat(s.urls)) });
        }
      };
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    await page.goto(link);
    return { context, page, errors };
  }
  const title = (page) => page.locator('#title').textContent();
  const expectTitle = (page, text, timeout = 60_000) => page.waitForFunction((t) => document.getElementById('title')?.textContent === t, text, { timeout })
    .catch(async () => { throw new Error(`Expected "${text}" but the phone shows "${await title(page).catch(() => '?')}"`); });
  const rtcCount = (page) => page.evaluate(() => window.__rtc.length);
  const selectedPair = (page) => page.evaluate(async () => {
    const pc = window.__rtc[0];
    if (!pc) return undefined;
    const reports = new Map();
    (await pc.getStats()).forEach((r) => reports.set(r.id, r));
    let pair;
    for (const r of reports.values()) if (r.type === 'transport' && r.selectedCandidatePairId) pair = reports.get(r.selectedCandidatePairId);
    const kind = (id) => reports.get(id)?.candidateType ?? 'unknown';
    return pair ? { local: kind(pair.localCandidateId), remote: kind(pair.remoteCandidateId) } : undefined;
  }).catch(() => undefined);

  /** The words, the check words and a file chosen: Drop is asking its owner. */
  async function toConsent(file, name, on = browser) {
    const from = await stateCount();
    await call('receive_start');
    const waiting = await waitState(from, ['waiting']);
    assert.ok(waiting.link?.startsWith(`${pageOrigin}/send/`) && waiting.words?.length === 4, 'Drop shows a link to the page and four words.');
    const phone = await openPhone(waiting.link, on);
    await expectTitle(phone.page, 'Send a file');
    await phone.page.locator('#words').fill(waiting.words.join(' '));
    await phone.page.getByRole('button', { name: 'Continue' }).click();
    await expectTitle(phone.page, 'Check these words with them');
    const check = await waitState(from, ['check']);
    const shown = (await phone.page.locator('.words-list li').allInnerTexts()).map((word) => word.trim());
    assert.deepEqual(shown, check.checkWords, 'Both show the same three check words.');
    await call('receive_verify', { matches: true });
    await phone.page.getByRole('button', { name: 'Yes, they match' }).click();
    await expectTitle(phone.page, 'Choose a file');
    const [chooser] = await Promise.all([phone.page.waitForEvent('filechooser'), phone.page.getByRole('button', { name: /^Choose (a|another) file$/u }).click()]);
    await chooser.setFiles(file);
    await expectTitle(phone.page, 'Waiting for them to accept');
    const consent = await waitState(from, ['consent']);
    assert.equal(consent.name, name);
    assert.equal(consent.size, statSync(file).size);
    assert.equal(await rtcCount(phone.page), 0, 'No peer connection before the owner accepts.');
    return { phone, from };
  }
  const receivedNow = () => filesUnder(received).map((path) => path.slice(received.length + 1)).sort();

  // ------------------------------------------- 1. a file arrives and is kept
  {
    const name = 'Holiday film (direct).mp4';
    const file = join(root, name);
    const bytes = Buffer.alloc(KEPT_BYTES);
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = (i * 131 + (i >> 11) * 7) & 0xff;
    writeFileSync(file, bytes);
    const loads = directLoads;
    const { phone, from } = await toConsent(file, name);
    const accepted = Date.now();
    await call('receive_consent', { accept: true });
    const paths = [];
    const sampler = setInterval(() => { selectedPair(phone.page).then((p) => { if (p) paths.push(p); }); }, 250);
    const final = await waitState(from, ['kept', 'failed', 'cancelled'], 240_000);
    clearInterval(sampler);
    assert.equal(final.state, 'kept', `Drop ended ${final.state} (${final.reason ?? final.by ?? ''})`);
    await expectTitle(phone.page, 'Sent');
    const states = await app.evaluate(`window.__e2e.states.slice(${from}).map((s) => ({ state: s.state, at: s.at, acknowledged: s.acknowledged ?? null, total: s.total ?? null, hidden: s.hidden ?? null }))`);
    const firstReceiving = states.find((s) => s.state === 'receiving');
    const verifying = states.find((s) => s.state === 'verifying');
    assert.ok(firstReceiving && verifying, 'Drop went through receiving and verifying.');
    assert.equal(firstReceiving.hidden, false);
    const acks = states.filter((s) => s.state === 'receiving').map((s) => s.acknowledged);
    for (let i = 1; i < acks.length; i += 1) assert.ok(acks[i] >= acks[i - 1], 'Progress only moves forward.');
    assert.equal(acks.at(-1), firstReceiving.total, 'Every envelope byte was acknowledged.');
    const kept = join(received, name);
    assert.ok(existsSync(kept), 'The file is in the Received folder.');
    assert.equal(sha256(readFileSync(kept)), sha256(bytes), 'Byte for byte the file the phone sent.');
    assert.equal(final.path, `~/Downloads/Wildbloom Received/${name}`);
    assert.deepEqual(leftIn(tempDir), [], 'Nothing is left in Drop\'s temporary folder.');
    assert.equal(directLoads - loads, 1, 'One hidden window for the transfer.');
    assert.equal(await rtcCount(phone.page), 1, 'The phone made one peer connection.');
    const [phoneConfig] = await phone.page.evaluate(() => window.__rtcConfigs);
    assert.deepEqual(phoneConfig, { policy: 'all', urls: [turnUrl] }, 'The phone used the invitation\'s server and nothing else.');
    const path = paths.at(-1);
    assert.ok(path && ['host', 'prflx'].includes(path.local) && ['host', 'prflx'].includes(path.remote), `A direct path, not ${JSON.stringify(path)}`);
    assert.deepEqual(phone.errors, []);
    const seconds = (verifying.at - firstReceiving.at) / 1000;
    const journey = {
      name: 'kept', file_bytes: bytes.length, envelope_bytes: firstReceiving.total, sha256: sha256(bytes),
      accept_to_kept_s: (final.at - accepted) / 1000, connect_s: (firstReceiving.at - accepted) / 1000, transfer_s: seconds,
      verify_s: (final.at - verifying.at) / 1000, frames: Math.ceil(firstReceiving.total / 65_527), mb_per_s: Number((firstReceiving.total / 1e6 / seconds).toFixed(2)),
      path, hidden: false, received_as: final.path,
    };
    evidence.journeys.push(journey);
    log(`ok  kept: ${bytes.length} bytes byte for byte in ~/Downloads/Wildbloom Received in ${journey.transfer_s.toFixed(1)} s (${journey.mb_per_s} MB/s) over ${path.local}/${path.remote}`);
    await phone.context.close();
  }

  // ------------------------------- 2. the page is closed mid-transfer
  {
    const name = 'closing.bin';
    const file = join(root, name);
    const descriptor = openSync(file, 'w');
    ftruncateSync(descriptor, CLOSED_BYTES);
    closeSync(descriptor);
    const before = receivedNow();
    const loads = directLoads;
    const { phone, from } = await toConsent(file, name);
    await call('receive_consent', { accept: true });
    const under = await until(async () => app.evaluate(`window.__e2e.states.slice(${from}).find((s) => s.state === 'receiving' && s.acknowledged >= 8 * 1024 * 1024) ?? window.__e2e.states.slice(${from}).find((s) => ['kept', 'failed', 'cancelled'].includes(s.state)) ?? false`),
      async () => `the transfer to be under way (last: ${JSON.stringify(await lastState())})`, 120_000);
    assert.equal(under.state, 'receiving', `It ended before the page could be closed: ${under.state}`);
    const closedAt = Date.now();
    await phone.page.close({ runBeforeUnload: false });
    const final = await waitState(from, ['kept', 'failed', 'cancelled'], 120_000);
    assert.ok((final.state === 'cancelled' && final.by === 'them') || (final.state === 'failed' && final.reason === 'lost'), `Drop ended ${final.state} ${final.by ?? final.reason}`);
    await until(() => leftIn(tempDir).length === 0, 'the temporary folder to empty', 15_000);
    assert.deepEqual(receivedNow(), before, 'Nothing new in the Received folder.');
    assert.equal(directLoads - loads, 1);
    const journey = { name: 'page-closed', file_bytes: CLOSED_BYTES, acknowledged_at_close: under.acknowledged, ended: final.state === 'cancelled' ? 'cancelled by them' : 'failed lost', noticed_s: (final.at - closedAt) / 1000 };
    evidence.journeys.push(journey);
    log(`ok  page closed after ${under.acknowledged} of ${CLOSED_BYTES} bytes: Drop says ${journey.ended} in ${journey.noticed_s.toFixed(1)} s, nothing kept, temp folder empty`);
    await phone.context.close();
  }

  // ------------- 3. the phone vanishes: its browser is killed, nothing says goodbye
  // WebKit never fires the channel's close for this; the end comes from the
  // connection state, Drop's restart (unanswered) and its 45 s give-up.
  {
    const name = 'vanishing.bin';
    const file = join(root, name);
    const descriptor = openSync(file, 'w');
    ftruncateSync(descriptor, CLOSED_BYTES);
    closeSync(descriptor);
    const before = receivedNow();
    const server = await chromium.launchServer({ headless: true, executablePath, args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] });
    const doomed = await chromium.connect(server.wsEndpoint());
    const { from } = await toConsent(file, name, doomed);
    await call('receive_consent', { accept: true });
    const under = await until(async () => app.evaluate(`window.__e2e.states.slice(${from}).find((s) => s.state === 'receiving' && s.acknowledged >= 8 * 1024 * 1024) ?? window.__e2e.states.slice(${from}).find((s) => ['kept', 'failed', 'cancelled'].includes(s.state)) ?? false`),
      async () => `the transfer to be under way (last: ${JSON.stringify(await lastState())})`, 120_000);
    assert.equal(under.state, 'receiving', `It ended before the phone could vanish: ${under.state}`);
    const killedAt = Date.now();
    const pid = server.process().pid;
    try { process.kill(-pid, 'SIGKILL'); } catch { process.kill(pid, 'SIGKILL'); }
    const final = await waitState(from, ['kept', 'failed', 'cancelled'], 180_000);
    assert.equal(final.state, 'failed', `Drop ended ${final.state} ${final.by ?? ''}`);
    assert.equal(final.reason, 'lost');
    const seen = await app.evaluate(`window.__e2e.states.slice(${from}).filter((s) => s.reconnecting === true).map((s) => s.at)`);
    assert.ok(seen.length > 0, 'Drop showed it was reconnecting before it gave up.');
    await until(() => leftIn(tempDir).length === 0, 'the temporary folder to empty', 15_000);
    assert.deepEqual(receivedNow(), before, 'Nothing new in the Received folder.');
    const journey = { name: 'phone-vanished', file_bytes: CLOSED_BYTES, acknowledged_at_kill: under.acknowledged, ended: 'failed lost', reconnecting_after_s: (seen[0] - killedAt) / 1000, gave_up_s: (final.at - killedAt) / 1000 };
    evidence.journeys.push(journey);
    log(`ok  phone killed after ${under.acknowledged} bytes: Drop showed reconnecting after ${journey.reconnecting_after_s.toFixed(1)} s and gave up (failed lost) after ${journey.gave_up_s.toFixed(1)} s, nothing kept`);
    await doomed.close().catch(() => undefined);
    await server.close().catch(() => undefined);
  }

  // ------------------------------------------- 4. the owner declines
  {
    const name = 'private.pdf';
    const file = join(root, name);
    writeFileSync(file, randomBytes(50_000));
    const before = receivedNow();
    const loads = directLoads;
    const { phone, from } = await toConsent(file, name);
    await call('receive_consent', { accept: false });
    const final = await waitState(from, ['declined', 'failed', 'cancelled', 'kept']);
    assert.equal(final.state, 'declined');
    await expectTitle(phone.page, 'They said no');
    await pause(1000);
    assert.equal(await rtcCount(phone.page), 0, 'The phone made no peer connection.');
    assert.equal(directLoads - loads, 0, 'Drop never opened its hidden window.');
    const seen = await app.evaluate(`window.__e2e.states.slice(${from}).map((s) => s.state)`);
    assert.ok(!seen.includes('connecting') && !seen.includes('receiving'), `Drop never connected: ${seen.join(', ')}`);
    assert.deepEqual(receivedNow(), before);
    evidence.journeys.push({ name: 'declined', phone_peer_connections: 0, direct_window_loads: 0, states: seen });
    log('ok  declined: Drop never opened its hidden window, the phone made no peer connection, nothing kept');
    await phone.context.close();
  }

  evidence.relay_requests = [...new Set(relayLog)].length;
  evidence.passed = passed = true;
  log('Receive a file passed end to end in the real app.');
} finally {
  writeFileSync(join(handoff, 'finished.json'), '{}');
  await browser?.close().catch(() => undefined);
  if (app && app.child.exitCode === null) {
    await Promise.race([app.command('quit').catch(() => undefined), pause(5000)]);
    await Promise.race([once(app.child, 'exit'), pause(10_000)]);
  }
  pageServer.close();
  await Promise.race([once(services, 'exit'), pause(15_000)]);
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) {
      try { process.kill(child === services ? -child.pid : child.pid, 'SIGKILL'); } catch { /* gone */ }
    }
  }
  // The app's own node, if it outlived the app.
  for (const line of execFileSync('ps', ['-axo', 'pid=,args='], { encoding: 'utf8' }).split('\n')) {
    const match = line.trim().match(/^(\d+)\s+(.*)$/u);
    if (match && match[2].includes(root)) try { process.kill(Number(match[1]), 'SIGKILL'); } catch { /* gone */ }
  }
  writeFileSync(join(root, 'evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  log(`evidence: ${join(root, 'evidence.json')}`);
  if (passed && process.env.DIRECT_KEEP !== '1') rmSync(root, { recursive: true, force: true });
}
