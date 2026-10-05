import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { release, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Actual native webview, production UI/IPC/supervision and bundled daemon.
// The compile-time debug driver controls only an isolated acceptance profile.
assert.ok(['darwin', 'linux', 'win32'].includes(process.platform), 'Unsupported native platform');
const exe = process.platform === 'win32' ? '.exe' : '';
const platformName = { darwin: 'macOS', linux: 'Linux', win32: 'Windows' }[process.platform];
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const appBinary = join(repo, `desktop/src-tauri/target/debug/wildbloom-desktop${exe}`);
const daemon = join(dirname(appBinary), `wildbloomd${exe}`);
const signer = join(repo, `target/debug/examples/acceptance_signer${exe}`);
for (const file of [appBinary, daemon, signer]) assert.ok(existsSync(file), 'Build the native acceptance binaries first.');
const root = mkdtempSync(join(tmpdir(), 'wildbloom-native-pools-'));
const runId = randomBytes(16).toString('hex');
const profileSuffix = `dev.forgesworn.wildbloom-acceptance.${runId}`;
const children = [], profiles = new Set();
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const started = Date.now();
const evidence = {
  schema: 'wildbloom.native-desktop-pools.v1', passed: false,
  scope: `${platformName} native debug webview with compile-time driver; real IPC and local nodes; not signed-installer or physical multi-device acceptance`,
  platform: process.platform,
  receipt_permissions: process.platform === 'win32' ? 'Windows ACL acceptance remains separate' : 'Unix private mode checked',
  source_commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim(),
  source_dirty: execFileSync('git', ['status', '--porcelain'], { cwd: repo, encoding: 'utf8' }).trim().length > 0,
  os_version: process.platform === 'darwin' ? execFileSync('sw_vers', ['-productVersion'], { encoding: 'utf8' }).trim() : release(),
  architecture: process.arch, app_sha256: sha(readFileSync(appBinary)), daemon_sha256: sha(readFileSync(daemon)),
  harness_sha256: sha(readFileSync(fileURLToPath(import.meta.url))),
  checks: [],
};
function passed(name) { evidence.checks.push(name); console.log(`PASS ${name}`); }
async function until(fn, label, timeout = 20000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await pause(100); }
  throw new Error(`Timed out: ${label}`);
}
async function bounded(promise, label, timeout = 15000) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label)), timeout);
  })]); } finally { clearTimeout(timer); }
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const done = once(child, 'exit'); child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
  try { await done; } finally { clearTimeout(timer); }
}
async function freePort() {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise((r) => server.close(r)); return port;
}
const owner = execFileSync(signer, ['--public-key'], { encoding: 'utf8' }).trim();
function sign(event) {
  return JSON.parse(execFileSync(signer, [], { input: JSON.stringify({ pubkey: owner, created_at: Math.floor(Date.now() / 1000), ...event }), encoding: 'utf8' }));
}
async function startNode(node, generation) {
  node.child = spawn(daemon, ['--no-tor', '--bind', new URL(node.origin).host, '--public-url', node.origin,
    '--allow-pubkey', owner, '--data-dir', join(root, `node-${node.index}-${generation}`), '--repair-interval', '0'], { stdio: 'ignore' });
  children.push(node.child);
  await until(async () => {
    assert.equal(node.child.exitCode, null);
    try { return (await fetch(`${node.origin}healthz`, { signal: AbortSignal.timeout(300) })).ok; } catch { return false; }
  }, 'storage node readiness');
}
function launchApp() {
  const child = spawn(appBinary, [], { env: { ...process.env, WILDBLOOM_ACCEPTANCE_ID: runId }, stdio: ['pipe', 'pipe', 'pipe'] });
  children.push(child);
  let serial = 0, buffer = '', webviewReady = false;
  const pending = new Map();
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    assert.ok(buffer.length < 1024 * 1024, 'Bounded native driver output');
    let end;
    while ((end = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      let reply; try { reply = JSON.parse(line); } catch { continue; }
      if (reply.id === 0 && reply.value?.webview_ready) webviewReady = true;
      const wait = pending.get(reply.id);
      if (wait) { pending.delete(reply.id); clearTimeout(wait.timer); wait.resolve(reply.value); }
    }
  });
  // Never copy native output, signer events or receipt contents into evidence.
  child.stderr.resume();
  child.on('exit', () => {
    for (const wait of pending.values()) { clearTimeout(wait.timer); wait.reject(new Error('Native app exited during driver command')); }
    pending.clear();
  });
  const command = (op, script = '') => new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Native driver timed out: ${op}`)); }, 15000);
    pending.set(id, { resolve, reject, timer });
    child.stdin.write(`${JSON.stringify({ id, op, script })}\n`);
  });
  const evaluate = (script) => command('eval', `(()=>{try{return (${script});}catch(e){return {driver_error:String(e)}}})()`);
  return { child, command, evaluate, ready: () => webviewReady };
}
// WebKitGTK and WebView2 have their own children. Count only real daemon
// children, so webview subprocesses neither fail nor satisfy supervision checks.
function descendants(parent) {
  assert.ok(Number.isSafeInteger(parent) && parent > 0);
  if (process.platform === 'win32') {
    const output = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
      `Get-CimInstance Win32_Process -Filter "ParentProcessId = ${parent} AND Name = 'wildbloomd.exe'" | ForEach-Object { $_.ProcessId }`],
    { encoding: 'utf8', timeout: 10000 }).trim();
    return output ? output.split(/\s+/).map(Number) : [];
  }
  return execFileSync('ps', ['-axo', 'pid=,ppid=,comm='], { encoding: 'utf8' }).trim().split('\n')
    .map((line) => line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/))
    .filter((row) => row && Number(row[2]) === parent && basename(row[3]) === 'wildbloomd')
    .map((row) => Number(row[1]));
}
function alive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }
const record = join(root, 'signer-count');
const signatures = () => existsSync(record) ? readFileSync(record, 'utf8').split('\n').filter(Boolean).length : 0;
let app;
try {
  const nodes = [];
  for (let index = 0; index < 4; index++) {
    const node = { index, origin: `http://127.0.0.1:${await freePort()}/` };
    await startNode(node, 0); nodes.push(node);
  }
  // Independent 2-of-4 coding fixture: generator rows [1,0], [0,1], [3,2], [2,3].
  // Opaque deterministic bytes stand in for ciphertext; browser decryption has
  // its separate acceptance suite. Neither desktop nor owner service sees a key.
  const payload = Buffer.alloc(65555); for (let i = 0; i < payload.length; i++) payload[i] = (i * 17 + (i >> 8)) & 255;
  payload.write('FSWNENC2');
  const size = Math.ceil(payload.length / 2), a = Buffer.alloc(size), b = Buffer.alloc(size);
  payload.copy(a, 0, 0, size); payload.copy(b, 0, size);
  const twice = (v) => ((v << 1) ^ (v & 128 ? 0x11d : 0)) & 255;
  const parts = [a, b, Buffer.from(a.map((v, i) => twice(v) ^ v ^ twice(b[i]))), Buffer.from(a.map((v, i) => twice(v) ^ twice(b[i]) ^ b[i]))];
  const manifest = { type: 'wildbloom.pool', version: 1, mode: 'erasure', profile: 'direct',
    payload: { sha256: sha(payload), size: payload.length, encryption: 'forgesworn-aes-256-gcm-chunked-v2' }, required: 2, total: 4, copies: 1,
    parts: parts.map((bytes, index) => ({ index, sha256: sha(bytes), size: bytes.length,
      targets: [{ id: `node-${index}`, origin: nodes[index].origin, failure_group: `site-${index}`, weight: 1 }] })) };
  const receipt = sign({ kind: 30078, content: JSON.stringify(manifest), tags: [['d', `wildbloom.pool.v1:${sha(payload)}`]] });
  for (const part of manifest.parts) {
    const auth = sign({ kind: 24242, content: 'Synthetic native acceptance upload', tags: [['t', 'upload'], ['x', part.sha256], ['server', '127.0.0.1'], ['expiration', String(Math.floor(Date.now() / 1000) + 120)]] });
    const response = await fetch(`${nodes[part.index].origin}upload`, { method: 'PUT', body: parts[part.index],
      headers: { Authorization: `Nostr ${Buffer.from(JSON.stringify(auth)).toString('base64url')}`, 'Content-Type': 'application/octet-stream', 'X-SHA-256': part.sha256 } });
    assert.ok(response.ok, `Fixture upload returned ${response.status}`);
  }
  async function verifyPart(index) {
    const res = await fetch(`${nodes[index].origin}${manifest.parts[index].sha256}`, { signal: AbortSignal.timeout(2000) });
    return res.ok && sha(Buffer.from(await res.arrayBuffer())) === manifest.parts[index].sha256;
  }
  async function boot() {
    app = launchApp();
    const dirs = await app.command('status');
    for (const path of [dirs.data_dir, dirs.config_dir]) {
      assert.ok(basename(path) === profileSuffix, 'Only the unique test profile may be touched'); profiles.add(path);
    }
    await until(app.ready, 'native page load');
    await until(async () => await app.evaluate('!!document.querySelector("#pool-import")') === true, 'native UI ready');
    return dirs.data_dir;
  }
  const dataDir = await boot();
  evidence.webview_user_agent = await app.evaluate('navigator.userAgent');
  await pause(500);
  assert.equal(descendants(app.child.pid).length, 0, 'Fresh app must not start a node/repair automatically');
  assert.equal(signatures(), 0);
  passed('native app starts without storage, signer or repair children');

  const importAction = `(()=>{
    const transfer=new DataTransfer(); transfer.items.add(new File([${JSON.stringify(JSON.stringify(receipt))}], 'receipt.json', {type:'application/json'}));
    document.querySelector('#pool-receipt').files=transfer.files;
    document.querySelector('#pool-receipt').dispatchEvent(new Event('input',{bubbles:true}));
    const owner=document.querySelector('#pool-owner'); owner.value=${JSON.stringify(owner)}; owner.dispatchEvent(new Event('input',{bubbles:true}));
    document.querySelector('#pool-import').click(); return true;
  })()`;
  assert.equal(await app.evaluate(importAction), true);
  await until(async () => await app.evaluate('!document.querySelector("#pool-details").hidden') === true, 'real receipt import');
  const saved = join(dataDir, 'owner-pools', receipt.id, 'receipt.json');
  assert.deepEqual(JSON.parse(readFileSync(saved)), receipt);
  if (process.platform !== 'win32') assert.equal(statSync(saved).mode & 0o077, 0);
  assert.equal(signatures(), 0);
  passed('receipt imported through native webview and real IPC; receipt persisted in isolated application profile');
  await app.evaluate('document.querySelector("#pool-check").click()');
  await until(async () => await app.evaluate('document.querySelector("#pool-health").textContent.includes("Requested protection verified")') === true, 'read-only health');
  assert.equal(signatures(), 0);
  const work = join(dataDir, 'owner-pools', receipt.id, 'work');
  assert.equal(JSON.parse(readFileSync(join(work, 'pool-report.json'))).uploads_attempted, 0);
  passed('desktop read-only check verifies four real parts without signing or uploading');
  for (const index of [0, 1]) { await stop(nodes[index].child); await startNode(nodes[index], 1); }
  await until(async () => await app.evaluate('!document.querySelector("#pool-check").disabled') === true, 'check completion');
  await app.evaluate('document.querySelector("#pool-check").click()');
  await until(async () => await app.evaluate('document.querySelector("#pool-health").textContent.includes("Needs repair")') === true, 'degraded health');
  await until(async () => await app.evaluate('!document.querySelector("#pool-check").disabled') === true, 'degraded check completion');
  passed('desktop reports recoverable but underprotected after two disposable stores are lost');

  assert.equal(await app.evaluate(`(()=>{
    for(const [id,value] of ${JSON.stringify([['pool-signer', signer], ['pool-signer-arguments', `--record\n${record}`], ['pool-interval', '5'], ['pool-transfer', '1'], ['pool-disk', '1']])}){
      const el=document.getElementById(id); el.value=value; el.dispatchEvent(new Event('input',{bubbles:true}));
    }
    const deadline=new Date(Date.now()-60000); deadline.setMinutes(deadline.getMinutes()-deadline.getTimezoneOffset());
    const expiry=document.querySelector('#pool-expiry');expiry.value=deadline.toISOString().slice(0,16);expiry.dispatchEvent(new Event('input',{bubbles:true}));
    const consent=document.querySelector('#pool-consent'); consent.checked=true; consent.dispatchEvent(new Event('change',{bubbles:true}));
    document.querySelector('#pool-start').click();return true;
  })()`), true);
  await until(async () => await app.evaluate('document.querySelector("#pool-action-status").textContent.includes("Authority must expire within the next year")') === true, 'expired authority rejected');
  assert.equal(signatures(), 0);
  assert.equal(descendants(app.child.pid).length, 0);
  assert.equal(await verifyPart(0), false);
  assert.equal(await verifyPart(1), false);
  passed('native IPC rejects expired authority without starting a worker, signing or repairing');
  await app.evaluate(`(()=>{
    const deadline=new Date(Date.now()+300000); deadline.setMinutes(deadline.getMinutes()-deadline.getTimezoneOffset());
    const expiry=document.querySelector('#pool-expiry'); expiry.value=deadline.toISOString().slice(0,16); expiry.dispatchEvent(new Event('input',{bubbles:true}));
    const consent=document.querySelector('#pool-consent'); consent.checked=true; consent.dispatchEvent(new Event('change',{bubbles:true}));
    document.querySelector('#pool-start').click(); return true;
  })()`);
  await until(async () => await app.evaluate('document.querySelector("#pool-action-status").textContent.includes("Automatic repair started")') === true, 'repair action accepted');
  await until(async () => await verifyPart(0) && await verifyPart(1), 'desktop owner repair', 45000);
  assert.ok(signatures() >= 2);
  await until(async () => descendants(app.child.pid).length === 1, 'one supervised repair child');
  passed('desktop starts the real owner service and restores both missing parts');

  await app.evaluate('document.querySelector("#pool-stop").click()');
  await until(async () => await app.evaluate('document.querySelector("#pool-action-status").textContent === "Pool process stopped."') === true, 'explicit stop action');
  assert.equal(descendants(app.child.pid).length, 0);
  assert.equal(await app.evaluate('document.querySelector("#pool-consent").checked'), false);
  passed('desktop Stop action terminates the real child and revokes repair consent');
  await until(async () => await app.evaluate('!document.querySelector("#pool-check").disabled') === true, 'stopped controls');
  await app.evaluate('(()=>{const c=document.querySelector("#pool-consent");c.checked=true;c.dispatchEvent(new Event("change",{bubbles:true}));document.querySelector("#pool-start").click();return true})()');
  await until(async () => await app.evaluate('document.querySelector("#pool-action-status").textContent.includes("Automatic repair started")') === true, 'explicit restart');
  await until(() => descendants(app.child.pid).length === 1, 'restarted owner child');

  assert.equal((await app.command('close')).ok, true);
  await until(async () => (await app.command('status')).visible === false, 'close-to-tray');
  const beforeTrayRepair = signatures();
  await stop(nodes[0].child); await startNode(nodes[0], 2);
  await until(() => verifyPart(0), 'repair while native window is closed', 20000);
  assert.ok(signatures() > beforeTrayRepair);
  assert.equal((await app.command('status')).visible, false);
  assert.ok(alive(app.child.pid));
  passed('real window close hides to tray; resident repair restores another lost part');
  const ownerChildren = descendants(app.child.pid); assert.equal(ownerChildren.length, 1);
  const exited = once(app.child, 'exit');
  await app.command('quit');
  const [exitCode] = await bounded(exited, 'Desktop quit hung');
  assert.equal(exitCode, 0);
  await until(() => ownerChildren.every((pid) => !alive(pid)), 'repair children exit on app quit');
  assert.ok(readdirSync(work).every((name) => !name.startsWith('pool-pass-')));
  passed('native app quit exits cleanly, stops owner child and removes temporary reconstruction files');

  const signaturesAtQuit = signatures();
  await stop(nodes[0].child); await startNode(nodes[0], 3);
  await boot();
  await until(async () => await app.evaluate('!document.querySelector("#pool-details").hidden') === true, 'receipt reload after reopening');
  assert.equal(await app.evaluate('document.querySelector("#pool-signer").value'), '');
  assert.equal(await app.evaluate('document.querySelector("#pool-consent").checked'), false);
  assert.equal(await app.evaluate('document.querySelector("#pool-start").disabled'), true);
  assert.match(await app.evaluate('document.querySelector("#pool-health").textContent'), /not yet verified/);
  await pause(6500);
  assert.equal(signatures(), signaturesAtQuit);
  assert.equal(await verifyPart(0), false);
  assert.equal(descendants(app.child.pid).length, 0);
  assert.deepEqual(JSON.parse(readFileSync(saved)), receipt);
  passed('reopening retains the receipt but no signer, consent, child or automatic repair authority');
  // A fresh read-only check also proves quit released the work-directory lock.
  await app.evaluate('document.querySelector("#pool-check").click()');
  await until(async () => await app.evaluate('document.querySelector("#pool-health").textContent.includes("Needs repair")') === true, 'fresh check after restart');
  assert.equal(signatures(), signaturesAtQuit);
  passed('fresh post-restart check reuses the released lock and reports current degraded storage');
  await until(async () => await app.evaluate('!document.querySelector("#pool-check").disabled') === true, 'final check completion');
  // Model the exact disposable files left by an interrupted owner pass. Real
  // forced-process failures are exercised by the daemon's subprocess suite.
  const leftover = join(work, 'pool-pass-Ab1234');
  mkdirSync(leftover, { mode: 0o700 });
  writeFileSync(join(leftover, 'source-0'), Buffer.from('synthetic temporary ciphertext'));
  const reportBeforeCleanup = readFileSync(join(work, 'pool-report.json'));
  await app.evaluate('document.querySelector("#pool-review-cleanup").click()');
  await until(async () => await app.evaluate('document.querySelector("#pool-cleanup-status").textContent.includes("1 interrupted repair folder")') === true, 'native cleanup review');
  assert.equal(await app.evaluate('document.querySelector("#pool-clear-cleanup").disabled'), true);
  assert.ok(existsSync(join(leftover, 'source-0')), 'Review must not delete');
  writeFileSync(join(leftover, 'coded-1'), Buffer.from('changed since review'));
  const confirmCleanup = '(()=>{const c=document.querySelector("#pool-cleanup-consent");c.checked=true;c.dispatchEvent(new Event("change",{bubbles:true}));document.querySelector("#pool-clear-cleanup").click();return true})()';
  await app.evaluate(confirmCleanup);
  await until(async () => await app.evaluate('document.querySelector("#pool-action-status").textContent.includes("changed since review")') === true, 'stale cleanup rejected');
  assert.ok(existsSync(join(leftover, 'source-0')));
  await app.evaluate('document.querySelector("#pool-review-cleanup").click()');
  await until(async () => await app.evaluate('!document.querySelector("#pool-cleanup-consent").disabled') === true, 'fresh cleanup review');
  await app.evaluate(confirmCleanup);
  await until(async () => await app.evaluate('document.querySelector("#pool-cleanup-status").textContent.includes("Repair remains stopped")') === true, 'native confirmed cleanup');
  assert.equal(existsSync(leftover), false);
  assert.deepEqual(readFileSync(join(work, 'pool-report.json')), reportBeforeCleanup);
  assert.deepEqual(JSON.parse(readFileSync(saved)), receipt);
  assert.equal(signatures(), signaturesAtQuit);
  assert.equal(descendants(app.child.pid).length, 0);
  assert.equal(await app.evaluate('document.querySelector("#pool-consent").checked'), false);
  passed('native cleanup requires review and confirmation, refuses changed files, preserves receipt/report and stays stopped');
  await app.evaluate('document.querySelector("#pool-check").click()');
  await until(async () => await app.evaluate('document.querySelector("#pool-health").textContent.includes("Needs repair") && !document.querySelector("#pool-check").disabled') === true, 'read-only check after cleanup');
  assert.equal(signatures(), signaturesAtQuit);
  passed('explicit read-only check works after clearing interrupted repair files');
  const finalExit = once(app.child, 'exit'); await app.command('quit');
  assert.equal((await bounded(finalExit, 'Final quit hung'))[0], 0);
  evidence.passed = true;
} finally {
  if (app?.child.exitCode === null) app.child.stdin.end();
  await Promise.all(children.map(stop));
  for (const path of profiles) {
    assert.ok(basename(path) === profileSuffix); rmSync(path, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
  rmSync(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  evidence.duration_ms = Date.now() - started;
  if (process.env.WILDBLOOM_NATIVE_EVIDENCE) writeFileSync(process.env.WILDBLOOM_NATIVE_EVIDENCE, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
}
console.log(`Native desktop pool acceptance passed (${(evidence.duration_ms / 1000).toFixed(1)}s).`);
