// The hidden direct-send window (desktop/ui/direct.js) in headless Chromium,
// against a fake Tauri bridge that stands in for Rust. The other end is a
// second DirectPeer from the same vendored bundle, in the same page, playing
// the phone with the raw frame helpers, so every frame on the wire is real:
// a real RTCPeerConnection pair over host candidates, real DATA, ACK, END,
// KEPT and STOP frames. Synthetic credentials only.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const here = dirname(fileURLToPath(import.meta.url));
const ui = resolve(here, '../ui');
const repo = resolve(here, '../..');

// The committed bundle is the one its provenance names.
execFileSync(process.execPath, [join(repo, 'scripts/vendor-direct.mjs'), '--check'], { stdio: 'inherit' });

// Served under Drop's own CSP, so the module and its vendored import must load as they do in the app.
const csp = JSON.parse(await readFile(join(repo, 'desktop/src-tauri/tauri.conf.json'), 'utf8')).app.security.csp;
const served = new Set(['direct.html', 'direct.js', 'vendor/wildbloom-direct.js']);
const server = createServer(async (request, response) => {
  const name = normalize(new URL(request.url, 'http://127.0.0.1').pathname.slice(1));
  if (!served.has(name)) { response.writeHead(404).end(); return; }
  response.writeHead(200, {
    'Content-Type': name.endsWith('.js') ? 'text/javascript' : 'text/html',
    'Content-Security-Policy': csp,
    'Cache-Control': 'no-store',
  });
  response.end(await readFile(join(ui, name)));
});
await new Promise((done) => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;

const executablePath = process.env.WILDBLOOM_BROWSER_EXECUTABLE
  ?? (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined);
const browser = await chromium.launch({
  headless: true,
  // Host candidates as addresses, so the two peers in one page reach each other whatever multicast does.
  args: ['--disable-features=WebRtcHideLocalIpsWithMdns'],
  ...(executablePath ? { executablePath } : {}),
});

const SECRET = 'synthetic-turn-credential';
const ENVELOPE = 3 * 1024 * 1024 + 777;
const SIZE = 3 * 1024 * 1024 + 12;
let passed = 0;

/** Stands in for Rust: records every command, answers the sink as told, and lets the test emit requests. */
function fakeTauri() {
  const fake = {
    order: [], reports: [], writes: [], ends: [], aborts: [], bytes: [], held: [],
    channel: undefined, mode: { write: 'ok', end: 'ok' },
    globals: Object.getOwnPropertyNames(window),
  };
  window.__fake = fake;
  const refusal = (mode) => (mode === 'storage' ? { code: 'sink_storage', message: 'There is no room.' } : { code: 'sink_failed', message: 'Refused.' });
  window.__TAURI__ = {
    core: {
      async invoke(command, args, options) {
        fake.order.push(command === 'direct_peer_report' ? `report:${args.report.kind}` : command);
        if (command === 'direct_peer_attach') { fake.channel = args.channel; return null; }
        if (command === 'direct_peer_report') { fake.reports.push(structuredClone(args.report)); return null; }
        if (command === 'direct_sink_write') {
          const headers = options?.headers ?? {};
          fake.writes.push({ raw: args instanceof Uint8Array, transfer: headers['Wildbloom-Transfer'], offset: headers['Wildbloom-Offset'], length: args.length });
          fake.bytes.push(args.slice());
          const mode = fake.mode.write;
          if (mode === 'hold') return new Promise((release) => fake.held.push(() => release(null)));
          if (mode !== 'ok') throw refusal(mode);
          return null;
        }
        if (command === 'direct_sink_end') {
          fake.ends.push(structuredClone(args));
          if (fake.mode.end !== 'ok') throw refusal(fake.mode.end);
          return null;
        }
        if (command === 'direct_sink_abort') { fake.aborts.push(args.transfer); return null; }
        throw { code: 'not_allowed' };
      },
    },
  };
  // Like Tauri's Channel: Rust's messages arrive at `onmessage`, one request each.
  window.__TAURI__.core.Channel = class Channel {
    onmessage = () => {};
  };
  window.__emit = (payload) => fake.channel?.onmessage(structuredClone(payload));
}

/** The phone's side, from the same bundle: answers Drop's offer and speaks frames. */
async function phoneKit() {
  const kit = await import('/vendor/wildbloom-direct.js');
  const phone = { peer: undefined, channel: undefined, frames: [], closed: false, sent: 0, chunks: [] };
  window.__phone = phone;
  phone.answer = async (offer) => {
    phone.peer ??= new kit.DirectPeer({ iceServers: [], hide: false });
    const sdp = await phone.peer.answer(offer);
    phone.peer.channel.then((channel) => {
      if (phone.channel) return;
      phone.channel = channel;
      channel.listen({
        frame: (bytes) => { try { phone.frames.push({ ...kit.decodeFrame('receiver', bytes) }); } catch (error) { phone.frames.push({ type: 'bad', error: String(error) }); } },
        low() {},
        closed() { phone.closed = true; },
      });
    });
    return sdp;
  };
  /** DATA frames for envelope bytes [from, to), in the protocol's largest payloads. */
  phone.data = (to) => {
    while (phone.sent < to) {
      const length = Math.min(65_527, to - phone.sent);
      const chunk = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) chunk[i] = ((phone.sent + i) * 31 + ((phone.sent + i) >> 9)) & 0xff;
      phone.chunks.push(chunk);
      phone.channel.send(kit.encodeData(phone.sent, chunk));
      phone.sent += length;
    }
  };
  phone.end = (size) => phone.channel.send(kit.encodeEnd(new Uint8Array(32).fill(0xab), size));
  phone.stop = (code) => phone.channel.send(kit.encodeStop(code));
  phone.same = async () => {
    const join = (parts) => { const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { all.set(p, at); at += p.length; } return all; };
    const digest = async (bytes) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))).join(',');
    return (await digest(join(phone.chunks))) === (await digest(join(window.__fake.bytes)));
  };
}

async function openWindow() {
  // With addresses shown, Chrome gathers on every interface only for a page with media permission,
  // else only on the default route's, which behind a full-tunnel VPN takes no local packets.
  const context = await browser.newContext({ permissions: ['microphone'] });
  const page = await context.newPage();
  const problems = [];
  const consoleLines = [];
  page.on('pageerror', (error) => problems.push(String(error)));
  page.on('console', (message) => consoleLines.push(message.text()));
  await page.addInitScript(fakeTauri);
  await page.goto(`${origin}/direct.html`);
  await page.waitForFunction(() => window.__fake.reports.some((r) => r.kind === 'ready'), null, { timeout: 10_000 });
  await page.evaluate(phoneKit);
  return { context, page, problems, consoleLines };
}

const reports = (w) => w.page.evaluate(() => window.__fake.reports);
const fake = (w) => w.page.evaluate(() => { const { order, reports, writes, ends, aborts } = window.__fake; return { order, reports, writes, ends, aborts }; });
const phone = (w) => w.page.evaluate(() => ({ frames: window.__phone.frames, closed: window.__phone.closed, sent: window.__phone.sent }));
const emit = (w, payload) => w.page.evaluate((p) => window.__emit(p), payload);

async function waitFor(w, fn, arg, what, timeout = 15_000) {
  try {
    await w.page.waitForFunction(fn, arg, { timeout, polling: 20 });
  } catch (error) {
    const state = await fake(w).catch(() => ({}));
    const other = await phone(w).catch(() => ({}));
    throw new Error(`Timed out waiting for ${what}: reports ${JSON.stringify((state.reports ?? []).map((r) => ({ ...r, sdp: r.sdp ? '<sdp>' : undefined })))}, phone frames ${JSON.stringify(other.frames?.slice(-6))}`, { cause: error });
  }
}
const reported = (w, match, what, timeout) => waitFor(w, (m) => window.__fake.reports.some((r) => Object.entries(m).every(([k, v]) => r[k] === v)), match, what, timeout);

/** create, offer, answer: up to an open channel with the frame logic running. */
async function connect(w, { transfer = 'T1', envelopeBytes = ENVELOPE, size = SIZE } = {}) {
  await emit(w, { transfer, seq: 1, op: 'create', iceServers: [], relayOnly: false, envelopeBytes, size });
  await reported(w, { kind: 'done', seq: 1 }, 'create');
  await emit(w, { transfer, seq: 2, op: 'offer' });
  await reported(w, { kind: 'offer', seq: 2 }, 'the offer');
  const offer = (await reports(w)).find((r) => r.kind === 'offer' && r.seq === 2);
  assert.equal(offer.transfer, transfer);
  assert.match(offer.sdp, /^v=0\r\n/u);
  assert.match(offer.sdp, /a=sctp-port/u, 'The offer carries the data channel.');
  const answer = await w.page.evaluate((sdp) => window.__phone.answer(sdp), offer.sdp);
  await emit(w, { transfer, seq: 3, op: 'answer', sdp: answer });
  await reported(w, { kind: 'done', seq: 3 }, 'the answer applied');
  await reported(w, { kind: 'channel', transfer }, 'the channel report');
  await waitFor(w, () => window.__phone.channel !== undefined, null, 'the phone channel');
}

async function journey(name, work) {
  const w = await openWindow();
  try {
    await work(w);
    assert.deepEqual(w.problems, [], `${name}: page errors`);
    for (const line of w.consoleLines) {
      assert.ok(!line.includes(SECRET) && !/v=0|a=ice-pwd|a=fingerprint/u.test(line), `${name}: a console line carries a credential or SDP`);
    }
    passed += 1;
    console.log(`ok  ${name}`);
  } finally {
    await w.context.close();
  }
}

try {
  {
    // The window faces a stranger's phone: no event permission, so it hears none of the app's events.
    const capability = JSON.parse(await readFile(join(repo, 'desktop/src-tauri/capabilities/direct-window.json'), 'utf8'));
    assert.deepEqual(capability.windows, ['direct']);
    assert.deepEqual(capability.permissions.filter((p) => typeof p !== 'string' || p.startsWith('core:')), [], 'The direct window has no core permission.');
    assert.deepEqual([...capability.permissions].sort(), ['allow-direct-peer-attach', 'allow-direct-peer-report', 'allow-direct-sink-abort', 'allow-direct-sink-end', 'allow-direct-sink-write']);
    assert.ok(!/__TAURI__\.event|\.event\./.test(await readFile(join(ui, 'direct.js'), 'utf8')), 'direct.js uses no event API.');
    passed += 1;
    console.log('ok  the direct window\'s capability grants no events, only its own commands');
  }

  await journey('starts by attaching its request channel, then says ready, under Drop\'s CSP, and adds no globals', async (w) => {
    const state = await fake(w);
    assert.deepEqual(state.order.slice(0, 2), ['direct_peer_attach', 'report:ready']);
    assert.deepEqual(state.reports, [{ kind: 'ready' }]);
    const added = await w.page.evaluate(() => Object.getOwnPropertyNames(window).filter((name) => !window.__fake.globals.includes(name) && !['__fake', '__emit', '__TAURI__', '__phone'].includes(name)));
    assert.deepEqual(added, [], 'The window keeps nothing in globals.');
  });

  await journey('receives a file in order, ACKs only what the sink has written, and sends KEPT after the sink keeps it', async (w) => {
    await connect(w);
    const states = (await reports(w)).filter((r) => r.kind === 'state').map((r) => r.state);
    assert.ok(states.includes('connected'), `connection states reported: ${states}`);
    assert.ok((await reports(w)).every((r) => r.transfer === undefined || r.transfer === 'T1'));
    // Hold the first write: nothing may be acknowledged, and no second write starts, until it resolves.
    await w.page.evaluate(() => { window.__fake.mode.write = 'hold'; window.__phone.data(2 * 1024 * 1024 + 100); });
    await waitFor(w, () => window.__fake.writes.length === 1, null, 'the first write');
    await new Promise((done) => setTimeout(done, 400));
    assert.equal((await fake(w)).writes.length, 1, 'One write at a time.');
    assert.deepEqual((await phone(w)).frames, [], 'No ACK before the bytes are written.');
    await w.page.evaluate(() => { window.__fake.mode.write = 'ok'; window.__fake.held.shift()(); });
    await waitFor(w, () => window.__phone.frames.some((f) => f.type === 'ack'), null, 'the first ACK');
    await w.page.evaluate((e) => window.__phone.data(e), ENVELOPE);
    await waitFor(w, (e) => window.__phone.frames.some((f) => f.type === 'ack' && f.next === e), ENVELOPE, 'the last ACK');
    await w.page.evaluate((s) => window.__phone.end(s), SIZE);
    await waitFor(w, () => window.__phone.frames.some((f) => f.type === 'kept'), null, 'KEPT');
    await reported(w, { kind: 'ended', outcome: 'kept' }, 'ended kept');
    const state = await fake(w);
    let offset = 0;
    for (const write of state.writes) {
      assert.equal(write.raw, true, 'Bytes go as the raw request body.');
      assert.equal(write.transfer, 'T1');
      assert.equal(write.offset, String(offset), 'Offsets count the envelope bytes written before.');
      offset += write.length;
    }
    assert.equal(offset, ENVELOPE);
    assert.ok(await w.page.evaluate(() => window.__phone.same()), 'Rust got exactly the bytes sent, in order.');
    assert.deepEqual(state.ends, [{ transfer: 'T1', sha256: 'ab'.repeat(32), size: SIZE }]);
    const frames = (await phone(w)).frames;
    const acks = frames.filter((f) => f.type === 'ack').map((f) => f.next);
    for (let i = 1; i < acks.length; i += 1) assert.ok(acks[i] > acks[i - 1]);
    assert.ok(acks.slice(0, -1).every((next, i) => next - (acks[i - 1] ?? 0) >= 1024 * 1024), `ACKs every MiB: ${acks}`);
    assert.equal(frames.at(-1).type, 'kept');
    assert.ok(state.order.indexOf('direct_sink_end') < state.order.indexOf('report:ended'), 'KEPT and ended only after the sink kept the file.');
    // Rust closes without a STOP: KEPT is already out, and nothing follows it.
    await emit(w, { transfer: 'T1', seq: 4, op: 'close', stop: null });
    await reported(w, { kind: 'done', seq: 4 }, 'close');
    await reported(w, { kind: 'state', state: 'closed' }, 'the closed state');
    assert.equal((await phone(w)).frames.filter((f) => f.type === 'stop').length, 0);
    assert.deepEqual(state.aborts, [], 'A kept file is never aborted.');
  });

  for (const [mode, code, outcome, where] of [['failed', 2, 'verification', 'write'], ['storage', 3, 'storage', 'write'], ['failed', 2, 'verification', 'end'], ['storage', 3, 'storage', 'end']]) {
    await journey(`a sink refusal (${mode} at ${where}) sends STOP ${code}, aborts the sink and ends ${outcome}`, async (w) => {
      await connect(w);
      await w.page.evaluate(({ m, at }) => { window.__fake.mode[at] = m; }, { m: mode, at: where });
      await w.page.evaluate((e) => window.__phone.data(e), ENVELOPE);
      if (where === 'end') {
        await waitFor(w, (e) => window.__phone.frames.some((f) => f.type === 'ack' && f.next === e), ENVELOPE, 'the last ACK');
        await w.page.evaluate((s) => window.__phone.end(s), SIZE);
      }
      await waitFor(w, () => window.__phone.frames.some((f) => f.type === 'stop'), null, 'STOP');
      await reported(w, { kind: 'ended', outcome }, `ended ${outcome}`);
      const frames = (await phone(w)).frames;
      assert.deepEqual(frames.filter((f) => f.type === 'stop'), [{ type: 'stop', code }]);
      assert.equal(frames.some((f) => f.type === 'kept'), false);
      assert.deepEqual((await fake(w)).aborts, ['T1']);
    });
  }

  for (const stop of [1, 2, 3]) {
    await journey(`close with stop ${stop} mid-transfer sends exactly STOP ${stop}, then closes`, async (w) => {
      await connect(w);
      await w.page.evaluate(() => { window.__fake.mode.write = 'hold'; window.__phone.data(512 * 1024); });
      await waitFor(w, () => window.__fake.writes.length === 1, null, 'a write in flight');
      await emit(w, { transfer: 'T1', seq: 4, op: 'close', stop });
      await reported(w, { kind: 'done', seq: 4 }, 'close');
      await waitFor(w, () => window.__phone.frames.some((f) => f.type === 'stop'), null, 'STOP at the phone');
      // The write in flight lands after the close: its ACK must not follow the STOP.
      await w.page.evaluate(() => { window.__fake.mode.write = 'ok'; window.__fake.held.shift()(); });
      await reported(w, { kind: 'ended', outcome: 'cancelled' }, 'ended cancelled');
      await reported(w, { kind: 'state', state: 'closed' }, 'the connection closed');
      await new Promise((done) => setTimeout(done, 200));
      assert.deepEqual((await phone(w)).frames, [{ type: 'stop', code: stop }], 'One STOP with Rust\'s reason and nothing else.');
      assert.deepEqual((await fake(w)).aborts, ['T1']);
    });
  }

  await journey('close without a stop mid-transfer sends no frame and closes the connection', async (w) => {
    await connect(w);
    await w.page.evaluate(() => { window.__fake.mode.write = 'hold'; window.__phone.data(512 * 1024); });
    await waitFor(w, () => window.__fake.writes.length === 1, null, 'a write in flight');
    await emit(w, { transfer: 'T1', seq: 4, op: 'close', stop: null });
    await reported(w, { kind: 'done', seq: 4 }, 'close');
    await reported(w, { kind: 'state', state: 'closed' }, 'the connection closed');
    await w.page.evaluate(() => { window.__fake.mode.write = 'ok'; window.__fake.held.shift()(); });
    await reported(w, { kind: 'ended', outcome: 'cancelled' }, 'ended cancelled');
    await new Promise((done) => setTimeout(done, 200));
    assert.deepEqual((await phone(w)).frames, [], 'Nothing at all goes out.');
  });

  await journey('the phone\'s STOP 1 ends it as peer-cancelled and aborts the sink', async (w) => {
    await connect(w);
    await w.page.evaluate(() => { window.__phone.data(200_000); window.__phone.stop(1); });
    await reported(w, { kind: 'ended', outcome: 'peer-cancelled' }, 'ended peer-cancelled');
    assert.deepEqual((await fake(w)).aborts, ['T1']);
    assert.equal((await phone(w)).frames.some((f) => f.type === 'stop'), false, 'No STOP answers a STOP.');
  });

  await journey('an ICE restart offer and answer keep the same channel going', async (w) => {
    await connect(w);
    await w.page.evaluate(() => window.__phone.data(1024 * 1024));
    await waitFor(w, () => window.__phone.frames.some((f) => f.type === 'ack'), null, 'an ACK before the restart');
    const before = (await reports(w)).find((r) => r.kind === 'offer').sdp.match(/a=ice-ufrag:(\S+)/u)[1];
    await emit(w, { transfer: 'T1', seq: 4, op: 'restart' });
    await reported(w, { kind: 'offer', seq: 4 }, 'the restart offer');
    const restart = (await reports(w)).find((r) => r.kind === 'offer' && r.seq === 4).sdp;
    assert.notEqual(restart.match(/a=ice-ufrag:(\S+)/u)[1], before, 'New ICE credentials.');
    const answer = await w.page.evaluate((sdp) => window.__phone.answer(sdp), restart);
    await emit(w, { transfer: 'T1', seq: 5, op: 'answer', sdp: answer });
    await reported(w, { kind: 'done', seq: 5 }, 'the restart answer applied');
    await w.page.evaluate((e) => window.__phone.data(e), ENVELOPE);
    await waitFor(w, (e) => window.__phone.frames.some((f) => f.type === 'ack' && f.next === e), ENVELOPE, 'every byte acknowledged after the restart');
    assert.equal((await reports(w)).filter((r) => r.kind === 'channel').length, 1, 'One channel for the whole transfer.');
  });

  await journey('hiding without a TURN URL is refused as no-relay; requests for another transfer are not served', async (w) => {
    await emit(w, { transfer: 'T1', seq: 1, op: 'create', iceServers: [{ urls: ['stun:127.0.0.1:9'], username: 'synthetic-user', credential: SECRET }], relayOnly: true, envelopeBytes: ENVELOPE, size: SIZE });
    await reported(w, { kind: 'error', seq: 1, reason: 'no-relay' }, 'no-relay');
    await emit(w, { transfer: 'T1', seq: 2, op: 'create', iceServers: [{ urls: ['turn:127.0.0.1:9?transport=udp'], username: 'synthetic-user', credential: SECRET }], relayOnly: true, envelopeBytes: ENVELOPE, size: SIZE });
    await reported(w, { kind: 'done', seq: 2 }, 'a relay-only create');
    await emit(w, { transfer: 'T9', seq: 3, op: 'offer' });
    await reported(w, { kind: 'error', seq: 3, reason: 'unknown-transfer' }, 'a refusal for another transfer');
    await emit(w, { transfer: 'T9', seq: 4, op: 'close', stop: 1 });
    await reported(w, { kind: 'done', seq: 4 }, 'close for another transfer');
    await emit(w, { transfer: 'T1', seq: 5, op: 'close', stop: null });
    await reported(w, { kind: 'done', seq: 5 }, 'close');
    assert.ok(!JSON.stringify(await reports(w)).includes(SECRET), 'Reports never carry the credential.');
  });

  console.log(`direct window: ${passed} passed`);
} finally {
  await browser.close();
  server.close();
}
