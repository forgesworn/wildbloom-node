// The recipient side of a Wildbloom Drop share in real Chromium: the built
// recipient page (`/get` from the wildbloom repository) receives a share made
// by the desktop engine in the `drop_share_to_the_get_page` Rust test.
//
//   GET_DIST            a `vite build` of the wildbloom client whose
//                       VITE_WILDBLOOM_PAIR_RELAY is http://127.0.0.1:5472/pair/v1/
//   WILDBLOOM_E2E_HANDOFF   the folder the Rust test writes share.json into
//   WILDBLOOM_BROWSER_EXECUTABLE   Chromium or Chrome (macOS default is Chrome)
//   GET_SCREENS_DIR     optional: state screenshots
//
// Start this first, then run the Rust test with the same WILDBLOOM_E2E_HANDOFF.
// This page is served on 127.0.0.1:5472 together with a same-origin proxy to
// the loopback relay, standing in for the deployed gateway. Synthetic only.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { chromium } from 'playwright-core';

const dist = resolve(process.env.GET_DIST ?? '');
const handoff = resolve(process.env.WILDBLOOM_E2E_HANDOFF ?? '');
assert.ok(existsSync(join(dist, 'get.html')), 'Set GET_DIST to a wildbloom build with get.html');
assert.ok(existsSync(handoff), 'Set WILDBLOOM_E2E_HANDOFF to an existing folder');
const screens = process.env.GET_SCREENS_DIR ? resolve(process.env.GET_SCREENS_DIR) : null;
if (screens) mkdirSync(screens, { recursive: true });
const pause = (ms) => new Promise((done) => setTimeout(done, ms));
async function waitFor(name, seconds = 180) {
  const path = join(handoff, name);
  const deadline = Date.now() + seconds * 1000;
  while (!existsSync(path)) {
    assert.ok(Date.now() < deadline, `timed out waiting for ${name}`);
    await pause(200);
  }
  return JSON.parse(readFileSync(path, 'utf8'));
}

let upstream = null;
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.png': 'image/png', '.txt': 'text/plain' };
const relayLog = [];
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1:5472');
  if (url.pathname === '/get/') { response.writeHead(301, { Location: '/get' }).end(); return; }
  if (url.pathname.startsWith('/pair/v1/')) {
    relayLog.push(`${request.method} ${url.pathname.replace(/[A-Za-z0-9_-]{22}/u, '<locator>')}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const headers = {};
    for (const name of ['authorization', 'content-type', 'accept']) if (request.headers[name]) headers[name] = request.headers[name];
    try {
      const answer = await fetch(`${upstream}/v1/${url.pathname.slice('/pair/v1/'.length)}`, {
        method: request.method, headers, redirect: 'error',
        body: ['POST', 'PUT'].includes(request.method) ? Buffer.concat(chunks) : undefined,
      });
      response.writeHead(answer.status, { 'Content-Type': answer.headers.get('content-type') ?? 'application/json', 'Cache-Control': 'no-store' });
      response.end(Buffer.from(await answer.arrayBuffer()));
    } catch {
      response.writeHead(502).end();
    }
    return;
  }
  const file = url.pathname === '/get' ? 'get.html' : normalize(url.pathname).replace(/^\/+/u, '');
  const path = join(dist, file);
  if (!path.startsWith(dist) || !existsSync(path) || !statSync(path).isFile()) { response.writeHead(404).end(); return; }
  response.writeHead(200, { 'Content-Type': types[extname(path)] ?? 'application/octet-stream' });
  response.end(readFileSync(path));
});
server.listen(5472, '127.0.0.1');
await once(server, 'listening');
process.stdout.write('ok  serving the recipient page on 127.0.0.1:5472\n');

const browser = await chromium.launch(process.env.WILDBLOOM_BROWSER_EXECUTABLE ? { executablePath: process.env.WILDBLOOM_BROWSER_EXECUTABLE } : process.platform === 'darwin' ? { executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' } : {});
try {
  const share = await waitFor('share.json');
  upstream = share.relayUpstream;
  const blobOrigins = new Set();
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await context.newPage();
  const requests = [];
  page.on('request', (request) => requests.push(new URL(request.url()).origin));
  const title = () => page.locator('#title').textContent();
  const expectTitle = (text, timeout = 30_000) => page.waitForFunction((t) => document.getElementById('title')?.textContent === t, text, { timeout })
    .catch(async () => { throw new Error(`Expected "${text}" but the page shows "${await title()}"`); });
  const shot = async (name) => { if (screens) await page.screenshot({ path: join(screens, `${name}.png`) }); };

  await page.goto(share.link);
  await expectTitle('Get your file');
  assert.deepEqual([...new Set(requests)], ['http://127.0.0.1:5472'], 'no request besides the page itself on load');
  await shot('r5-enter-words');
  process.stdout.write('ok  R5: the link opens with no network request beyond the page\n');

  await page.locator('#words').fill(share.words);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expectTitle('Check these words with the sender', 90_000);
  const shown = (await page.locator('.words-list li').allInnerTexts()).map((w) => w.trim());
  assert.equal(shown.length, 3);
  writeFileSync(join(handoff, 'recipient-words.json'), JSON.stringify({ words: shown.join(' ') }));
  await shot('r12-check-words');
  process.stdout.write('ok  R12: paired with the desktop and shows three check words\n');

  await page.getByRole('button', { name: 'Yes, they match' }).click();
  await expectTitle('Your file is ready', 90_000);
  const body = await page.locator('#view').innerText();
  assert.ok(body.includes(share.name), 'R15 shows the file name');
  await shot('r15-ready');
  process.stdout.write('ok  R15: the share details arrived and the receipt went back\n');

  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download' }).click()]);
  const bytes = readFileSync(await download.path());
  await expectTitle('Downloaded');
  await shot('r18-downloaded');
  for (const origin of new Set(requests)) if (origin !== 'http://127.0.0.1:5472') blobOrigins.add(origin);
  writeFileSync(join(handoff, 'downloaded.json'), JSON.stringify({
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.length,
    name: download.suggestedFilename(),
  }));
  assert.ok([...blobOrigins].every((origin) => /^http:\/\/(localhost|127\.0\.0\.1):\d+$/u.test(origin)), `only loopback origins: ${[...blobOrigins]}`);
  process.stdout.write(`ok  R18: downloaded ${bytes.length} bytes as ${download.suggestedFilename()} from ${[...blobOrigins].join(', ')}\n`);

  await waitFor('stopped.json');
  process.stdout.write(`ok  relay requests seen: ${[...new Set(relayLog)].join('; ')}\n`);
  await context.close();
  process.stdout.write('Drop to /get journey passed in real Chromium.\n');
} finally {
  await browser.close();
  server.close();
}
