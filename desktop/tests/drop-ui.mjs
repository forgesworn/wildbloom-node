// Wildbloom Drop webview acceptance. Serves desktop/ statically, stubs window.__TAURI__
// with tests/drop-stub.js and drives every screen and state from fixtures. IPC is mocked;
// the Rust side is tested separately. Set WILDBLOOM_SCREENSHOT_DIR to also write the
// screenshots of every state (light and dark, 400x600, 340x420 and the wide layout).
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { chromium } from 'playwright-core';
import AxeBuilder from '@axe-core/playwright';

const root = fileURLToPath(new URL('..', import.meta.url));
const types = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.md': 'text/plain' };
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname === '/favicon.ico') { res.writeHead(204).end(); return; }
  const file = path.normalize(path.join(root, url.pathname));
  if (!file.startsWith(path.join(root, 'ui') + path.sep) && !file.startsWith(path.join(root, 'tests') + path.sep)) { res.writeHead(404).end(); return; }
  try {
    res.setHeader('Content-Type', types[path.extname(file)] || 'application/octet-stream');
    res.end(await readFile(file));
  } catch { res.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const stubPath = path.join(root, 'tests', 'drop-stub.js');
const browser = await chromium.launch(process.env.WILDBLOOM_BROWSER_EXECUTABLE ? { executablePath: process.env.WILDBLOOM_BROWSER_EXECUTABLE } : process.platform === 'darwin' ? { executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' } : {});

const FIXED = new Date('2026-10-16T10:00:00Z'); // 11:00 in London (BST)
const problems = [];
const results = [];
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'];
const NPUB_SHORT = 'npub1q8…7xk2';

async function open(url, { os = 'mac', desktop = '', scheme = 'light', width = 400, height = 600, reduced = false, clock = 'fixed', contrast, forced, font, touch } = {}) {
  const context = await browser.newContext({ hasTouch: Boolean(touch), viewport: { width, height }, colorScheme: scheme, reducedMotion: reduced ? 'reduce' : 'no-preference', forcedColors: forced ? 'active' : 'none', contrast: contrast || 'no-preference', timezoneId: 'Europe/London', locale: 'en-GB' });
  const page = await context.newPage();
  const label = url.replace(/^.*\/(ui|tests)\//, '');
  page.on('pageerror', (error) => problems.push(`${label}: pageerror ${error.message}`));
  page.on('console', (message) => { if (message.type() === 'error') problems.push(`${label}: console ${message.text()}`); });
  page.on('request', (request) => { if (new URL(request.url()).hostname !== '127.0.0.1') problems.push(`${label}: external request ${request.url()}`); });
  await context.addInitScript(() => document.addEventListener('securitypolicyviolation', (event) => { (window.__csp ||= []).push(`${event.violatedDirective} ${event.blockedURI}`); }));
  if (clock === 'fixed') await page.clock.setFixedTime(FIXED);
  else if (clock === 'install') await page.clock.install({ time: FIXED });
  await context.addInitScript({ path: stubPath });
  // `font: 'wide'` swaps in wide sans metrics (Verdana or DejaVu Sans, the
  // usual Linux default), so layout checks hold whatever the system font.
  // The rule rides in the page's own stylesheets, so it applies from first paint.
  if (font === 'wide' || process.env.DROP_UI_WIDE_FONT) {
    const wide = await readFile(path.join(root, 'tests/wide-font.css'), 'utf8');
    await context.route(/\/ui\/(drop|style)\.css$/, async (route) => {
      const response = await route.fetch();
      await route.fulfill({ response, body: `${await response.text()}\n${wide}` });
    });
  }
  const separator = url.includes('?') ? '&' : '?';
  await page.goto(`${url}${separator}os=${os}${desktop ? `&desktop=${desktop}` : ''}`);
  return page;
}
const drop = (state, options = {}, extra = '') => open(`${base}/ui/drop.html?state=${state}${extra}`, options);
async function ready(page) {
  await page.waitForFunction(() => window.__stub && window.__stub.calls.some((c) => c.command === 'drop_status') && (document.querySelector('#status-line')?.dataset.status || document.querySelector('#view-first .flow')));
  await page.waitForTimeout(80);
}
async function done(page) {
  const csp = await page.evaluate(() => window.__csp || []);
  assert.deepEqual(csp, [], 'CSP violations');
  await page.context().close();
}
const text = (locator) => locator.evaluate((node) => node.textContent.replace(/\s+/g, ' ').trim());
// innerText: separates block level pieces, as a reader or a sighted user sees them.
const visual = (locator) => locator.evaluate((node) => node.innerText.replace(/\s+/g, ' ').trim());
const calls = (page, command) => page.evaluate((name) => window.__stub.calls.filter((c) => c.command === name), command);
async function axe(page, label) {
  const result = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  assert.deepEqual(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })), [], `axe ${label}`);
}
function scenario(name, fn) { results.push({ name, fn }); }
const clockTime = (seconds) => new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Europe/London' }).format(new Date(seconds * 1000));
const nowSeconds = Math.floor(FIXED.getTime() / 1000);
// Not returned from evaluate: confirm dialogs keep the action's promise pending until closed.
const menuAction = (page, prefix) => page.evaluate((start) => { window.__stub.lastMenu.items.find((item) => item.text.startsWith(start)).action(); }, prefix);
const rowByName = (page, name) => page.locator('li.row', { has: page.locator('h3', { hasText: name }) });

/* ---------- static audits ---------- */

scenario('static: CSP unchanged, textContent only, no network or crypto in JS, no em dashes or home paths', async () => {
  const ui = path.join(root, 'ui');
  const read = (name) => readFile(path.join(ui, name), 'utf8');
  const csp = (source) => source.match(/http-equiv="Content-Security-Policy"\s+content="([^"]+)"/)[1];
  assert.equal(csp(await read('drop.html')), csp(await read('index.html')), 'drop.html CSP must equal index.html CSP');
  assert.match(csp(await read('drop.html')), /connect-src ipc: http:\/\/ipc\.localhost;/);
  const tauri = JSON.parse(await readFile(path.join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'));
  assert.equal(csp(await read('drop.html')), tauri.app.security.csp, 'drop.html CSP must equal tauri.conf.json CSP');
  for (const name of ['drop.js', 'share.js', 'receive.js']) {
    const source = await read(name);
    for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'fetch(', 'XMLHttpRequest', 'WebSocket', 'crypto.subtle', 'getRandomValues', 'localStorage', 'sessionStorage']) {
      assert.equal(source.includes(banned), false, `${name} must not use ${banned}`);
    }
  }
  const emDash = String.fromCharCode(0x2014);
  for (const dir of [ui, path.join(root, 'tests')]) {
    for (const name of await readdir(dir)) {
      if (!/\.(js|mjs|css|html|md)$/.test(name)) continue;
      const source = await readFile(path.join(dir, name), 'utf8');
      assert.equal(source.includes(emDash), false, `${name} contains an em dash`);
      assert.equal(source.includes(['', 'Users', ''].join('/')), false, `${name} contains a home path`);
      assert.equal(new RegExp(['clau', 'de|co-auth', 'ored'].join(''), 'i').test(source), false, `${name} mentions an assistant`);
    }
  }
  const htmlSource = await read('drop.html');
  assert.equal(/\sstyle=|<style|onclick=/i.test(htmlSource), false, 'no inline styles or handlers');
});

/* ---------- drop window: rows, status line, zone ---------- */

const EXPECTED_ROWS = {
  f1: { status: `2.4 MB · Today ${clockTime(nowSeconds - 3600)}`, spoken: `2.4 MB, added ${clockTime(nowSeconds - 3600)} today.`, share: true, menu: ['Share…', 'Save a Copy…', 'Remove…'] },
  f2: { status: 'Copying online · 45%', share: true, bar: 'Copying tax-return-2026.pdf online', menu: ['Share…', 'Save a Copy…', 'Remove…'] },
  f3: { status: '1 copy · online copy failed', inline: 'Retry', menu: ['Retry', 'Save a Copy…', 'Remove…'] },
  f4: { status: 'Encrypting · 20%', spoken: 'Encrypting, 20%.', bar: 'Encrypting contract-draft.docx', menu: ['Remove…'] },
  f5: { status: '1 copy · copying online next', share: true, menu: ['Share…', 'Save a Copy…', 'Remove…'] },
  f6: { status: '1 copy · on this computer', spoken: '1 copy, on this computer.', menu: ['Save a Copy…', 'Remove…'] },
  f7: { status: '1 copy · waiting for your online node', menu: ['Save a Copy…', 'Remove…'] },
  f8: { status: '1 copy · online copy missing', inline: 'Copy again', menu: ['Copy Again', 'Save a Copy…', 'Remove…'] },
  f9: { status: '1 copy · online space full', menu: ['Save a Copy…', 'Remove…'] },
  f10: { status: '1 copy · online only', spoken: '1 copy, online only.', inline: 'Copy back', menu: ['Copy Back', 'Save a Copy…', 'Remove…'] },
  f11: { status: 'Restoring · 62%', bar: 'Restoring photos-2019.tar', menu: null },
  f12: { status: `Shared · until ${clockTime(nowSeconds + 20 * 3600)} tomorrow`, spoken: `Shared until ${clockTime(nowSeconds + 20 * 3600)} tomorrow.`, share: true, menu: ['Share Again…', 'Stop Sharing…', 'Save a Copy…', 'Remove…'] },
  f13: { status: 'Sharing stopped · deleting the shared copy when online', spoken: 'Sharing stopped. The shared copy will be deleted when your online node is back.', menu: ['Save a Copy…'] },
  f14: { status: `Sharing ended · ${clockTime(nowSeconds - 1800)} today`, spoken: `Sharing ended at ${clockTime(nowSeconds - 1800)} today.`, share: true, menu: ['Share…', 'Save a Copy…', 'Remove…'] },
  f15: { status: "Couldn't read this file. Check you can open it, then add it again.", spoken: "Couldn't read this file. Check you can open it, then add it again.", inline: 'Remove', menu: null },
  f18: { status: "Shared · only your online node's owner can delete it now", spoken: "Shared. Only your online node's owner can delete the shared copy now.", share: true, menu: ['Share…', 'Save a Copy…', 'Remove…'] },
};

scenario('rows: long names fit two lines with wide sans metrics too', async () => {
  const page = await drop('all-states', { font: 'wide' });
  await ready(page);
  for (const [width, height] of [[400, 600], [340, 420]]) {
    await page.setViewportSize({ width, height });
    await page.waitForTimeout(150);
    const fit = await page.evaluate(() => {
      const heading = [...document.querySelectorAll('li.row h3')].find((node) => node.getAttribute('title').startsWith('holiday-photos'));
      const lineHeight = parseFloat(getComputedStyle(heading).lineHeight);
      return { text: heading.textContent, font: getComputedStyle(heading).fontFamily, lines: Math.round(heading.getBoundingClientRect().height / lineHeight), scroll: heading.scrollHeight, client: heading.clientHeight };
    });
    assert.match(fit.font, /^Verdana/, 'the wide font applied');
    assert.ok(fit.lines <= 2, `long name takes ${fit.lines} lines at ${width} with wide metrics`);
    assert.ok(fit.scroll <= fit.client + 1, 'nothing is clipped');
    assert.match(fit.text, /^holiday-photos.*….*\.zip$/, `start and extension stay visible at ${width}: ${fit.text}`);
  }
  await done(page);
});

scenario('rows: every state shows the exact copy, actions and menu items (macOS casing)', async () => {
  const page = await drop('all-states');
  await ready(page);
  for (const [id, expected] of Object.entries(EXPECTED_ROWS)) {
    const li = page.locator(`li.row[data-id="${id}"]`);
    assert.equal(await text(li.locator('.row-visual')), expected.status, `${id} status`);
    if (expected.spoken) assert.equal(await text(li.locator('.row-status .sr-only')), expected.spoken, `${id} spoken`);
    assert.equal(await li.locator('.row-visual').getAttribute('aria-hidden'), 'true');
    const share = li.locator('[data-ctl="share"]');
    assert.equal(await share.count(), expected.share ? 1 : 0, `${id} share button`);
    if (expected.share === true) assert.match(await share.getAttribute('aria-label'), /^Share /);
    if (expected.inline) assert.equal(await text(li.locator('[data-ctl="inline"]')), expected.inline, `${id} inline action`);
    else assert.equal(await li.locator('[data-ctl="inline"]').count(), 0);
    if (expected.bar) assert.equal(await li.locator('progress').getAttribute('aria-label'), expected.bar);
    else assert.equal(await li.locator('progress').count(), 0);
    const more = li.locator('[data-ctl="more"]');
    if (expected.menu) {
      assert.match(await more.getAttribute('aria-label'), /^More actions for /);
      assert.equal(await more.getAttribute('aria-haspopup'), 'menu');
      await page.evaluate(() => { window.__stub.lastMenu = null; });
      await more.click();
      const items = await page.evaluate(() => window.__stub.lastMenu && window.__stub.lastMenu.items.map((item) => item.text));
      assert.deepEqual(items, expected.menu, `${id} menu`);
    } else {
      assert.equal(await more.count(), 0, `${id} has no menu button`);
    }
  }
  assert.equal(await rowByName(page, 'holiday-photos').locator('h3').getAttribute('title'), 'holiday-photos-from-the-summer-trip-to-the-coast-with-everyone-final-version-2026.zip');
  const truncated = await text(rowByName(page, 'holiday-photos').locator('h3'));
  assert.match(truncated, /…/);
  assert.match(truncated, /\.zip$/);
  assert.equal(await page.locator('li.row img').count(), 0, 'hostile file name is not markup');
  for (const [width, height] of [[400, 600], [340, 420]]) {
    await page.setViewportSize({ width, height });
    await page.waitForTimeout(150);
    const fit = await page.evaluate(() => {
      const heading = [...document.querySelectorAll('li.row h3')].find((node) => node.getAttribute('title').startsWith('holiday-photos'));
      const lineHeight = parseFloat(getComputedStyle(heading).lineHeight);
      return { text: heading.textContent, lines: Math.round(heading.getBoundingClientRect().height / lineHeight), scroll: heading.scrollHeight, client: heading.clientHeight };
    });
    assert.ok(fit.lines <= 2, `long name takes ${fit.lines} lines at ${width}`);
    assert.ok(fit.scroll <= fit.client + 1, 'nothing is clipped');
    assert.match(fit.text, /^holiday-photos.*….*final-version-2026\.zip$|^holiday-photos.*….*\.zip$/, `extension stays visible at ${width}: ${fit.text}`);
  }
  await page.setViewportSize({ width: 400, height: 600 });
  // The hostile name is text (its full form in the title; the visible text
  // may be middle-truncated, depending on the system font).
  const hostile = await page.evaluate(() => [...document.querySelectorAll('li.row h3')].filter((h) => h.getAttribute('title') === '<img src=x onerror=alert(1)>.pdf').map((h) => h.textContent));
  assert.equal(hostile.length, 1);
  assert.match(hostile[0], /^<img src=x.*\.pdf$/);
  assert.equal(await page.evaluate(() => window.__stub.windows.length), 0);
  await done(page);
});

scenario('rows: Windows casing, native menu positioned at the button', async () => {
  const page = await drop('all-states', { os: 'windows' });
  await ready(page);
  await page.locator('li.row[data-id="f12"] [data-ctl="more"]').click();
  assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), ['Share again…', 'Stop sharing…', 'Save a copy…', 'Remove…']);
  assert.equal(typeof (await page.evaluate(() => window.__stub.lastMenu.at.y)), 'number');
  await page.locator('li.row[data-id="f10"] [data-ctl="more"]').click();
  assert.equal((await page.evaluate(() => window.__stub.lastMenu.items[0].text)), 'Copy back');
  await done(page);
});

const STATUS_CASES = [
  ['list', 'node', 'Wildbloom Node has stopped.', 'Open node settings'],
  ['list', 'node,keychain,expired,unreachable,full', 'Wildbloom Node has stopped.', 'Open node settings'],
  ['list', 'keychain,expired,unreachable,full', "Wildbloom can't reach your keychain.", 'Try again'],
  ['list', 'expired,unreachable,full', 'Approval for this computer has ended. New files stay on this computer.', 'Approve again'],
  ['list', 'unreachable,full', "Can't reach your online node. Files will copy when it's back.", 'Try now'],
  ['list', 'full', 'Your online space is full. New files stay on this computer.', 'Settings'],
  ['list', '', '1 file has only 1 copy.', 'Retry all'],
  ['all-states', '', '2 files have only 1 copy.', 'Retry all'],
  ['no-online', 'ends', 'Files have 1 copy, on this computer.', 'Add online node'],
  ['good', 'ends,recovery', 'Approval for this computer ends on 28 October 2026.', 'Renew'],
  ['good', 'recovery', "Your recovery key isn't saved yet.", 'Save it'],
  ['list', 'keylist', '1 file has only 1 copy.', 'Retry all'],
  ['good', 'keylist', "Wildbloom couldn't update the list it needs to restore your files. Your files are safe on this computer.", 'Try again'],
  ['folder', 'folder-unavailable', "Your Wildbloom folder can't be found. Changes there are paused.", 'Use folder again'],
  ['folder', 'folder-too-many', 'Your Wildbloom folder has more than 20,000 items. Changes there are paused.', null],
  ['list', 'keychain,folder-unavailable', "Wildbloom can't reach your keychain.", 'Try again'],
  ['list', 'folder-unavailable,expired,unreachable,full', "Your Wildbloom folder can't be found. Changes there are paused.", 'Use folder again'],
  ['list', 'folder-too-many,expired', 'Your Wildbloom folder has more than 20,000 items. Changes there are paused.', null],
  ['folder', '', "4 files in your Wildbloom folder can't be kept.", null],
  ['held', '', "7 files were deleted from your Wildbloom folder. They're kept until you choose.", 'Review…'],
  ['held-one', '', "1 file was deleted from your Wildbloom folder. It's kept until you choose.", 'Review…'],
  ['list', 'held,expired,unreachable,full,keylist', "7 files were deleted from your Wildbloom folder. They're kept until you choose.", 'Review…'],
  ['list', 'held,folder-too-many', 'Your Wildbloom folder has more than 20,000 items. Changes there are paused.', null],
  ['list', 'held,folder-unavailable', "Your Wildbloom folder can't be found. Changes there are paused.", 'Use folder again'],
  ['list', 'held,keychain', "Wildbloom can't reach your keychain.", 'Try again'],
  ['folder', 'keylist', "Wildbloom couldn't update the list it needs to restore your files. Your files are safe on this computer.", 'Try again'],
  ['good', '', 'All 5 files have 2 copies.', null],
  ['empty', '', '', null],
  ['empty', 'no-online', 'Files have 1 copy, on this computer.', 'Add online node'],
];
scenario('status line: priority order, copy and actions (section 6.1)', async () => {
  for (const [state, flags, expected, action] of STATUS_CASES) {
    const page = await drop(state, {}, `&status=${flags}`);
    await ready(page);
    assert.equal(await text(page.locator('#status-text')), expected, `${state} ${flags}`);
    const button = page.locator('#status-action');
    if (action) assert.equal(await text(button), action, `${state} ${flags} action`);
    else assert.equal(await button.isHidden(), true);
    await done(page);
  }
  // copying has no action, and a single file reads in the singular
  let page = await drop('good');
  await ready(page);
  await page.evaluate(() => { window.__stub.pushRow({ id: 'f20', name: 'budget.xlsx', bytes: 5, added: 1, state: 'copying', progress: 10 }); });
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('Copying'));
  assert.equal(await text(page.locator('#status-text')), 'Copying 1 file to your online node');
  assert.equal(await page.locator('#status-action').isHidden(), true);
  await page.evaluate(() => { window.__stub.pushRow({ id: 'f21', name: 'cv.pdf', bytes: 5, added: 1, state: 'queued' }); });
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('Copying 2'));
  assert.equal(await text(page.locator('#status-text')), 'Copying 2 files to your online node');
  await done(page);
  page = await drop('good');
  await ready(page);
  for (const id of ['f1', 'f16', 'f17', 'f20']) await page.evaluate((rowId) => window.__stub.emit('drop://file', { id: rowId, removed: true }), id);
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('Your file'));
  assert.equal(await text(page.locator('#status-text')), 'Your file has 2 copies.');
  await done(page);
});

scenario('folder: not_kept and linked rows, copy, menus, status counts', async () => {
  let page = await drop('folder');
  await ready(page);
  const expected = {
    f30: { status: `2.4 MB · Today ${clockTime(nowSeconds - 3000 - 30 * 600)}`, folder: 'Taxes/2026', menu: ['Open', 'Show in Finder', 'Share…', 'Save a Copy…', 'Remove…'] },
    f31: { status: `2.4 MB · Today ${clockTime(nowSeconds - 3000 - 31 * 600)}`, folder: null, menu: ['Open', 'Show in Finder', 'Share…', 'Save a Copy…', 'Remove…'] },
    f32: { status: 'Not kept · over 1 GB', folder: 'Videos', menu: ['Show in Finder'] },
    f33: { status: 'Not kept · rename it to keep it', folder: null, menu: ['Show in Finder'] },
    f34: { status: 'Not kept · its folder path is too long', folder: 'Projects/Research/Archive/Interviews/Transcripts', menu: ['Show in Finder'] },
    f35: { status: "Not kept · it's too many folders deep", folder: 'a/b/c/d/e/f/g/h/i/j', menu: ['Show in Finder'] },
    f36: { status: `2.4 MB · Today ${clockTime(nowSeconds - 3000 - 36 * 600)}`, folder: null, menu: ['Share…', 'Save a Copy…', 'Remove…'] },
  };
  for (const [id, want] of Object.entries(expected)) {
    const li = page.locator(`li.row[data-id="${id}"]`);
    assert.equal(await text(li.locator('.row-visual')), want.status, `${id} status`);
    if (want.folder) {
      assert.equal(await text(li.locator('.row-folder')), want.folder, `${id} folder`);
      // It wraps only after a slash, never inside a folder name.
      assert.equal(await li.locator('.row-folder wbr').count(), want.folder.split('/').length - 1, `${id} folder breaks`);
    } else assert.equal(await li.locator('.row-folder').count(), 0);
    assert.equal(await li.locator('[data-ctl="share"]').count(), id === 'f32' || id === 'f33' || id === 'f34' || id === 'f35' ? 0 : 1, `${id} share`);
    await page.evaluate(() => { window.__stub.lastMenu = null; });
    await li.locator('[data-ctl="more"]').click();
    assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), want.menu, `${id} menu`);
  }
  assert.equal(await text(page.locator('#status-text')), "4 files in your Wildbloom folder can't be kept.");
  // Open and Show in Finder call the commands; a refusal says so.
  await page.locator('li.row[data-id="f30"] [data-ctl="more"]').click();
  await menuAction(page, 'Open');
  await page.locator('li.row[data-id="f30"] [data-ctl="more"]').click();
  await menuAction(page, 'Show in');
  await page.locator('li.row[data-id="f32"] [data-ctl="more"]').click();
  await menuAction(page, 'Show in');
  await page.waitForFunction(() => window.__stub.calls.filter((c) => c.command === 'reveal_file').length === 2);
  assert.deepEqual((await calls(page, 'open_file')).map((c) => c.args), [{ id: 'f30' }]);
  assert.deepEqual((await calls(page, 'reveal_file')).map((c) => c.args), [{ id: 'f30' }, { id: 'f32' }]);
  await page.evaluate(() => { window.__stub.handlers.open_file = () => { throw { code: 'not_in_folder' }; }; });
  await page.locator('li.row[data-id="f30"] [data-ctl="more"]').click();
  await menuAction(page, 'Open');
  await page.locator('#notices p', { hasText: "That file isn't in your Wildbloom folder." }).waitFor();
  // One unkept file reads in the singular; the 2 copies count leaves them out.
  for (const id of ['f33', 'f34', 'f35']) await page.evaluate((rowId) => window.__stub.emit('drop://file', { id: rowId, removed: true }), id);
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('1 file'));
  assert.equal(await text(page.locator('#status-text')), "1 file in your Wildbloom folder can't be kept.");
  await page.evaluate(() => window.__stub.emit('drop://file', { id: 'f32', removed: true }));
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('All'));
  assert.equal(await text(page.locator('#status-text')), 'All 3 files have 2 copies.');
  await done(page);
  for (const [os, desktop, label] of [['windows', '', 'Show in Explorer'], ['linux', 'gnome', 'Show in Folder']]) {
    page = await drop('folder', { os, desktop });
    await ready(page);
    await page.locator('li.row[data-id="f32"] [data-ctl="more"]').click();
    assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), [label], os);
    await page.locator('li.row[data-id="f31"] [data-ctl="more"]').click();
    assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), ['Open', label, 'Share…', 'Save a copy…', 'Remove…'], os);
    await done(page);
  }
});

scenario('folder: Use folder again calls set_watch_folder with no confirmation', async () => {
  const page = await drop('list', {}, '&status=folder-unavailable');
  await ready(page);
  await page.locator('#status-action').click();
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('1 file has'));
  assert.deepEqual((await calls(page, 'set_watch_folder')).map((c) => c.args), [{ enabled: true }]);
  assert.equal(await page.locator('dialog').count(), 0);
  await done(page);
});

scenario('folder: turning it on asks first (Trash or Recycle Bin), Cancel changes nothing', async () => {
  const body = (bin) => `Each computer with the folder on holds the same files in the same folders. Changes and deletions there reach your other computers. Anything Wildbloom replaces or removes goes to the ${bin}. Update Wildbloom on all your computers first.`;
  for (const [os, desktop, bin, turnOnFirst] of [['mac', '', 'Trash', false], ['windows', '', 'Recycle Bin', true], ['linux', 'gnome', 'Trash', false]]) {
    const page = await drop('empty', { os, desktop });
    await ready(page);
    await page.locator('#folder-toggle').click();
    const dialog = page.locator('dialog[open]');
    await dialog.waitFor();
    assert.equal(await text(dialog.locator('h2')), 'Keep a readable copy of every file in ~/Wildbloom?');
    assert.deepEqual(await dialog.locator('p').allTextContents(), [body(bin)]);
    assert.deepEqual(await dialog.locator('button').allTextContents(), turnOnFirst ? ['Turn on', 'Cancel'] : ['Cancel', 'Turn on'], os);
    assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Turn on', 'the default is Turn on');
    await page.keyboard.press('Escape');
    await dialog.waitFor({ state: 'detached' });
    assert.equal((await calls(page, 'set_watch_folder')).length, 0, `${os} cancel`);
    assert.equal(await page.evaluate(() => document.activeElement.id), 'folder-toggle');
    await page.locator('#folder-toggle').click();
    await page.locator('dialog[open] button', { hasText: 'Cancel' }).click();
    assert.equal((await calls(page, 'set_watch_folder')).length, 0);
    await page.locator('#folder-toggle').click();
    await page.locator('dialog[open] button', { hasText: 'Turn on' }).click();
    await page.waitForFunction(() => document.querySelector('#folder-toggle').textContent === 'Open your Wildbloom folder');
    assert.deepEqual((await calls(page, 'set_watch_folder')).map((c) => c.args), [{ enabled: true }], os);
    await done(page);
  }
});

scenario('folder: Remove copy while the folder is on', async () => {
  for (const [os, bin] of [['mac', 'Trash'], ['windows', 'Recycle Bin']]) {
    const page = await drop('folder', { os });
    await ready(page);
    await page.locator('li.row[data-id="f31"] [data-ctl="more"]').click();
    await menuAction(page, 'Remove');
    const dialog = page.locator('dialog[open]');
    await dialog.waitFor();
    assert.equal(await text(dialog.locator('h2')), 'Remove cv.pdf from Wildbloom?');
    assert.deepEqual(await dialog.locator('p').allTextContents(), [`cv.pdf is removed from Wildbloom on all your computers. Copies in your Wildbloom folders go to the ${bin}. Its encrypted copies and key are deleted, which can't be undone.`], os);
    await page.keyboard.press('Escape');
    await done(page);
  }
});

scenario('folder: held deletions, their rows, menu and the review dialog', async () => {
  const body = (bin) => `If you remove them everywhere, copies in your other Wildbloom folders go to the ${bin}. Their encrypted copies and keys are deleted, which can't be undone.`;
  const ALL = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7'];
  const reviewed = (page) => calls(page, 'resolve_held_removals');
  let page = await drop('held');
  await ready(page);
  // Rows: one indicator, no Share, no Open or Show in Finder; Put Back first in the menu.
  const li = page.locator('li.row[data-id="h1"]');
  assert.equal(await text(li.locator('.row-visual')), 'Deleted from your folder · kept until you choose');
  assert.equal(await text(li.locator('.row-status .sr-only')), 'Deleted from your Wildbloom folder. Kept until you choose.');
  assert.equal(await text(li.locator('.row-folder')), 'Work/2026');
  assert.equal(await li.locator('[data-ctl="share"]').count(), 0);
  assert.equal(await li.locator('[data-ctl="inline"]').count(), 0);
  await li.locator('[data-ctl="more"]').click();
  assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), ['Put Back', 'Save a Copy…', 'Remove…']);
  // The review dialog: counts, five names in folder order, then how many more.
  await page.locator('#status-action').click();
  let dialog = page.locator('dialog.held[open]');
  await dialog.waitFor();
  assert.equal(await text(dialog.locator('h2')), '7 files were deleted from your Wildbloom folder');
  assert.deepEqual(await dialog.locator('p').allTextContents(), [
    "That's more than Wildbloom removes without asking. Your other computers and your online node still have them.",
    'and 2 more.',
    body('Trash'),
  ]);
  assert.deepEqual(await dialog.locator('li').allTextContents(), ['draft.txt', 'notes.txt', 'Photos/beach.jpg', 'Photos/holiday.jpg', 'Work/2026/budget.xlsx']);
  assert.deepEqual(await dialog.locator('button').allTextContents(), ['Remove them everywhere', 'Decide later', 'Put them back']);
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Put them back', 'Put them back is the default');
  // Escape and Decide later change nothing.
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'detached' });
  assert.equal(await page.evaluate(() => document.activeElement.id), 'status-action', 'focus returns to the status action');
  await page.locator('#status-action').click();
  await page.locator('dialog.held[open] button', { hasText: 'Decide later' }).click();
  await page.locator('dialog.held').waitFor({ state: 'detached' });
  assert.equal((await reviewed(page)).length, 0);
  assert.match(await text(page.locator('#status-text')), /^7 files were deleted/);
  // Put them back sends exactly the rows it listed.
  await page.locator('#status-action').click();
  await page.locator('dialog.held[open] button', { hasText: 'Put them back' }).click();
  await page.locator('#notices p', { hasText: 'Putting 7 files back in your Wildbloom folder.' }).waitFor();
  assert.deepEqual((await reviewed(page)).map((c) => c.args), [{ ids: ['h7', 'h6', 'h5', 'h4', 'h2', 'h1', 'h3'], choice: 'put_back' }]);
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('All'));
  assert.equal(await text(page.locator('#status-text')), 'All 9 files have 2 copies.');
  await done(page);

  // Remove them everywhere; a row held while the dialog was open stays held.
  page = await drop('held');
  await ready(page);
  await page.locator('#status-action').click();
  await page.locator('dialog.held[open]').waitFor();
  await page.evaluate(() => window.__stub.pushRow({ id: 'h8', name: 'late.txt', bytes: 5, added: 1, state: 'held', progress: null }));
  await page.locator('dialog.held[open] button', { hasText: 'Remove them everywhere' }).click();
  await page.locator('#notices p', { hasText: 'Removed 7 files from Wildbloom.' }).waitFor();
  const sent = (await reviewed(page)).map((c) => c.args);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].choice, 'remove');
  assert.deepEqual([...sent[0].ids].sort(), ALL);
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('1 file was'));
  assert.equal(await text(page.locator('#status-text')), "1 file was deleted from your Wildbloom folder. It's kept until you choose.");
  // Put Back from the row menu: that row only.
  await page.locator('li.row[data-id="h8"] [data-ctl="more"]').click();
  await menuAction(page, 'Put Back');
  await page.locator('#notices p', { hasText: 'Putting late.txt back in your Wildbloom folder.' }).waitFor();
  assert.deepEqual((await reviewed(page)).at(-1).args, { ids: ['h8'], choice: 'put_back' });
  await done(page);

  // One file reads in the singular, with no "more" line.
  page = await drop('held-one');
  await ready(page);
  await page.locator('#status-action').click();
  dialog = page.locator('dialog.held[open]');
  await dialog.waitFor();
  assert.equal(await text(dialog.locator('h2')), '1 file was deleted from your Wildbloom folder');
  assert.deepEqual(await dialog.locator('p').allTextContents(), [
    "That's more than Wildbloom removes without asking. Your other computers and your online node still have it.",
    "If you remove it everywhere, copies in your other Wildbloom folders go to the Trash. Its encrypted copies and key are deleted, which can't be undone.",
  ]);
  assert.deepEqual(await dialog.locator('button').allTextContents(), ['Remove it everywhere', 'Decide later', 'Put it back']);
  await page.keyboard.press('Escape');
  await done(page);

  // Windows: primary first, Recycle Bin, sentence-case menu.
  page = await drop('held', { os: 'windows' });
  await ready(page);
  await page.locator('li.row[data-id="h1"] [data-ctl="more"]').click();
  assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), ['Put back', 'Save a copy…', 'Remove…']);
  await page.locator('#status-action').click();
  dialog = page.locator('dialog.held[open]');
  await dialog.waitFor();
  assert.deepEqual(await dialog.locator('button').allTextContents(), ['Put them back', 'Remove them everywhere', 'Decide later']);
  assert.equal(await dialog.locator('p').last().textContent(), body('Recycle Bin'));
  await page.keyboard.press('Escape');
  await done(page);
});

scenario('status line: actions call the right commands', async () => {
  let page = await drop('list');
  await ready(page);
  await page.locator('#status-action').click();
  assert.deepEqual((await calls(page, 'retry')).map((c) => c.args), [{ id: null }]);
  await done(page);
  page = await drop('good', {}, '&status=keychain');
  await ready(page);
  await page.locator('#status-action').click();
  assert.deepEqual((await calls(page, 'drop_status')).at(-1).args, { recheck: 'keychain' });
  await done(page);
  page = await drop('good', {}, '&status=unreachable');
  await ready(page);
  await page.locator('#status-action').click();
  assert.deepEqual((await calls(page, 'drop_status')).at(-1).args, { recheck: 'online' });
  await done(page);
  page = await drop('good', {}, '&status=node');
  await ready(page);
  await page.locator('#status-action').click();
  await page.locator('#footer-settings').click();
  assert.deepEqual(await page.evaluate(() => window.__stub.windows), ['show main', 'focus main', 'show main', 'focus main']);
  await done(page);
  page = await drop('good', {}, '&status=expired');
  await ready(page);
  await page.locator('#status-action').click();
  await page.locator('dialog[open] h2', { hasText: 'Approve this computer again' }).waitFor();
  await page.keyboard.press('Escape');
  await page.locator('dialog').waitFor({ state: 'detached' });
  assert.equal(await page.evaluate(() => document.activeElement.id), 'status-action', 'focus returns to the status action');
  await done(page);
});

scenario('zone and footer: empty, with files, no online node, folder toggle', async () => {
  let page = await drop('empty');
  await ready(page);
  assert.equal(await text(page.locator('#zone-title')), 'Drop files here');
  assert.equal(await text(page.locator('#zone-body')), 'Wildbloom encrypts each file, keeps it on this computer and copies it to your online node.');
  assert.equal(await text(page.locator('#add-files')), 'Add files…');
  assert.equal(await page.locator('#zone #add-files').count(), 0, 'the zone holds no button for adding');
  assert.equal(await text(page.locator('#folder-toggle')), 'Turn on your Wildbloom folder');
  assert.equal(await page.locator('#footer-online').count(), 0, 'the usage line is gone from the footer');
  assert.equal(await page.locator('#zone').evaluate((n) => n.classList.contains('empty')), true);
  await page.locator('#folder-toggle').click();
  await page.locator('dialog[open] button', { hasText: 'Turn on' }).click();
  await page.waitForFunction(() => document.querySelector('#folder-toggle').textContent === 'Open your Wildbloom folder');
  assert.deepEqual((await calls(page, 'set_watch_folder')).map((c) => c.args), [{ enabled: true }]);
  await page.locator('#folder-toggle').click();
  assert.equal((await calls(page, 'open_watch_folder')).length, 1);
  await page.locator('#add-files').click();
  assert.equal((await calls(page, 'pick_files')).length, 1);
  await done(page);
  page = await drop('list');
  await ready(page);
  assert.equal(await page.locator('#zone-body').isHidden(), true);
  assert.equal(await page.locator('#zone').evaluate((n) => getComputedStyle(n).display), 'none');
  await done(page);
});

scenario('find: shown over 20 files, filters, no-results copy, shortcut', async () => {
  let page = await drop('list');
  await ready(page);
  assert.equal(await page.locator('#find').isHidden(), true);
  await done(page);
  page = await drop('many');
  await ready(page);
  assert.equal(await text(page.locator('#find label')), 'Find a file');
  await page.locator('#find-input').fill('document-07');
  assert.equal(await page.locator('li.row:visible').count(), 1);
  await page.locator('#find-input').fill('zzz');
  assert.equal(await page.locator('li.row:visible').count(), 0);
  assert.equal(await text(page.locator('#no-match')), 'No files match “zzz”.');
  await page.locator('#find-input').fill('');
  await page.locator('#add-files').focus();
  await page.keyboard.press('Meta+f');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'find-input');
  await done(page);
});

/* ---------- drag and drop, notices ---------- */

scenario('drag: hover, folder, too big, leave, drop, refusals and duplicate flash', async () => {
  const page = await drop('list');
  await ready(page);
  const overlay = page.locator('#drag-overlay');
  assert.equal(await overlay.evaluate((n) => n.classList.contains('on')), false);
  await page.evaluate(() => window.__stub.emit('tauri://drag-enter', { paths: ['/a/one.pdf'], position: { x: 1, y: 1 } }));
  assert.equal(await overlay.evaluate((n) => n.classList.contains('on')), true);
  assert.equal(await text(page.locator('#drag-message')), 'Drop to keep 2 copies');
  await page.evaluate(() => window.__stub.emit('drop://drag-info', { files: 0, folders: 1, tooBig: 0 }));
  assert.equal(await text(page.locator('#drag-message')), "Folders can't be added yet");
  assert.equal(await overlay.evaluate((n) => n.classList.contains('refuse')), true);
  await page.evaluate(() => window.__stub.emit('drop://drag-info', { files: 1, folders: 0, tooBig: 1 }));
  assert.equal(await text(page.locator('#drag-message')), 'Too big to add: over 1 GB');
  await page.evaluate(() => window.__stub.emit('drop://drag-info', { files: 2, folders: 1, tooBig: 0 }));
  assert.equal(await text(page.locator('#drag-message')), 'Drop to keep 2 copies');
  await page.evaluate(() => window.__stub.emit('tauri://drag-leave', {}));
  assert.equal(await overlay.evaluate((n) => n.classList.contains('on')), false);

  const drop_ = (paths) => page.evaluate((list) => { window.__stub.emit('tauri://drag-enter', { paths: list }); window.__stub.emit('tauri://drag-drop', { paths: list }); }, paths);
  await drop_(['/folder/Pictures']);
  await page.waitForFunction(() => document.querySelector('#notices').textContent.includes('Folders'));
  assert.equal(await text(page.locator('#notices')), "Folders can't be added yet. Drop the files inside, or zip the folder first.");
  await drop_(['/big/movie.mkv']);
  await page.waitForFunction(() => document.querySelector('#notices').textContent.includes('movie.mkv'));
  assert.equal(await text(page.locator('#notices')), 'movie.mkv is over 1 GB and can\'t be added yet.');
  await drop_(['/nospace/disk.img']);
  await page.waitForFunction(() => document.querySelector('#notices').textContent.includes('disk.img'));
  assert.equal(await text(page.locator('#notices')), 'Not enough space on this computer for disk.img.');
  await drop_(['/dup/holiday.jpg']);
  await page.waitForFunction(() => document.querySelector('#notices').textContent.includes('already'));
  assert.equal(await text(page.locator('#notices')), 'holiday.jpg is already kept.');
  assert.equal(await page.locator('li.row[data-id="f1"]').evaluate((n) => n.classList.contains('flash')), true);
  await drop_(['/tmp/new-file.txt']);
  await page.locator('li.row h3', { hasText: 'new-file.txt' }).waitFor();
  assert.equal(await page.locator('#notices').evaluate((n) => n.children.length), 0, 'notices clear on the next drop');
  assert.equal(await text(rowByName(page, 'new-file.txt').locator('.row-visual')), 'Encrypting · 0%');
  assert.deepEqual((await calls(page, 'add_paths')).at(-1).args, { paths: ['/tmp/new-file.txt'] });
  await done(page);
});

scenario('drag: no overlay during first run or while a dialog is open', async () => {
  let page = await drop('first-run-1');
  await ready(page);
  await page.evaluate(() => window.__stub.emit('tauri://drag-enter', { paths: ['/a/one.pdf'] }));
  assert.equal(await page.locator('#drag-overlay').evaluate((n) => n.classList.contains('on')), false);
  await done(page);
  page = await drop('list');
  await ready(page);
  await page.locator('li.row[data-id="f1"] [data-ctl="more"]').click();
  await menuAction(page, 'Remove');
  await page.locator('dialog[open]').waitFor();
  await page.evaluate(() => window.__stub.emit('tauri://drag-enter', { paths: ['/a/one.pdf'] }));
  assert.equal(await page.locator('#drag-overlay').evaluate((n) => n.classList.contains('on')), false);
  await done(page);
});

scenario('reduced motion: overlay has no transition, spinner does not spin; otherwise 120 ms', async () => {
  let page = await drop('all-states', { reduced: true });
  await ready(page);
  await page.evaluate(() => window.__stub.emit('tauri://drag-enter', { paths: ['/a/one.pdf'] }));
  for (const state of ['on', '']) {
    const duration = await page.locator('#drag-overlay').evaluate((n) => getComputedStyle(n).transitionDuration);
    assert.match(duration, /^0s(, 0s)*$/, `overlay duration ${duration}`);
    await page.evaluate(() => window.__stub.emit('tauri://drag-leave', {}));
    if (!state) break;
  }
  assert.equal(await page.locator('li.row[data-id="f4"] svg.spin').evaluate((n) => getComputedStyle(n).animationName), 'none');
  await done(page);
  page = await drop('all-states');
  await ready(page);
  assert.match(await page.locator('#drag-overlay').evaluate((n) => getComputedStyle(n).transitionDuration), /0\.12s/);
  assert.notEqual(await page.locator('li.row[data-id="f4"] svg.spin').evaluate((n) => getComputedStyle(n).animationName), 'none');
  await done(page);
});

/* ---------- announcer, live updates ---------- */

scenario('announcer: three rows reaching 2 copies within 1 s give one message; failures batch too', async () => {
  const page = await drop('all-states');
  await ready(page);
  await page.evaluate(() => {
    window.__said = [];
    new MutationObserver(() => { const value = document.getElementById('drop-announcer').textContent; if (value) window.__said.push(value); }).observe(document.getElementById('drop-announcer'), { childList: true, characterData: true, subtree: true });
    const now = window.__stub.files;
    for (const id of ['f2', 'f4', 'f5']) window.__stub.pushRow({ ...now.find((row) => row.id === id), state: 'two_copies', progress: null });
  });
  await page.waitForTimeout(1800);
  assert.deepEqual(await page.evaluate(() => window.__said), ['3 files now have 2 copies.']);
  await page.evaluate(() => {
    window.__said.length = 0;
    window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f1'), state: 'failed' });
  });
  await page.waitForTimeout(2300);
  assert.deepEqual(await page.evaluate(() => window.__said), ["holiday.jpg couldn't be copied online."]);
  await page.evaluate(() => {
    window.__said.length = 0;
    window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f1'), state: 'two_copies' });
  });
  await page.waitForTimeout(2300);
  assert.deepEqual(await page.evaluate(() => window.__said), ['holiday.jpg now has 2 copies.']);
  assert.equal(await page.locator('#drop-announcer').getAttribute('aria-live'), 'polite');
  await done(page);
});

scenario('notice: keeps running event, row icon cross-fade only on state change', async () => {
  const page = await drop('list');
  await ready(page);
  await page.evaluate(() => window.__stub.emit('drop://notice', { kind: 'keeps_running' }));
  assert.equal(await text(page.locator('#notices')), 'Wildbloom keeps running. Open it again from your apps.');
  await page.evaluate(() => window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f3'), state: 'queued' }));
  assert.equal(await page.locator('li.row[data-id="f3"] .icon-slot').evaluate((n) => n.classList.contains('fade')), true);
  await page.evaluate(() => window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f2'), progress: 60 }));
  assert.equal(await page.locator('li.row[data-id="f2"] .icon-slot').evaluate((n) => n.classList.contains('fade')), false);
  await done(page);
});

scenario('live rows: progress updates in place, removal moves focus, status events', async () => {
  const page = await drop('list');
  await ready(page);
  const bar = page.locator('li.row[data-id="f2"] progress');
  await bar.evaluate((node) => { node.dataset.same = 'yes'; });
  await page.evaluate(() => window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f2'), progress: 80 }));
  assert.equal(await text(page.locator('li.row[data-id="f2"] .row-visual')), 'Copying online · 80%');
  assert.equal(await bar.getAttribute('data-same'), 'yes', 'the progress element is reused');
  assert.equal(await bar.evaluate((n) => n.value), 80);
  await page.locator('li.row[data-id="f1"] [data-ctl="share"]').focus();
  await page.evaluate(() => window.__stub.emit('drop://file', { id: 'f1', removed: true }));
  assert.equal(await page.locator('li.row[data-id="f1"]').count(), 0);
  assert.equal(await page.evaluate(() => document.activeElement.closest('li.row')?.getAttribute('data-id')), 'f2', 'focus moves to a neighbouring row');
  
  await done(page);
});

/* ---------- keyboard, platform, web tells ---------- */

scenario('keyboard: tab order, roving rows with arrows, Home and End', async () => {
  const page = await drop('list');
  await ready(page);
  await page.evaluate(() => document.body.focus());
  const stops = [];
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press('Tab');
    stops.push(await page.evaluate(() => { const a = document.activeElement; return a.getAttribute('aria-label') || a.textContent.trim(); }));
  }
  assert.deepEqual(stops, ['Retry all', 'Share holiday.jpg', 'More actions for holiday.jpg', 'Share tax-return-2026.pdf', 'More actions for tax-return-2026.pdf', 'Retry copying notes.txt', 'More actions for notes.txt', 'Share archive.zip', 'More actions for archive.zip', 'Share quote.pdf', 'More actions for quote.pdf', 'Add files…', 'More ways to add files', 'Settings']);
  assert.equal(await page.locator('[tabindex]:not([tabindex="-1"])').count(), 0, 'no positive tabindex');
  await page.locator('li.row[data-id="f1"] [data-ctl="share"]').focus();
  await page.keyboard.press('ArrowDown');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Share tax-return-2026.pdf');
  await page.keyboard.press('ArrowDown');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Retry copying notes.txt', 'falls back to the row\'s own control');
  await page.keyboard.press('End');
  assert.equal(await page.evaluate(() => document.activeElement.closest('li').getAttribute('data-id')), 'f12');
  await page.keyboard.press('ArrowUp');
  assert.equal(await page.evaluate(() => document.activeElement.closest('li').getAttribute('data-id')), 'f9');
  await page.keyboard.press('Home');
  assert.equal(await page.evaluate(() => document.activeElement.closest('li').getAttribute('data-id')), 'f1');
  await page.locator('li.row[data-id="f1"] [data-ctl="more"]').focus();
  await page.keyboard.press('ArrowDown');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'More actions for tax-return-2026.pdf');
  await done(page);
});

scenario('platform: data attributes, button order attribute, shortcuts, reload keys, context menu', async () => {
  const cases = [['mac', '', 'mac', '', 'primary-right'], ['windows', '', 'windows', '', 'primary-left'], ['linux', 'gnome', 'linux', 'gnome', 'primary-right'], ['linux', 'kde', 'linux', 'kde', 'primary-left']];
  for (const [os, desktop, expectOs, expectDesktop, order] of cases) {
    const page = await drop('list', { os, desktop });
    await ready(page);
    assert.deepEqual(await page.evaluate(() => [document.documentElement.dataset.os, document.documentElement.dataset.desktop, document.documentElement.dataset.buttonOrder]), [expectOs, expectDesktop, order], `${os} ${desktop}`);
    await done(page);
  }
  let page = await drop('list');
  await ready(page);
  const prevented = await page.evaluate(() => ['F5', 'r'].map((key) => { const event = new KeyboardEvent('keydown', { key, metaKey: key === 'r', cancelable: true, bubbles: true }); document.dispatchEvent(event); return event.defaultPrevented; }));
  assert.deepEqual(prevented, [true, true]);
  const context = await page.evaluate(() => { const event = new MouseEvent('contextmenu', { cancelable: true, bubbles: true }); document.body.dispatchEvent(event); return event.defaultPrevented; });
  assert.equal(context, true, 'web context menu suppressed');
  await page.keyboard.press('Meta+o');
  assert.equal((await calls(page, 'pick_files')).length, 1);
  await page.locator('li.row[data-id="f1"]').click({ button: 'right' });
  assert.equal(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text).join('|')), 'Share…|Save a Copy…|Remove…');
  assert.equal(typeof (await page.evaluate(() => window.__stub.lastMenu.at.x)), 'number');
  await page.locator('li.row[data-id="f1"] [data-ctl="share"]').focus();
  await page.keyboard.press('Meta+Shift+s');
  await page.locator('dialog[open] h2').waitFor();
  assert.equal((await calls(page, 'share_start')).length, 1);
  await done(page);
  page = await drop('list', { os: 'windows' });
  await ready(page);
  await page.keyboard.press('Control+o');
  await page.keyboard.press('Meta+o');
  assert.equal((await calls(page, 'pick_files')).length, 1, 'Ctrl on Windows, not Meta');
  await page.keyboard.press('Control+,');
  assert.equal(await page.evaluate(() => window.__stub.windows.length), 2);
  await done(page);
  page = await drop('list');
  await ready(page);
  assert.equal(await page.evaluate(() => { const ids = [...document.querySelectorAll('h1, h2, h3')].map((n) => n.tagName); return ids.slice(0, 3).join(); }), 'H1,H2,H3');
  assert.deepEqual(await page.evaluate(() => [document.querySelector('header').localName, document.querySelector('main').localName, document.querySelector('footer').localName, document.querySelector('ul.files').getAttribute('aria-label')]), ['header', 'main', 'footer', 'Kept files']);
  await done(page);
});

/* ---------- confirm dialogs ---------- */

scenario('confirm dialogs: Stop sharing and Remove copy, Cancel focused, order per platform', async () => {
  for (const [os, desktop, confirmFirst] of [['mac', '', false], ['windows', '', true], ['linux', 'gnome', false], ['linux', 'kde', true]]) {
    const page = await drop('good', { os, desktop });
    await ready(page);
    await page.locator('li.row[data-id="f21"] [data-ctl="more"]').click();
    await menuAction(page, 'Remove');
    const dialog = page.locator('dialog[open]');
    await dialog.waitFor();
    assert.equal(await text(dialog.locator('h2')), 'Remove cv.pdf from Wildbloom?');
    assert.deepEqual(await dialog.locator('p').allTextContents(), ["Both copies and the key that unlocks them are deleted. This can't be undone. The original file on your computer isn't touched.", "It stays in your Wildbloom folder, but Wildbloom won't keep copies of it."]);
    assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Cancel', `${os} ${desktop} cancel is the default`);
    const labels = await dialog.locator('button').allTextContents();
    assert.deepEqual(labels, confirmFirst ? ['Remove', 'Cancel'] : ['Cancel', 'Remove'], `${os} ${desktop} order`);
    await page.keyboard.press('Enter');
    await dialog.waitFor({ state: 'detached' });
    assert.equal((await calls(page, 'remove')).length, 0, 'Enter on the default Cancel removes nothing');
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'More actions for cv.pdf', 'focus returns');
    await done(page);
  }
  let page = await drop('good');
  await ready(page);
  await page.locator('li.row[data-id="f1"] [data-ctl="more"]').click();
  await menuAction(page, 'Remove');
  assert.deepEqual(await page.locator('dialog[open] p').allTextContents(), ["Both copies and the key that unlocks them are deleted. This can't be undone. The original file on your computer isn't touched."]);
  await page.locator('dialog[open] button', { hasText: 'Remove' }).click();
  await page.waitForFunction(() => !document.querySelector('li.row[data-id="f1"]'));
  assert.deepEqual((await calls(page, 'remove')).map((c) => c.args), [{ id: 'f1' }]);
  await done(page);
  page = await drop('list');
  await ready(page);
  await page.locator('li.row[data-id="f12"] [data-ctl="more"]').click();
  await menuAction(page, 'Stop');
  const stop = page.locator('dialog[open]');
  assert.equal(await text(stop.locator('h2')), 'Stop sharing quote.pdf?');
  assert.equal(await text(stop.locator('p')), "The shared copy is deleted. Anyone who hasn't downloaded it yet won't be able to. Anyone who already has it keeps their copy.");
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Cancel');
  await page.keyboard.press('Escape');
  await stop.waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'stop_sharing')).length, 0);
  await page.locator('li.row[data-id="f12"] [data-ctl="more"]').click();
  await menuAction(page, 'Stop');
  await page.locator('dialog[open] button', { hasText: 'Stop sharing' }).click();
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'stop_sharing'));
  assert.deepEqual((await calls(page, 'stop_sharing')).map((c) => c.args), [{ id: 'f12' }]);
  await page.locator('li.row[data-id="f1"] [data-ctl="more"]').click();
  await menuAction(page, 'Save');
  await page.waitForFunction(() => document.querySelector('#notices').textContent.startsWith('Saved'));
  assert.equal(await text(page.locator('#notices')), 'Saved holiday.jpg to Downloads.');
  assert.deepEqual((await calls(page, 'save_copy')).at(-1).args, { id: 'f1' }, 'Rust opens the save dialog; the page names no path');
  await done(page);
});

/* ---------- share sheet ---------- */

const LINK = 'https://wildbloom.example/get#v1.abc123';
const WORDS = ['orbit', 'lemon', 'candle', 'frost'];
async function openShare(page, payload, rowId = 'f1') {
  await page.evaluate((initial) => { window.__stub.handlers.share_start = async () => initial; window.__stub.handlers.share_again = async () => initial; }, payload);
  await page.locator(`li.row[data-id="${rowId}"] [data-ctl="share"]`).click();
  await page.locator('dialog.sheet[open]').waitFor();
  await page.waitForTimeout(60);
}
const emitShare = (page, payload) => page.evaluate((p) => window.__stub.emit('share://state', { id: 'f1', ...p }), payload);

scenario('share sheet: S1 too big, S2 preparing', async () => {
  let page = await drop('list');
  await ready(page);
  await page.evaluate(() => { window.__stub.pushRow({ ...window.__stub.files.find((r) => r.id === 'f1'), bytes: 300_000_000 }); });
  await page.locator('li.row[data-id="f1"] [data-ctl="share"]').click();
  const sheet = page.locator('dialog.sheet[open]');
  await sheet.waitFor();
  assert.equal(await text(sheet.locator('h2')), 'Share holiday.jpg');
  assert.equal(await visual(sheet.locator('[role="status"].share-slot')), "Files over 250 MB can't be shared yet.");
  assert.deepEqual(await sheet.locator('button').allTextContents(), ['Close']);
  assert.equal((await calls(page, 'share_start')).length, 0, 'no work is started for a file that is too big');
  await page.locator('dialog button', { hasText: 'Close' }).click();
  await sheet.waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'share_cancel')).length, 0);
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Share holiday.jpg');
  await done(page);
  page = await drop('list');
  await ready(page);
  await openShare(page, { state: 'preparing', progress: 45 });
  assert.equal(await text(page.locator('.share-slot')), 'Making a copy to share · 45%');
  assert.equal(await page.locator('dialog progress').getAttribute('aria-label'), 'Making a copy of holiday.jpg to share');
  await emitShare(page, { state: 'preparing', progress: 70 });
  assert.equal(await text(page.locator('.share-slot')), 'Making a copy to share · 70%');
  assert.equal(await page.locator('dialog progress').evaluate((n) => n.value), 70);
  assert.deepEqual(await page.locator('dialog.sheet button').allTextContents(), ['Cancel']);
  await done(page);
});

scenario('share sheet: S3 to S7 happy path, copy buttons, focus, Escape, Done', async () => {
  const page = await drop('list');
  await ready(page);
  const expiresAt = nowSeconds + 581;
  await openShare(page, { state: 'ready', link: LINK, words: WORDS, expiresAt });
  const sheet = page.locator('dialog.sheet[open]');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Share holiday.jpg', 'focus starts on the heading');
  assert.equal(await sheet.getAttribute('aria-labelledby'), await sheet.locator('h2').getAttribute('id'));
  assert.equal(await sheet.locator('input[readonly]').inputValue(), LINK);
  assert.equal(await sheet.locator('ol.words').getAttribute('aria-label'), 'Words to read out: orbit, lemon, candle, frost');
  assert.deepEqual(await sheet.locator('ol.words li').allTextContents(), ['1orbit'.slice(1), 'lemon', 'candle', 'frost']);
  assert.match(await visual(sheet), /Send them this link/);
  assert.match(await visual(sheet), /Phone them and read out these words/);
  assert.match(await visual(sheet), /Don't send the words with the link\. Anyone with both can get the file\./);
  assert.equal(await visual(sheet.locator('[role="status"].share-slot')), 'Waiting for them to open the link 9:41 left');
  assert.equal(await sheet.locator('.share-time').getAttribute('aria-hidden'), 'true');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Copy link', 'Copy link is the next stop');
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(() => window.__stub.clipboard), LINK);
  assert.equal(await text(sheet.locator('[data-key="copy-link"]')), 'Copied');
  await sheet.locator('[data-key="copy-words"]').click();
  assert.equal(await page.evaluate(() => window.__stub.clipboard), 'orbit lemon candle frost');
  assert.equal(await text(sheet.locator('[data-key="copy-words"]')), 'Copied');

  await page.locator('[data-key="copy-link"]').focus();
  await emitShare(page, { state: 'opened', link: LINK, words: WORDS, expiresAt });
  assert.equal(await visual(sheet.locator('.share-slot')), "They've opened the link. 9:41 left");
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('data-key')), 'copy-link', 'focus stays on a control that survives the state change');
  await emitShare(page, { state: 'check', link: LINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt });
  assert.match(await visual(sheet), /3 Read these words to them/);
  assert.match(await visual(sheet), /Ask if they see the same 3 words\./);
  assert.equal(await sheet.locator('ol.words').nth(0).getAttribute('aria-label'), 'Check words to read out: apple, river, stone', 'steps 1 and 2 are done, so the check words are the only list');
  assert.deepEqual(await sheet.locator('.dialog-actions button').allTextContents(), ["They don't match", 'They match, send file'], 'macOS order: primary on the right');
  await sheet.locator('button', { hasText: 'They match, send file' }).click();
  assert.deepEqual((await calls(page, 'share_verify')).at(-1).args, { id: 'f1', matches: true });
  await page.waitForFunction(() => document.querySelector('.share-slot').textContent.includes('Sending'));
  assert.equal(await visual(sheet.locator('.share-slot')), 'Sending…');
  await emitShare(page, { state: 'sent', deleteAt: nowSeconds + 86400 });
  assert.equal(await text(sheet.locator('h2')), 'Share holiday.jpg', 'the heading keeps the file name');
  assert.equal(await visual(sheet.locator('.share-slot')), 'They can download holiday.jpg now.');
  assert.match(await visual(sheet), new RegExp(`Wildbloom deletes the shared copy at ${clockTime(nowSeconds + 86400)} tomorrow, or sooner if you stop sharing\\. This computer needs to be on to delete it\\.`));
  assert.doesNotMatch(await visual(sheet), /Stopping can't take back/);
  assert.deepEqual(await sheet.locator('.dialog-actions button').allTextContents(), ['Stop sharing…', 'Done']);
  await page.locator('dialog.sheet button', { hasText: 'Done' }).click();
  await sheet.waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'share_cancel')).length, 0, 'closing after a send does not delete the shared copy');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Share holiday.jpg');
  await done(page);
});

scenario('share sheet: Escape cancels, Start again, Try again, wrong words, Stop sharing from the sheet', async () => {
  const page = await drop('list');
  await ready(page);
  await openShare(page, { state: 'ready', link: LINK, words: WORDS, expiresAt: nowSeconds + 500 });
  await page.keyboard.press('Escape');
  await page.locator('dialog.sheet').waitFor({ state: 'detached' });
  assert.deepEqual((await calls(page, 'share_cancel')).map((c) => c.args), [{ id: 'f1' }], 'Escape cancels the session');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Share holiday.jpg', 'focus returns to the row Share button');

  const terminal = [
    ['expired', 'The link ran out of time before they connected.', ['Close', 'Start again']],
    ['wrong_words', 'Someone typed the wrong words, so this link stopped working. Check you read them clearly.', ['Close', 'Start again'], { triesLeft: 0 }],
    ['mismatch', "Sharing stopped because the words didn't match. Nothing was sent.", ['Close', 'Start again']],
    ['left', 'They left before the file was sent.', ['Close', 'Start again']],
    ['relay_unreachable', "Can't reach the sharing service. Check your internet connection.", ['Close', 'Try again']],
    ['node_unreachable', "Can't reach your online node, so the shared copy couldn't be made.", ['Close', 'Try again']],
  ];
  for (const [state, copy, buttons, extra] of terminal) {
    await openShare(page, { state: 'ready', link: LINK, words: WORDS, expiresAt: nowSeconds + 500 });
    await page.locator('[data-key="copy-link"]').focus();
    await emitShare(page, { state, ...(extra || {}) });
    assert.equal(await visual(page.locator('dialog .share-slot')), copy, state);
    assert.deepEqual(await page.locator('dialog.sheet .dialog-actions button').allTextContents(), buttons, `${state} buttons`);
    assert.equal(await page.evaluate(() => document.activeElement.textContent), buttons[1], `${state} focus on the primary action`);
    await page.keyboard.press('Escape');
    await page.locator('dialog.sheet').waitFor({ state: 'detached' });
  }
  await page.evaluate(() => { window.__stub.calls.length = 0; });
  await openShare(page, { state: 'ready', link: LINK, words: WORDS, expiresAt: nowSeconds + 500 });
  await emitShare(page, { state: 'expired' });
  await page.evaluate(() => { window.__stub.handlers.share_again = async () => ({ state: 'ready', link: 'https://wildbloom.example/get#fresh', words: ['river', 'maple', 'tide', 'ember'], expiresAt: Math.floor(Date.now() / 1000) + 600 }); });
  await page.locator('dialog button', { hasText: 'Start again' }).click();
  await page.waitForFunction(() => document.querySelector('dialog input[readonly]')?.value.endsWith('#fresh'));
  assert.deepEqual((await calls(page, 'share_again')).map((c) => c.args), [{ id: 'f1' }]);
  assert.equal(await page.locator('ol.words li').count(), 4);
  await emitShare(page, { state: 'node_unreachable' });
  await page.locator('dialog button', { hasText: 'Try again' }).click();
  assert.equal((await calls(page, 'share_start')).length >= 1, true);
  await emitShare(page, { state: 'wrong_words', link: LINK, words: WORDS, triesLeft: 2, expiresAt: nowSeconds + 400 });
  assert.equal(await visual(page.locator('dialog .share-slot')), 'They typed the wrong words. They can try 2 more times. 6:40 left');
  await emitShare(page, { state: 'wrong_words', link: LINK, words: WORDS, triesLeft: 1, expiresAt: nowSeconds + 400 });
  assert.match(await visual(page.locator('dialog .share-slot')), /They can try 1 more time\./);
  await emitShare(page, { state: 'check', link: LINK, words: WORDS, checkWords: ['a', 'b', 'c'], expiresAt: nowSeconds + 400 });
  await page.locator('dialog button', { hasText: "They don't match" }).click();
  assert.deepEqual((await calls(page, 'share_verify')).at(-1).args, { id: 'f1', matches: false });
  await page.waitForFunction(() => document.querySelector('dialog .share-slot').textContent.startsWith('Sharing stopped'));
  await page.keyboard.press('Escape');
  await page.locator('dialog.sheet').waitFor({ state: 'detached' });

  await openShare(page, { state: 'sent', deleteAt: nowSeconds + 3600 }, 'f12');
  await page.locator('dialog.sheet button', { hasText: 'Stop sharing…' }).click();
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Cancel');
  await page.locator('dialog.confirm button', { hasText: 'Stop sharing' }).click();
  await page.waitForFunction(() => !document.querySelector('dialog'));
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'stop_sharing'));
  assert.deepEqual((await calls(page, 'stop_sharing')).at(-1).args, { id: 'f12' });
  await done(page);
});

scenario('share sheet: share again on a shared row and unreachable start', async () => {
  const page = await drop('list');
  await ready(page);
  await openShare(page, { state: 'ready', link: LINK, words: WORDS, expiresAt: nowSeconds + 500 }, 'f12');
  assert.equal((await calls(page, 'share_again')).length, 1, 'Share on a shared row reuses the shared copy');
  assert.equal((await calls(page, 'share_start')).length, 0);
  await page.keyboard.press('Escape');
  await page.locator('dialog.sheet').waitFor({ state: 'detached' });
  await page.evaluate(() => { window.__stub.handlers.share_start = async () => { throw { code: 'node_unreachable' }; }; });
  await page.locator('li.row[data-id="f1"] [data-ctl="share"]').click();
  await page.waitForFunction(() => document.querySelector('dialog .share-slot')?.textContent.includes('online node'));
  assert.equal(await visual(page.locator('dialog .share-slot')), "Can't reach your online node, so the shared copy couldn't be made.");
  await done(page);
});

scenario('share sheet: countdown and 2 minute and 1 minute announcements (fake clock)', async () => {
  const page = await drop('list', { clock: 'install' });
  await ready(page);
  await page.clock.runFor(200);
  await openShare(page, { state: 'ready', link: LINK, words: WORDS, expiresAt: nowSeconds + 125 });
  await page.clock.runFor(1000);
  assert.match(await text(page.locator('.share-time')), /^2:0[34] left$/);
  await page.clock.runFor(6000);
  await page.clock.runFor(100);
  assert.equal(await text(page.locator('dialog [role="status"].sr-only')), '2 minutes left.');
  await page.clock.runFor(64000);
  assert.equal(await text(page.locator('dialog [role="status"].sr-only')), '1 minute left.');
  await page.clock.runFor(60000);
  assert.equal(await text(page.locator('.share-time')), '0:00 left');
  await done(page);
});

scenario('share sheet: button order follows the platform, and stacks primary first when it must', async () => {
  // Default system font and wide sans metrics (the usual Linux default), at
  // the default and the narrowest window: side by side the order follows the
  // platform; stacked, the primary action is on top.
  for (const font of [undefined, 'wide']) {
    for (const width of [400, 340]) {
      for (const [os, desktop, first] of [['mac', '', "They don't match"], ['linux', 'gnome', "They don't match"], ['windows', '', 'They match, send file'], ['linux', 'kde', 'They match, send file']]) {
        const label = `${os} ${desktop} ${font || 'system'} font at ${width}`;
        const page = await drop('list', { os, desktop, font, width, height: 640 });
        await ready(page);
        await openShare(page, { state: 'check', link: LINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt: nowSeconds + 500 });
        const rects = await page.evaluate(() => [...document.querySelectorAll('dialog .dialog-actions button')].map((b) => { const r = b.getBoundingClientRect(); return { t: b.textContent, x: r.left, y: r.top, right: r.right }; }));
        assert.equal(rects.length, 2, label);
        const primary = rects.find((r) => r.t === 'They match, send file');
        const secondary = rects.find((r) => r.t === "They don't match");
        const viewport = await page.evaluate(() => document.documentElement.clientWidth);
        assert.ok(rects.every((r) => r.x >= 0 && r.right <= viewport + 0.5), `${label}: buttons inside the window`);
        if (Math.abs(primary.y - secondary.y) < 2) {
          const leftmost = [...rects].sort((a, b) => a.x - b.x)[0].t;
          assert.equal(leftmost, first, `${label}: leftmost button`);
        } else {
          assert.ok(primary.y < secondary.y, `${label}: stacked with the primary action on top`);
        }
        await done(page);
      }
    }
  }
});

/* ---------- first run ---------- */

scenario('first run D1: validation, check states, success flash, set up later', async () => {
  let page = await drop('first-run-1');
  await ready(page);
  const flow = page.locator('#view-first');
  assert.equal(await page.locator('#drop-header').isHidden(), true);
  assert.equal(await page.locator('#drop-footer').isHidden(), true);
  assert.equal(await text(flow.locator('.eyebrow')), 'Step 1 of 3');
  assert.equal(await text(flow.locator('h2')), 'Set up Wildbloom Drop');
  assert.match(await text(flow), /Drop a file here and Wildbloom keeps two encrypted copies: one on this computer and one on your online node\./);
  assert.match(await text(flow), /Online node address/);
  assert.equal(await flow.locator('input').getAttribute('placeholder'), 'https://storage.example');
  assert.match(await text(flow), /The address of the Wildbloom Node you run online\./);
  assert.match(await text(flow), /Wildbloom Node will run on this computer only\. You can change that later in Node settings\./);
  assert.deepEqual(await flow.locator('button').allTextContents(), ['Continue', 'Set up later and keep copies on this computer only', 'Restore from a recovery key']);
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Set up Wildbloom Drop');
  const attempt = async (value) => { await flow.locator('input').fill(value); await flow.locator('button', { hasText: 'Continue' }).click(); };
  await attempt('');
  assert.equal(await text(flow.locator('[role="alert"]')), "Enter your online node's address.");
  assert.equal(await flow.locator('input').getAttribute('aria-invalid'), 'true');
  await attempt('http://storage.example');
  assert.equal(await text(flow.locator('[role="alert"]')), 'Use an address that starts with https://');
  await attempt('storage.example');
  assert.equal(await text(flow.locator('[role="alert"]')), 'Use an address that starts with https://');
  assert.equal((await calls(page, 'check_online_node')).length, 0, 'invalid input never reaches Rust');
  await attempt('https://silent.example');
  await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]:not([hidden])')?.textContent.includes('respond'));
  assert.equal(await text(flow.locator('[role="alert"]')), "silent.example didn't respond. Check the address and your internet connection.");
  await attempt('https://notnode.example');
  await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]:not([hidden])')?.textContent.includes('isn'));
  assert.equal(await text(flow.locator('[role="alert"]')), "notnode.example isn't a Wildbloom Node.");
  await attempt('https://badtls.example');
  await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]:not([hidden])')?.textContent.includes('secure'));
  assert.equal(await text(flow.locator('[role="alert"]')), "Couldn't make a secure connection to badtls.example.");
  await page.evaluate(() => { window.__stub.handlers.check_online_node = () => new Promise((resolve) => { window.__release = () => resolve({ ok: true, host: 'storage.example', usedBytes: 0, limitBytes: 5_000_000_000 }); }); });
  await attempt('https://storage.example/');
  await page.waitForFunction(() => document.querySelector('#view-first button[type="submit"]').textContent === 'Checking…');
  assert.equal(await flow.locator('button[type="submit"]').getAttribute('aria-disabled'), 'true');
  assert.equal(await text(flow.locator('[role="status"]')), 'Checking storage.example…');
  await page.evaluate(() => window.__release());
  await page.waitForFunction(() => document.querySelector('#view-first [role="status"]')?.textContent.startsWith('Found it'));
  assert.equal(await text(flow.locator('[role="status"]')), 'Found it. 5 GB free.');
  await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Approve this computer', null, { timeout: 4000 });
  assert.deepEqual((await calls(page, 'set_online_node')).at(-1).args, { url: 'https://storage.example' });
  assert.equal(await text(flow.locator('.eyebrow')), 'Step 2 of 3');
  await done(page);

  page = await drop('first-run-1');
  await ready(page);
  await page.locator('button', { hasText: 'Set up later' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Save your recovery key');
  assert.deepEqual((await calls(page, 'set_online_node')).at(-1).args, { url: null });
  assert.equal(await text(page.locator('#view-first .eyebrow')), 'Step 3 of 3', 'the recovery key is still required');
  await done(page);

  page = await drop('first-run-1');
  await ready(page);
  await page.evaluate(() => { window.__stub.state.firstRun.nodeSettingsExist = true; });
  await done(page);
});

scenario('first run D2: facts, paste, bad link, waiting, cancel, errors, success', async () => {
  const page = await drop('first-run-2');
  await ready(page);
  const flow = page.locator('#view-first');
  await flow.locator('h2').waitFor();
  assert.equal(await text(flow.locator('.eyebrow')), 'Step 2 of 3');
  assert.equal(await text(flow.locator('h2')), 'Approve this computer');
  assert.match(await text(flow), /Your signer approves this computer once\. After that, Wildbloom copies files to your online node without asking each time\./);
  assert.equal(await visual(flow.locator('dl')), `This computer ${NPUB_SHORT} Copy Allowed Up to 5 GB, until 16 October 2027`);
  await flow.locator('dl button').click();
  assert.equal(await page.evaluate(() => window.__stub.clipboard), await page.evaluate(() => window.__stub.npub), 'copies the full public key');
  assert.match(await text(flow), /Signer connection link/);
  assert.match(await text(flow), /From Heartwood or another NIP-46 signer\. It starts with bunker:\/\//);
  assert.equal(await flow.locator('button', { hasText: 'Approve in your browser instead' }).count(), 0, 'hidden until the browser route exists');
  assert.deepEqual(await flow.locator('button').allTextContents(), ['Copy', 'Paste', 'Ask my signer to approve']);
  await flow.locator('button', { hasText: 'Paste' }).click();
  assert.equal(await flow.locator('input').inputValue(), 'bunker://relay.example/pair?secret=abc');
  await flow.locator('input').fill('nsec-not-a-link');
  await flow.locator('button', { hasText: 'Ask my signer' }).click();
  assert.equal(await text(flow.locator('[role="alert"]')), "That isn't a signer connection link. It should start with bunker://");
  assert.equal((await calls(page, 'approve_device')).length, 0);
  await flow.locator('input').fill('bunker://relay.example/pair?secret=abc');
  await flow.locator('button', { hasText: 'Ask my signer' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first p[role="status"]')?.textContent.startsWith('Waiting'));
  assert.equal(await text(flow.locator('p[role="status"]')), 'Waiting for your signer. Check your Heartwood device.');
  assert.deepEqual((await calls(page, 'approve_device')).at(-1).args, { bunkerUrl: 'bunker://relay.example/pair?secret=abc' });
  await flow.locator('button', { hasText: 'Cancel' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first input'));
  assert.equal((await calls(page, 'cancel_approval')).length, 1);
  assert.equal(await flow.locator('input').inputValue(), 'bunker://relay.example/pair?secret=abc', 'the link stays filled in');

  const failures = [
    [{ state: 'failed', code: 'timeout' }, "Your signer didn't answer within 2 minutes. Check it's on and connected, then try again."],
    [{ state: 'failed', code: 'declined' }, 'Your signer declined. Nothing was changed.'],
    [{ state: 'failed', code: 'wrong_owner', ownerNpub: 'npub1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzabcd' }, "Your online node doesn't recognise npub1zz…abcd as its owner. Approve with the key that runs the node."],
    [{ state: 'failed', code: 'refused', detail: 'grant limit too high' }, "Your online node didn't accept the approval: grant limit too high."],
    [{ state: 'failed', code: 'offline' }, "You're offline. Connect to the internet, then try again."],
  ];
  for (const [status, copy] of failures) {
    await page.evaluate((next) => { window.__stub.handlers.approve_device = () => { window.__stub.approval = next; }; }, status);
    await flow.locator('button', { hasText: 'Ask my signer' }).click();
    await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]:not([hidden])'), null, { timeout: 4000 });
    assert.equal(await text(flow.locator('[role="alert"]')), copy);
    assert.equal(await flow.locator('input').inputValue(), 'bunker://relay.example/pair?secret=abc');
    assert.equal(await page.evaluate(() => document.activeElement.tagName), 'INPUT', 'focus returns to the field');
  }
  await page.evaluate(() => {
    window.__stub.handlers.approve_device = () => { window.__stub.approval = { state: 'approved', byNpub: window.__stub.npub }; };
    window.__stub.state.firstRun.step = 'recovery';
  });
  await flow.locator('button', { hasText: 'Ask my signer' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first p[role="status"]')?.textContent.startsWith('Approved'), null, { timeout: 4000 });
  assert.equal(await text(flow.locator('p[role="status"]')), `Approved by ${NPUB_SHORT}.`);
  await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Save your recovery key', null, { timeout: 4000 });
  await done(page);
});

scenario('first run D3: key display, save and copy, Finish gating', async () => {
  const page = await drop('first-run-3');
  await ready(page);
  const flow = page.locator('#view-first');
  await flow.locator('.key').waitFor();
  assert.equal(await text(flow.locator('.eyebrow')), 'Step 3 of 3');
  assert.equal(await text(flow.locator('h2')), 'Save your recovery key');
  assert.match(await text(flow), /If this computer is lost or breaks, this key is the only way to unlock your files on your online node\. Wildbloom can't recover it for you\./);
  const key = await page.evaluate(() => window.__stub.key);
  assert.equal(await flow.locator('.key').evaluate((n) => n.textContent), key, 'the key text is exact, grouping is visual only');
  assert.equal(await flow.locator('.key .grp').count(), Math.ceil(key.length / 6));
  assert.match(await text(flow), /Keep it in a password manager or print the file\. Don't keep it only on this computer\. Anyone with this key and access to your online node could unlock your files\./);
  const finish = flow.locator('button', { hasText: 'Finish' });
  const checkbox = flow.locator('input[type="checkbox"]');
  assert.equal(await text(flow.locator('label.check')), "I've saved my recovery key somewhere other than this computer");
  assert.equal(await finish.isDisabled(), true);
  await checkbox.check();
  assert.equal(await finish.isDisabled(), true, 'ticking alone is not enough');
  await checkbox.uncheck();
  await flow.locator('button', { hasText: 'Copy' }).click();
  assert.equal(await page.evaluate(() => window.__stub.clipboard), key);
  assert.equal(await text(flow.locator('[role="status"]')), 'Copied.');
  assert.equal(await finish.isDisabled(), true, 'using Copy alone is not enough');
  await flow.locator('button', { hasText: 'Save recovery file…' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first [role="status"]')?.textContent.startsWith('Saved'));
  assert.equal(await text(flow.locator('[role="status"]')), 'Saved to Wildbloom recovery key.txt.');
  assert.equal((await calls(page, 'save_recovery_file')).at(-1).args, undefined, 'Rust opens the save dialog; the page names no path');
  await checkbox.check();
  assert.equal(await finish.isEnabled(), true);
  await finish.click();
  await page.waitForFunction(() => !document.querySelector('#view-drop').hidden);
  assert.equal((await calls(page, 'confirm_recovery_saved')).length, 1);
  assert.equal(await page.locator('#view-first').evaluate((n) => n.children.length), 0, 'the key is gone from the page');
  assert.equal(await page.locator('#drop-header').isVisible(), true);
  await done(page);
});

scenario('first run D4: keychain missing on each platform, Try again', async () => {
  const expected = {
    mac: ['Wildbloom needs your keychain', 'Wildbloom keeps its keys in your login keychain. Allow access when macOS asks, then try again.'],
    windows: ['Wildbloom needs Credential Manager', 'Wildbloom keeps its keys in Windows Credential Manager. Try again, and if this keeps happening, restart your computer.'],
    linux: ['Wildbloom needs your keyring', 'Wildbloom keeps its keys in your keyring. Install or unlock GNOME Keyring or KWallet, then try again.'],
  };
  for (const [os, [heading, body]] of Object.entries(expected)) {
    const page = await drop('first-run-keychain', { os, desktop: os === 'linux' ? 'gnome' : '' });
    await ready(page);
    const flow = page.locator('#view-first');
    await flow.locator('h2').waitFor();
    assert.equal(await text(flow.locator('h2')), heading, os);
    assert.equal(await text(flow.locator('p.body')), body, os);
    await flow.locator('button', { hasText: 'Try again' }).click();
    await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]:not([hidden])'));
    assert.equal(await text(flow.locator('[role="alert"]')), "Still can't reach it.");
    await page.evaluate(() => { window.__stub.keychainFixed = true; });
    await flow.locator('button', { hasText: 'Try again' }).click();
    await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Set up Wildbloom Drop');
    await done(page);
  }
  const page = await drop('first-run-1');
  await ready(page);
  await page.locator('#view-first input').fill('https://keychain.example');
  await page.locator('#view-first button[type="submit"]').click();
  await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Wildbloom needs your keychain');
  await done(page);
});

scenario('first run: Restore from a recovery key', async () => {
  const page = await drop('first-run-1');
  await ready(page);
  const flow = page.locator('#view-first');
  await flow.locator('button', { hasText: 'Restore from a recovery key' }).click();
  assert.equal(await text(flow.locator('h2')), 'Restore your files');
  assert.equal(await flow.locator('.eyebrow').count(), 0);
  assert.match(await text(flow), /Enter your recovery key and approve this computer\. Wildbloom copies your files back from your online node\./);
  assert.deepEqual(await flow.locator('button').allTextContents(), ['Paste', 'Open recovery file…', 'Continue', 'Back']);
  const key = 'wbk1_abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef';
  await flow.locator('input').nth(0).fill('hello');
  await flow.locator('button', { hasText: 'Continue' }).click();
  assert.equal(await text(flow.locator('[role="alert"]')), "That isn't a Wildbloom recovery key. It starts with wbk1_");
  await flow.locator('input').nth(0).fill(key);
  await flow.locator('input').nth(1).fill('https://nofiles.example');
  await flow.locator('button', { hasText: 'Continue' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]')?.textContent.includes('No files'));
  assert.equal(await text(flow.locator('[role="alert"]')), 'No files were found for this recovery key on nofiles.example.');
  await flow.locator('input').nth(1).fill('https://wrongkey.example');
  await flow.locator('button', { hasText: 'Continue' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first [role="alert"]')?.textContent.includes("doesn't unlock"));
  assert.equal(await text(flow.locator('[role="alert"]')), "This recovery key doesn't unlock the files on wrongkey.example.");
  await flow.locator('button', { hasText: 'Open recovery file…' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first .hint[role="status"]')?.textContent.startsWith('Using'));
  assert.equal(await flow.locator('input').nth(0).isDisabled(), true);
  await flow.locator('input').nth(1).fill('');
  await flow.locator('input').nth(0).evaluate((n) => { n.disabled = false; });
  await flow.locator('button', { hasText: 'Paste' }).click();
  assert.equal(await flow.locator('input').nth(0).inputValue(), 'bunker://relay.example/pair?secret=abc', 'paste fills the key field and drops the file');
  await flow.locator('input').nth(0).fill(key);
  await flow.locator('input').nth(1).fill('https://storage.example');
  await flow.locator('button', { hasText: 'Continue' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Approve this computer');
  assert.deepEqual((await calls(page, 'restore')).at(-1).args, { recoveryKey: key, recoveryFile: null, url: 'https://storage.example' });
  assert.equal(await flow.locator('.eyebrow').count(), 0, 'no step counter while restoring');
  await flow.locator('input').fill('bunker://relay.example/pair?secret=abc');
  await page.evaluate(() => { window.__stub.handlers.approve_device = () => { window.__stub.approval = { state: 'restore_failed', code: 'no_files' }; }; });
  await flow.locator('button', { hasText: 'Ask my signer' }).click();
  await page.waitForFunction(() => document.querySelector('#view-first h2')?.textContent === 'Restore your files', null, { timeout: 4000 });
  assert.equal(await text(flow.locator('[role="alert"]')), 'No files were found for this recovery key on storage.example.');
  await done(page);
});

/* ---------- node window settings (section 9.5) ---------- */

async function settingsPage(options = {}, query = '') {
  const page = await open(`${base}/ui/index.html?state=good${query}`, { width: 820, height: 900, ...options });
  await page.evaluate(() => {
    window.__stub.handlers.node_status = () => ({ phase: 'ready', phaseLabel: 'Ready', detail: 'ok', publicUrl: 'http://127.0.0.1:3742', storage: { blobs: 0, bytes: 0, quotaBytes: 1e9 }, settings: { friendGrants: [], quotaGib: 10, transport: 'direct', directPort: 3742, startAtLogin: false } });
    window.__stub.handlers.pool_status = () => ({ pools: [], error: null });
  });
  await page.waitForFunction(() => document.querySelector('#drop-node-status')?.textContent && !document.querySelector('#drop-node-status').textContent.startsWith('Not available'));
  return page;
}
scenario('settings: section order, values, actions and sheets', async () => {
  const page = await settingsPage();
  assert.equal(await page.evaluate(() => document.querySelector('main > header').nextElementSibling.id), 'drop-settings', 'first section after the header');
  assert.equal(await page.locator('#settings-form #drop-settings').count(), 0, 'outside the node form');
  const section = page.locator('#drop-settings');
  assert.equal(await text(section.locator('.label')), 'Wildbloom Drop');
  assert.equal(await text(section.locator('h2')), 'Online copies');
  assert.equal(await text(section.locator('#drop-node-url')), 'https://storage.example');
  assert.equal(await text(section.locator('#drop-node-status')), 'Connected · 1.2 GB of 5 GB used');
  assert.equal(await text(section.locator('#drop-node-change')), 'Change…');
  assert.equal(await text(section.locator('#drop-device-npub')), NPUB_SHORT);
  assert.equal(await text(section.locator('#drop-approval-text')), `Approved by ${NPUB_SHORT} until ${new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'Europe/London' }).format(new Date((nowSeconds + 300 * 86400) * 1000))}`);
  assert.equal(await text(section.locator('#drop-renew')), 'Renew approval…');
  assert.equal(await text(section.locator('label.check').first()), 'Keep copies of everything in my Wildbloom folder');
  assert.equal(await text(section.locator('#drop-folder-hint')), '~/Wildbloom.');
  assert.match(await text(section.locator('#drop-recovery-text')), /^Saved \d+ \w+ 2026$/);
  assert.match(await text(section.locator('.drop-note')), /^Files are encrypted on this computer before they're copied\. This is new software and hasn't been independently audited yet\.$/);
  assert.equal(await section.locator('#drop-folder-show').isDisabled(), true);

  await section.locator('#drop-device-copy').click();
  assert.equal(await page.evaluate(() => window.__stub.clipboard), await page.evaluate(() => window.__stub.npub));
  await section.locator('#drop-folder').check();
  const folderConfirm = page.locator('dialog.confirm[open]');
  assert.equal(await text(folderConfirm.locator('h2')), 'Keep a readable copy of every file in ~/Wildbloom?');
  await folderConfirm.locator('button', { hasText: 'Cancel' }).click();
  // The change handler unticks the box once the dialog's promise settles.
  await page.waitForFunction(() => !document.querySelector('#drop-folder').checked, null, { timeout: 5000 }).catch(() => {});
  assert.equal(await section.locator('#drop-folder').isChecked(), false, 'Cancel leaves it off');
  assert.equal((await calls(page, 'set_watch_folder')).length, 0);
  await section.locator('#drop-folder').check();
  await folderConfirm.locator('button', { hasText: 'Turn on' }).click();
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'set_watch_folder'));
  assert.deepEqual((await calls(page, 'set_watch_folder')).at(-1).args, { enabled: true });
  await page.waitForFunction(() => !document.querySelector('#drop-folder-show').disabled);
  assert.equal(await text(section.locator('#drop-folder-hint')), '~/Wildbloom. Deleting a file here removes it on all your computers. Their copies go to the Trash.');
  await section.locator('#drop-folder-show').click();
  assert.equal((await calls(page, 'open_watch_folder')).length, 1);

  await section.locator('#drop-node-change').click();
  const confirm = page.locator('dialog.confirm[open]');
  assert.equal(await text(confirm.locator('h2')), 'Use a different online node?');
  assert.equal(await text(confirm.locator('p')), "Your files will be copied to the new node. Copies on storage.example aren't deleted.");
  assert.deepEqual(await confirm.locator('button').allTextContents(), ['Cancel', 'Continue']);
  await confirm.locator('button', { hasText: 'Cancel' }).click();
  assert.equal(await page.evaluate(() => document.activeElement.id), 'drop-node-change');
  await section.locator('#drop-node-change').click();
  await confirm.locator('button', { hasText: 'Continue' }).click();
  const sheet = page.locator('dialog.flow-sheet'); // closed dialogs are removed in the close handler, so detached means disposed
  assert.equal(await text(sheet.locator('h2')), 'Set up Wildbloom Drop');
  assert.equal(await sheet.locator('.eyebrow').count(), 0);
  assert.deepEqual(await sheet.locator('button').allTextContents(), ['Continue', 'Cancel'], 'no first-run extras in a sheet');
  await sheet.locator('input').fill('https://new.example');
  await sheet.locator('button', { hasText: 'Continue' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.flow-sheet h2')?.textContent === 'Approve this computer', null, { timeout: 4000 });
  assert.deepEqual((await calls(page, 'set_online_node')).at(-1).args, { url: 'https://new.example' });
  await sheet.locator('input').fill('bunker://relay.example/pair?secret=abc');
  await sheet.locator('button', { hasText: 'Ask my signer' }).click();
  await page.evaluate(() => { window.__stub.approval = { state: 'approved', byNpub: window.__stub.npub }; });
  await sheet.waitFor({ state: 'detached', timeout: 6000 });
  assert.equal(await page.evaluate(() => document.activeElement.id), 'drop-node-change');
  assert.equal((await calls(page, 'cancel_approval')).length, 0, 'a finished approval is never cancelled when the sheet closes');

  await section.locator('#drop-renew').click();
  await page.evaluate(() => { window.__stub.approval = { state: 'idle' }; });
  await sheet.locator('input').waitFor();
  assert.equal(await text(sheet.locator('h2')), 'Approve this computer again');
  await sheet.locator('input').fill('bunker://relay.example/pair?secret=abc');
  await sheet.locator('button', { hasText: 'Ask my signer' }).click();
  assert.deepEqual((await calls(page, 'renew_approval')).at(-1).args, { bunkerUrl: 'bunker://relay.example/pair?secret=abc' });
  await page.keyboard.press('Escape');
  await sheet.waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'cancel_approval')).length, 1, 'dismissing a waiting sheet cancels the approval');

  // The recovery key is shown only in the Drop window: the node window asks
  // Rust to open it there and never reads the key itself.
  await section.locator('#drop-recovery').click();
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'open_drop_flow'));
  assert.deepEqual((await calls(page, 'open_drop_flow')).at(-1).args, { flow: 'recovery' });
  assert.equal(await page.locator('dialog.flow-sheet').count(), 0);
  assert.equal((await calls(page, 'recovery_key_for_display')).length, 0);
  assert.equal((await calls(page, 'confirm_recovery_saved')).length, 0);
  await done(page);
});

scenario('drop window: the node window\'s "Save recovery key again" opens the recovery sheet here', async () => {
  const page = await drop('good');
  await ready(page);
  await page.evaluate(() => window.__stub.emit('drop://open-flow', { flow: 'recovery' }));
  const sheet = page.locator('dialog.flow-sheet');
  await sheet.locator('.key').waitFor();
  assert.equal(await sheet.locator('input[type="checkbox"]').count(), 0, 'the checkbox is not required again');
  await sheet.locator('button', { hasText: 'Done' }).click();
  await sheet.waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'confirm_recovery_saved')).length, 0);
  // A cancelled Rust save dialog leaves no notice.
  await page.evaluate(() => { window.__stub.saveCancelled = true; });
  await page.locator('li.row[data-id="f1"] [data-ctl="more"]').click();
  await menuAction(page, 'Save');
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'save_copy'));
  assert.equal(await text(page.locator('#notices')), '');
  await done(page);
});

scenario('settings: changing node warns that live shares end', async () => {
  const page = await settingsPage({}, '&status=shared');
  await page.locator('#drop-node-change').click();
  const confirm = page.locator('dialog.confirm[open]');
  assert.deepEqual(await confirm.locator('p').allTextContents(), [
    "Your files will be copied to the new node. Copies on storage.example aren't deleted.",
    "You're sharing 2 files. Their shared copies on storage.example are deleted now, so their links stop working.",
  ]);
  await confirm.locator('button', { hasText: 'Cancel' }).click();
  await done(page);
});

scenario('settings: not set up, unreachable, approval ending soon, events', async () => {
  let page = await settingsPage({}, '&status=no-online');
  await page.waitForFunction(() => document.querySelector('#drop-node-status').textContent === 'Not set up');
  assert.equal(await text(page.locator('#drop-node-change')), 'Add online node…');
  assert.equal(await page.locator('#drop-node-url').isHidden(), true);
  assert.equal(await page.locator('#drop-renew').isDisabled(), true);
  await page.locator('#drop-node-change').click();
  assert.equal(await page.locator('dialog.confirm').count(), 0, 'nothing to confirm when no node is set');
  await page.locator('dialog.flow-sheet h2').waitFor();
  await done(page);
  page = await open(`${base}/ui/index.html?state=good&status=unreachable,ends`, { width: 820, height: 900 });
  await page.evaluate(() => {
    window.__stub.handlers.node_status = () => { throw 'unavailable'; };
    window.__stub.handlers.pool_status = () => ({ pools: [], error: null });
  });
  await page.waitForFunction(() => document.querySelector('#drop-node-status').textContent.startsWith('Can'));
  assert.equal(await text(page.locator('#drop-node-status')), "Can't reach it right now");
  assert.equal(await page.locator('#drop-renew').evaluate((n) => n.classList.contains('emphasis')), true);
  await page.evaluate(() => { window.__stub.state.online.reachable = true; window.__stub.state.online.failedChecks = 0; window.__stub.flush(); });
  await page.waitForFunction(() => document.querySelector('#drop-node-status').textContent.startsWith('Connected'));
  await done(page);
});

scenario('contrast: field border tokens and the node window inputs (C1)', async () => {
  let page = await drop('empty', { scheme: 'dark' });
  await ready(page);
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--field-border').trim()), '#5d7262');
  await done(page);
  page = await drop('empty', { scheme: 'light' });
  await ready(page);
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--field-border').trim()), '#7d8a7e');
  await done(page);
  page = await drop('empty', { scheme: 'dark', contrast: 'more' });
  await ready(page);
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--field-border').trim()), await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--ink').trim()));
  await done(page);
  page = await settingsPage({ scheme: 'dark' });
  for (const selector of ['#pubkey', '#quota']) {
    assert.equal(await page.locator(selector).evaluate((n) => getComputedStyle(n).borderTopColor), 'rgb(93, 114, 98)', selector);
  }
  assert.equal(await page.locator('.field-with-suffix span').evaluate((n) => getComputedStyle(n).borderTopColor), 'rgb(93, 114, 98)');
  await done(page);
});

/* ---------- layout, axe, screenshots over every state ---------- */

const STATES = [
  'empty', 'list', 'all-states', 'good', 'many', 'no-online',
  'drag-hover', 'drag-folder', 'drag-big', 'notice-folder',
  'share-s1', 'share-s2', 'share-s3', 'share-s4', 'share-s5', 'share-s6', 'share-s7', 'share-s8', 'share-s9', 'share-s9b', 'share-s10', 'share-s11', 'share-s12', 'share-s13', 'share-s14', 'share-s15', 'share-s16', 'share-s17', 'share-s18',
  'confirm-remove', 'confirm-stop',
  'first-run-1', 'first-run-1-error', 'first-run-2', 'first-run-2-waiting', 'first-run-2-error', 'first-run-3', 'first-run-3-used', 'first-run-restore',
  'first-run-keychain&os=mac', 'first-run-keychain&os=windows', 'first-run-keychain&os=linux',
  'good&status=downloads', 'good&status=shared', 'good&status=node', 'good&status=keychain', 'good&status=expired', 'good&status=unreachable', 'good&status=full', 'good&status=ends', 'good&status=recovery', 'list&status=folder',
  'folder', 'folder&status=folder-unavailable', 'folder&status=folder-too-many', 'folder&os=windows', 'confirm-folder-on',
  'held', 'confirm-held', 'confirm-held&os=windows', 'confirm-held&os=linux&desktop=kde',
  'share-s5&os=windows', 'share-s5&os=linux&desktop=kde',
  'receive-idle', 'receive-r1', 'receive-r2', 'receive-r3', 'receive-r4', 'receive-r5', 'receive-r6', 'receive-r6b', 'receive-r6c', 'receive-r7', 'receive-r7b', 'receive-r7c',
  'receive-r8', 'receive-r8b', 'receive-r9', 'receive-r10', 'receive-r10b', 'receive-r11', 'receive-r12', 'receive-r12b',
  'receive-f-no_turn', 'receive-f-wrong_words', 'receive-f-unsupported', 'receive-f-no_relay', 'receive-f-verification',
  'receive-r4&os=windows', 'receive-r6&os=linux&desktop=kde',
];
const SIZES = [[400, 600], [340, 420], [760, 600]];
const SCHEMES = ['light', 'dark'];
const safe = (name) => name.replace(/[^a-z0-9]+/gi, '-');

async function harness(state, { width, height, scheme }) {
  const [name, ...rest] = state.split('&');
  const query = rest.join('&');
  const params = Object.fromEntries(new URLSearchParams(query));
  const page = await open(`${base}/tests/drop-harness.html?state=${name}${query ? `&${query}` : ''}`, { os: params.os || 'mac', desktop: params.desktop || '', width, height, scheme });
  await page.waitForSelector('html[data-harness="ready"]', { timeout: 8000 });
  await page.waitForTimeout(300);
  return page;
}

scenario('every state: no overflow, axe clean, screenshots (light and dark, three sizes)', async () => {
  const shots = process.env.WILDBLOOM_SCREENSHOT_DIR;
  const full = Boolean(shots) || process.env.DROP_UI_FULL === '1';
  if (shots) await mkdir(shots, { recursive: true });
  for (const state of STATES) {
    for (const scheme of SCHEMES) {
      for (const [width, height] of SIZES) {
        // Default run: axe in both schemes at 400x600 and a layout check at 340x420 in light.
        // WILDBLOOM_SCREENSHOT_DIR or DROP_UI_FULL=1 runs every size and scheme.
        const quick = (width === 400 && height === 600) || (scheme === 'light' && height === 420);
        if (!full && !quick) continue;
        const page = await harness(state, { width, height, scheme });
        const overflow = await page.evaluate(() => ({ wide: document.documentElement.scrollWidth > innerWidth, tall: document.documentElement.scrollHeight > innerHeight + 1 }));
        assert.equal(overflow.wide, false, `${state} ${scheme} ${width}x${height}: horizontal scroll`);
        assert.equal(overflow.tall, false, `${state} ${scheme} ${width}x${height}: the window itself scrolls (only the list or a sheet may)`);
        const sheetFit = await page.evaluate(() => { const body = document.querySelector('dialog.receive[open] .sheet-body'); return !body || body.scrollWidth <= body.clientWidth; });
        assert.equal(sheetFit, true, `${state} ${scheme} ${width}x${height}: the sheet scrolls sideways`);
        if (width === 400 || full) await axe(page, `${state} ${scheme} ${width}x${height}`);
        if (shots) await page.screenshot({ path: path.join(shots, `${safe(state)}-${scheme}-${width}x${height}.png`) });
        await page.context().close();
      }
    }
  }
  if (shots) {
    // The node window is dark only.
    const page = await settingsPage({ scheme: 'dark', width: 820, height: 1000 });
    await page.locator('#drop-settings').screenshot({ path: path.join(shots, 'settings-820.png') });
    await page.setViewportSize({ width: 420, height: 900 });
    await page.locator('#drop-settings').screenshot({ path: path.join(shots, 'settings-420.png') });
    await page.locator('#drop-node-change').click();
    await page.locator('dialog.confirm button', { hasText: 'Continue' }).click();
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(shots, 'settings-sheet-420.png') });
    await axe(page, 'settings sheet');
    await page.context().close();
  }
});

scenario('settings page: axe on the new section and forced colours', async () => {
  const page = await settingsPage({ scheme: 'dark' });
  const result = await new AxeBuilder({ page }).include('#drop-settings').withTags(AXE_TAGS).analyze();
  assert.deepEqual(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })), []);
  for (const width of [820, 420, 320]) {
    await page.setViewportSize({ width, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `overflow at ${width}`);
  }
  await done(page);
});

scenario('layout: no zone band with files; wide layout uses columns', async () => {
  let page = await drop('list', { width: 340, height: 420 });
  await ready(page);
  assert.equal(await page.locator('#zone').evaluate((n) => getComputedStyle(n).display), 'none');
  assert.equal(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight + 1), true);
  await done(page);
  page = await drop('list', { width: 760, height: 600 });
  await ready(page);
  const rects = await page.evaluate(() => { const li = document.querySelector('li.row[data-id="f1"]'); return [li.querySelector('h3'), li.querySelector('.row-status'), li.querySelector('[data-ctl="share"]')].map((n) => n.getBoundingClientRect().top); });
  assert.ok(Math.abs(rects[0] - rects[1]) < 12 && Math.abs(rects[1] - rects[2]) < 16, `columns share a line ${rects}`);
  await done(page);
});

scenario('forced colours and high contrast render without errors', async () => {
  for (const options of [{ forced: true }, { contrast: 'more', scheme: 'dark' }]) {
    const page = await drop('all-states', options);
    await ready(page);
    await page.evaluate(() => window.__stub.emit('tauri://drag-enter', { paths: ['/a'] }));
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await done(page);
  }
});

/* ---------- the calmer Drop window (design-drop-declutter.md, section 12) ---------- */

const box = (page, selector) => page.locator(selector).first().boundingBox();
const near = (a, b, tolerance, message) => assert.ok(Math.abs(a - b) <= tolerance, `${message}: ${a} vs ${b}`);

scenario('declutter 2 and 3: no zone band, Add files in the footer, header plus footer stay slim', async () => {
  for (const scheme of ['light', 'dark']) {
    for (const [width, height] of [[400, 600], [340, 420]]) {
      const page = await drop('list', { scheme, width, height });
      await ready(page);
      assert.equal(await page.locator('#zone').evaluate((n) => getComputedStyle(n).display), 'none', `${scheme} ${width}`);
      assert.equal(await page.locator('#drop-footer #add-files').count(), 1);
      assert.equal(await page.locator('#footer-online').count(), 0);
      const header = await box(page, '#drop-header');
      const footer = await box(page, '#drop-footer');
      assert.ok(header.height + footer.height <= 110, `${scheme} ${width}x${height}: header ${header.height} plus footer ${footer.height}`);
      await done(page);
    }
  }
});

scenario('declutter 4: healthy rows are quiet, with a spoken sentence', async () => {
  const page = await drop('good');
  await ready(page);
  assert.equal(await page.locator('li[data-state="two_copies"]').count(), 5);
  for (const li of await page.locator('li[data-state="two_copies"]').all()) {
    assert.equal(await li.locator('.row-status .lead').count(), 0);
    assert.equal(await li.locator('.row-status .icon-slot').count(), 0);
  }
  const f1 = page.locator('li[data-id="f1"]');
  assert.equal(await visual(f1.locator('.row-visual')), `2.4 MB · Today ${clockTime(nowSeconds - 3600)}`);
  assert.equal(await text(f1.locator('.row-status .sr-only')), `2.4 MB, added ${clockTime(nowSeconds - 3600)} today.`);
  await done(page);
});

scenario('declutter 5 to 8: Share shows on hover and focus, never moves anything, stays in the menu', async () => {
  let page = await drop('good');
  await ready(page);
  const share = page.locator('li[data-id="f1"] [data-ctl="share"]');
  const more = page.locator('li[data-id="f1"] [data-ctl="more"]');
  const opacity = () => share.evaluate((n) => getComputedStyle(n).opacity);
  await page.mouse.move(2, 2);
  await page.waitForTimeout(250);
  assert.equal(await opacity(), '0', 'hidden before hover');
  const before = await more.boundingBox();
  const shareBefore = await share.boundingBox();
  await page.hover('li[data-id="f1"] h3');
  await page.waitForTimeout(250);
  assert.equal(await opacity(), '1', 'shown on hover');
  const after = await more.boundingBox();
  for (const key of ['x', 'y', 'width', 'height']) near(before[key], after[key], 0.5, `the more button ${key}`);
  const shareAfter = await share.boundingBox();
  for (const key of ['x', 'y', 'width', 'height']) near(shareBefore[key], shareAfter[key], 0.5, `Share ${key}`);
  assert.equal(await page.locator('li[data-id="f1"] [data-ctl="share"]').count(), 1);
  await page.mouse.move(2, 2);
  await page.waitForTimeout(250);
  await page.evaluate(() => document.body.focus());
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), 'Share holiday.jpg');
  await page.waitForTimeout(250);
  assert.equal(await opacity(), '1', 'shown on keyboard focus');
  assert.equal(await share.evaluate((n) => getComputedStyle(n).outlineWidth), '3px');
  assert.notEqual(await share.evaluate((n) => getComputedStyle(n).outlineStyle), 'none');
  await more.click();
  assert.equal(await page.evaluate(() => window.__stub.lastMenu.items[0].text), 'Share…');
  await done(page);
  // Touch: Share is always there. Chrome headless only reports a coarse pointer for some touch setups.
  page = await drop('good', { touch: true });
  await ready(page);
  if (await page.evaluate(() => matchMedia('(any-pointer: coarse)').matches)) {
    assert.equal(await page.locator('li[data-id="f1"] [data-ctl="share"]').evaluate((n) => getComputedStyle(n).opacity), '1', 'visible on touch without hover');
  } else console.log('     (touch reveal not verified: this browser reports no coarse pointer)');
  await done(page);
});

scenario('declutter 9 and 10: no online node, and an unreachable one, say it once and fit at 340', async () => {
  let page = await drop('no-online', { width: 340, height: 420 });
  await ready(page);
  assert.equal(await page.locator('[data-ctl="share"]').count(), 0);
  assert.equal(await visual(page.locator('li[data-id="f1"] .row-visual')), `2.4 MB · Today ${clockTime(nowSeconds - 3600)}`);
  assert.equal(await text(page.locator('#status-action')), 'Add online node');
  assert.ok((await box(page, '#status-action')).height <= 34, 'Add online node is one line');
  await done(page);
  page = await drop('good', { width: 340, height: 420 }, '&status=unreachable');
  await ready(page);
  assert.equal(await text(page.locator('#status-text')), "Can't reach your online node. Files will copy when it's back.");
  assert.ok((await box(page, '#status-action')).height <= 34, 'Try now is one line');
  await done(page);
});

scenario('declutter 11: the empty window is one calm zone', async () => {
  for (const [width, height] of [[400, 600], [340, 420]]) {
    const page = await drop('empty', { width, height });
    await ready(page);
    assert.equal(await page.locator('#status-line').count(), 1);
    assert.equal(await text(page.locator('#status-line')), '');
    assert.equal(await page.locator('#status-line').getAttribute('role'), 'status');
    assert.ok((await box(page, '#drop-header')).height <= 8, 'the header collapses');
    const zone = page.locator('#zone.empty');
    assert.match(await text(zone), /Drop files here/);
    assert.match(await text(zone), /Turn on your Wildbloom folder/);
    assert.equal(await zone.getByRole('button', { name: 'Add files…' }).count(), 0);
    const footer = page.locator('#drop-footer');
    assert.equal(await footer.getByRole('button', { name: 'Add files…' }).count(), 1);
    assert.equal(await footer.getByRole('button', { name: 'Settings' }).count(), 1);
    assert.equal(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight + 1), true, `no scroll at ${width}x${height}`);
    await done(page);
  }
});

scenario('declutter 12: the status line is honest', async () => {
  const page = await drop('good');
  await ready(page);
  assert.equal(await text(page.locator('#status-text')), 'All 5 files have 2 copies.');
  await page.evaluate(() => window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f1'), state: 'missing_local' }));
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('4 of 5'));
  assert.equal(await text(page.locator('#status-text')), '4 of 5 files have 2 copies.');
  assert.equal(await page.locator('#status-action').isHidden(), true);
  await page.evaluate(() => window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f1'), state: 'two_copies' }));
  await page.waitForFunction(() => document.querySelector('#status-text').textContent.startsWith('All'));
  await done(page);
});

scenario('declutter 13: wide rows share their columns', async () => {
  for (const [state, extra] of [['folder', ''], ['good', '&status=shared']]) {
    const page = await drop(state, { width: 760, height: 600 }, extra);
    await ready(page);
    const edges = await page.evaluate(() => [...document.querySelectorAll('li.row')].map((li) => ({ left: li.querySelector('.row-status').getBoundingClientRect().left, right: li.querySelector('[data-ctl="more"]')?.getBoundingClientRect().right ?? null })));
    for (const edge of edges) near(edge.left, edges[0].left, 1, `${state} meta left`);
    const rights = edges.filter((edge) => edge.right !== null);
    for (const edge of rights) near(edge.right, rights[0].right, 1, `${state} more right`);
    if (state === 'folder') {
      const lines = await page.evaluate(() => { const h3 = [...document.querySelectorAll('li.row h3')].find((n) => n.getAttribute('title') === 'notes-with-a-very-long-name.txt'); return Math.round(h3.getBoundingClientRect().height / parseFloat(getComputedStyle(h3).lineHeight)); });
      assert.ok(lines <= 2, `long name takes ${lines} lines`);
    }
    await done(page);
  }
});

scenario('declutter 14 and 15: downloaded rows and their menus', async () => {
  const page = await drop('good', {}, '&status=downloads');
  await ready(page);
  const until = clockTime(nowSeconds + 20 * 3600);
  const cases = {
    f40: [`Downloaded · kept until ${until} tomorrow`, `Downloaded at ${clockTime(nowSeconds - 1080)} today. Shared copy kept until ${until} tomorrow.`, ['Share Again…', 'Stop Sharing…', 'Save a Copy…', 'Remove…']],
    f41: [`Downloaded · ${clockTime(nowSeconds - 1080)} today`, `Downloaded at ${clockTime(nowSeconds - 1080)} today. Shared copy deleted.`, ['Share…', 'Save a Copy…', 'Remove…']],
    f42: ['Downloaded · deleting the shared copy when online', `Downloaded at ${clockTime(nowSeconds - 1080)} today. The shared copy will be deleted when your online node is back.`, ['Save a Copy…']],
  };
  assert.equal(clockTime(nowSeconds - 1080), '10:42');
  for (const [id, [visualText, spoken, menu]] of Object.entries(cases)) {
    const li = page.locator(`li.row[data-id="${id}"]`);
    assert.equal(await text(li.locator('.row-visual')), visualText, id);
    assert.equal(await text(li.locator('.row-status .sr-only')), spoken, id);
    await page.evaluate(() => { window.__stub.lastMenu = null; });
    await li.locator('[data-ctl="more"]').click();
    assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), menu, `${id} menu`);
  }
  assert.equal(await page.locator('li.row[data-id="f40"] .icon-slot').evaluate((n) => n.className.includes('tone-success')), true, 'a download is a success tone');
  await done(page);
  const shared = await drop('good', {}, '&status=shared');
  await ready(shared);
  assert.equal(await text(shared.locator('li.row[data-id="f12"] .row-visual')), `Shared · until ${until} tomorrow`);
  assert.equal(await shared.locator('li.row[data-id="f12"] .icon-slot svg').count(), 1, 'one icon, not two');
  await done(shared);
});

scenario('declutter 16: a download that arrives with no sheet open is announced', async () => {
  const page = await drop('good');
  await ready(page);
  await page.evaluate(() => {
    window.__said = [];
    new MutationObserver(() => { const value = document.getElementById('drop-announcer').textContent; if (value) window.__said.push(value); }).observe(document.getElementById('drop-announcer'), { childList: true, characterData: true, subtree: true });
  });
  const now = nowSeconds;
  await page.evaluate((at) => window.__stub.pushRow({ ...window.__stub.files.find((row) => row.id === 'f1'), state: 'sharing_ended', sharingEnded: at, downloadedAt: at }), now);
  await page.waitForFunction(() => window.__said.includes('holiday.jpg was downloaded.'), null, { timeout: 2500 });
  await done(page);
});

const HEADING_STATES = ['share-s3', 'share-s5', 'share-s7', 'share-s14', 'share-s15', 'share-s16', 'share-s17', 'share-s18'];
scenario('declutter 17: the sheet heading is constant and the status follows it', async () => {
  for (const state of HEADING_STATES) {
    const page = await harness(state, { width: 400, height: 600, scheme: 'light' });
    assert.equal(await text(page.locator('dialog h2')), 'Share holiday.jpg', state);
    assert.equal(await page.evaluate(() => document.querySelector('dialog h2').nextElementSibling.classList.contains('share-slot')), true, `${state}: the status slot follows the heading`);
    await page.context().close();
  }
});

scenario('declutter 18 and 19: the check state fits at 340x420, finished steps shrink, the countdown is inline', async () => {
  let page = await harness('share-s5', { width: 340, height: 420, scheme: 'light' });
  const match = page.locator('dialog button', { hasText: 'They match, send file' });
  const rect = await match.boundingBox();
  assert.ok(rect.y >= 0 && rect.y + rect.height <= 420, `the primary button is on screen (${rect.y}, ${rect.height})`);
  assert.equal(await page.locator('dialog .share-step').count(), 3);
  for (const index of [0, 1]) {
    const step = page.locator('dialog .share-step').nth(index);
    assert.equal(await step.locator('.step-body').count(), 0);
    assert.equal(await step.locator('.step-title .sr-only').textContent(), ', done');
  }
  await page.context().close();
  page = await harness('share-s3', { width: 400, height: 600, scheme: 'light' });
  const time = await box(page, '[data-time]');
  const status = await box(page, '.share-status .share-text');
  const line = await box(page, '.share-status');
  near(time.y, status.y, 4, 'the countdown top');
  near(time.x + time.width, line.x + line.width, 1, 'the countdown sits on the right edge');
  await page.context().close();
});

scenario('declutter 20 and 21: sent and downloaded copy', async () => {
  const body = (page) => text(page.locator('dialog .share-body'));
  const status = (page) => text(page.locator('dialog .share-status'));
  const buttons = (page) => page.locator('dialog.sheet .dialog-actions button').allTextContents();
  const keep = `Wildbloom deletes the shared copy at ${clockTime(nowSeconds + 86400)} tomorrow, or sooner if you stop sharing. This computer needs to be on to delete it.`;
  const cases = {
    'share-s14': ['Sent. Waiting for them to download it.', `Wildbloom deletes the shared copy once they've downloaded it, or by ${clockTime(nowSeconds + 86400)} tomorrow. This computer needs to be on to delete it.`, ['Stop sharing…', 'Done']],
    'share-s15': ['Sent. Waiting for them to download it.', keep, ['Stop sharing…', 'Done']],
    'share-s7': ['They can download holiday.jpg now.', keep, ['Stop sharing…', 'Done']],
    'share-s16': ['Downloaded at 11:00.', 'The shared copy is deleted, so the link no longer works.', ['Done']],
    'share-s17': ['Downloaded at 11:00.', 'Wildbloom deletes the shared copy when it can reach your online node. This computer needs to be on to delete it.', ['Done']],
    'share-s18': ['Downloaded at 11:00.', keep, ['Stop sharing…', 'Done']],
  };
  for (const [state, [statusText, bodyText, buttonTexts]] of Object.entries(cases)) {
    const page = await harness(state, { width: 400, height: 600, scheme: 'light' });
    assert.match(await status(page), new RegExp(`^${statusText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`), state);
    assert.equal(await body(page), bodyText, state);
    assert.deepEqual(await buttons(page), buttonTexts, state);
    assert.doesNotMatch(await text(page.locator('dialog')), /Stopping can't take back/, state);
    if (!state.endsWith('s7') || true) assert.equal(await page.locator('dialog [data-time]').count(), 0, `${state} has no countdown`);
    await page.context().close();
  }
});

scenario('declutter 22 and 23: no layout shift when the download arrives, and closing sends no cancel', async () => {
  // Whatever the font: wide sans metrics wrap the text differently, and the box must still not change.
  const variants = [];
  for (const os of ['mac', 'windows']) for (const font of [undefined, 'wide']) for (const width of [340, 400, 760]) variants.push({ os, font, width });
  for (const { os, font, width } of variants) {
    const page = await drop('good', { os, font, width, height: 600 });
    await ready(page);
    await openShare(page, { state: 'sent', deleteAt: nowSeconds + 86400, awaitingDownload: true, afterDownload: 'delete' });
    await page.waitForTimeout(400); // the sheet's own entrance animation has to finish before measuring
    const slot = page.locator('dialog .share-slot');
    await slot.evaluate((n) => { n.dataset.same = 'yes'; });
    await page.locator('dialog [data-key="stop"]').focus();
    const before = await box(page, 'dialog [data-key="done"]');
    await emitShare(page, { state: 'downloaded', downloadedAt: nowSeconds, copy: 'deleted' });
    const after = await box(page, 'dialog [data-key="done"]');
    for (const key of ['x', 'y', 'width', 'height']) near(before[key], after[key], 0.5, `${os} ${font || 'system'} ${width} Done ${key}`);
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('data-key')), 'done', 'focus moves to Done');
    assert.equal(await slot.getAttribute('data-same'), 'yes', 'the status slot is updated in place');
    assert.equal(await slot.getAttribute('role'), 'status');
    await page.keyboard.press('Escape');
    await page.locator('dialog.sheet').waitFor({ state: 'detached' });
    assert.equal((await calls(page, 'share_cancel')).length, 0, `${os} Escape from downloaded sends no cancel`);
    await done(page);
  }
  const page = await harness('share-s16', { width: 400, height: 600, scheme: 'light' });
  await page.locator('dialog button', { hasText: 'Done' }).click();
  await page.locator('dialog.sheet').waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'share_cancel')).length, 0);
  await page.context().close();
});

scenario('declutter 24 to 26: sharing settings', async () => {
  const page = await settingsPage({ scheme: 'dark' });
  const titles = await page.locator('#drop-settings .drop-setting-title').allTextContents();
  assert.deepEqual(titles, ['Online node', 'This computer', 'Wildbloom folder', 'Sharing', 'Receiving files', 'Recovery key']);
  const group = page.getByRole('group', { name: "When they've downloaded it" });
  assert.equal(await group.count(), 1);
  assert.equal(await group.getByRole('radio', { name: 'Delete the shared copy' }).isChecked(), true);
  assert.equal(await group.getByRole('radio', { name: 'Keep it until it expires' }).isChecked(), false);
  const select = page.getByRole('combobox', { name: 'Shared copies expire after' });
  assert.equal(await select.inputValue(), '86400');
  assert.deepEqual(await select.locator('option').allTextContents(), ['1 hour', '24 hours', '7 days']);
  assert.equal(await page.locator('#settings-form #drop-settings').count(), 0);
  assert.match(await text(page.locator('#drop-sharing-hint')), /^Wildbloom can only tell they've downloaded a file within 10 minutes of making its link\. If it can't tell, the shared copy stays until it expires\. Changes apply to files you share from now on\.$/);
  assert.equal(await page.locator('#drop-after-download').getAttribute('aria-describedby'), 'drop-sharing-hint');
  assert.equal(await select.getAttribute('aria-describedby'), 'drop-sharing-hint');
  await group.getByRole('radio', { name: 'Keep it until it expires' }).check();
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'set_sharing'));
  assert.deepEqual((await calls(page, 'set_sharing')).map((c) => c.args), [{ afterDownload: 'keep', expirySeconds: 86400 }]);
  await select.selectOption('604800');
  await page.waitForFunction(() => window.__stub.calls.filter((c) => c.command === 'set_sharing').length === 2);
  assert.deepEqual((await calls(page, 'set_sharing')).at(-1).args, { afterDownload: 'keep', expirySeconds: 604800 });
  await page.evaluate(() => { window.__stub.handlers.set_sharing = () => { throw { code: 'unknown' }; }; });
  await select.selectOption('3600');
  await page.locator('#drop-settings-error:not([hidden])').waitFor();
  assert.equal(await text(page.locator('#drop-settings-error')), "Couldn't change the sharing settings.");
  assert.equal(await select.inputValue(), '604800', 'the control goes back');
  const result = await new AxeBuilder({ page }).include('#drop-settings').withTags(AXE_TAGS).analyze();
  assert.deepEqual(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })), []);
  for (const width of [820, 420, 320]) {
    await page.setViewportSize({ width, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `overflow at ${width}`);
  }
  await done(page);
});

scenario('declutter 27: tab order through the list is status, rows, Add files, Settings', async () => {
  const page = await drop('list');
  await ready(page);
  await page.evaluate(() => document.body.focus());
  const stops = [];
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press('Tab');
    stops.push(await page.evaluate(() => ({ id: document.activeElement.id, ctl: document.activeElement.getAttribute('data-ctl'), visible: document.activeElement.getClientRects().length > 0 })));
  }
  assert.equal(stops[0].id, 'status-action');
  assert.equal(stops.at(-3).id, 'add-files');
  assert.equal(stops.at(-2).id, 'add-more');
  assert.equal(stops.at(-1).id, 'footer-settings');
  assert.ok(stops.slice(1, -3).every((stop) => stop.ctl), 'only row controls between');
  assert.ok(stops.every((stop) => stop.visible), 'no stop on a hidden element');
  await done(page);
});

scenario('declutter 29: Share is visible on hover under forced colours', async () => {
  const page = await drop('good', { forced: true });
  await ready(page);
  await page.hover('li[data-id="f1"] h3');
  await page.waitForTimeout(250);
  assert.equal(await page.locator('li[data-id="f1"] [data-ctl="share"]').evaluate((n) => getComputedStyle(n).opacity), '1');
  await done(page);
});

/* ---------- receive a file ---------- */

const RLINK = 'https://wildbloom.example/send/#v1.abc123';
const OFFER = { name: 'holiday.mp4', size: 120_000_000, type: 'video/mp4' };
const KEPT = { state: 'kept', ...OFFER, id: 'k1', path: '~/Downloads/Wildbloom Received/holiday.mp4', folder: '~/Downloads/Wildbloom Received', canAdd: true };
async function openReceive(page) {
  await page.locator('#add-more').click();
  await page.waitForFunction(() => window.__stub.lastMenu);
  await page.evaluate(() => { const menu = window.__stub.lastMenu; window.__stub.lastMenu = null; menu.items.find((item) => item.text.startsWith('Receive')).action(); });
  await page.locator('dialog.receive[open]').waitFor();
  await page.waitForTimeout(60);
}
const setReceive = (page, payload) => page.evaluate((next) => window.__stub.setReceive(next), payload);
const sheetText = (page) => visual(page.locator('dialog.receive[open]'));
const statusOf = (page) => visual(page.locator('dialog.receive[open] .share-slot'));
const buttonsOf = (page) => page.locator('dialog.receive[open] .share-bottom button').allTextContents();

scenario('receive: one small menu beside Add files, nothing new in the list', async () => {
  let page = await drop('list');
  await ready(page);
  assert.equal(await page.locator('#add-more').getAttribute('aria-label'), 'More ways to add files');
  assert.equal(await page.locator('#add-more').getAttribute('aria-haspopup'), 'menu');
  assert.doesNotMatch(await text(page.locator('#drop-main')), /Receive/, 'no receive text in the window until it is used');
  assert.doesNotMatch(await text(page.locator('#drop-footer')), /Receive/);
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'receive_state'));
  assert.equal((await calls(page, 'receive_state')).length, 1, 'start-up asks Rust whether a receive is running');
  assert.equal((await calls(page, 'receive_start')).length, 0, 'and starts nothing');
  assert.equal(await page.locator('dialog').count(), 0);
  await page.locator('#add-more').click();
  await page.waitForFunction(() => window.__stub.lastMenu);
  assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), ['Add Files…', 'Receive a File…']);
  await page.evaluate(() => window.__stub.lastMenu.items[0].action());
  assert.equal((await calls(page, 'pick_files')).length, 1, 'the menu still adds files');
  await done(page);
  page = await drop('empty', { os: 'windows' });
  await ready(page);
  await page.locator('#add-more').click();
  await page.waitForFunction(() => window.__stub.lastMenu);
  assert.deepEqual(await page.evaluate(() => window.__stub.lastMenu.items.map((item) => item.text)), ['Add files…', 'Receive a file…']);
  await done(page);
});

scenario('receive: the whole happy path, answers sent once, nothing about time or rate', async () => {
  const page = await drop('list');
  await ready(page);
  await openReceive(page);
  const sheet = page.locator('dialog.receive[open]');
  assert.equal(await text(sheet.locator('h2')), 'Receive a file');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Receive a file', 'focus starts on the heading');
  assert.equal((await calls(page, 'receive_start')).length, 1);
  assert.equal(await statusOf(page), 'Getting a link ready…');
  assert.deepEqual(await buttonsOf(page), ['Cancel']);

  const expiresAt = nowSeconds + 581;
  await setReceive(page, { state: 'waiting', link: RLINK, words: WORDS, expiresAt });
  assert.equal(await statusOf(page), 'Send the link, say the words another way. 9:41 left');
  assert.equal(await sheet.locator('input[readonly]').inputValue(), RLINK);
  assert.equal(await sheet.locator('ol.words').getAttribute('aria-label'), 'Words to read out: orbit, lemon, candle, frost');
  assert.deepEqual(await sheet.locator('ol.words li').allTextContents(), ['orbit', 'lemon', 'candle', 'frost']);
  assert.match(await sheetText(page), /Say these words another way, like a call or a message/);
  assert.match(await sheetText(page), /Don't send the words with the link\. Anyone with both could send you a file\./);
  assert.match(await sheetText(page), /They can send one file, up to 250 MB\./);
  await sheet.locator('[data-key="copy-link"]').click();
  assert.equal(await page.evaluate(() => window.__stub.clipboard), RLINK);
  await sheet.locator('[data-key="copy-words"]').click();
  assert.equal(await page.evaluate(() => window.__stub.clipboard), 'orbit lemon candle frost');

  await setReceive(page, { state: 'opened', link: RLINK, words: WORDS, expiresAt });
  assert.equal(await statusOf(page), 'Someone opened your link. 9:41 left');
  await setReceive(page, { state: 'check', link: RLINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt });
  assert.equal(await statusOf(page), 'Do these 3 words match theirs? 9:41 left');
  assert.equal(await sheet.locator('ol.words').getAttribute('aria-label'), 'Check words to read out: apple, river, stone');
  assert.deepEqual(await buttonsOf(page), ["They don't match", 'They match', 'Cancel'], 'macOS order: primary on the right');
  await sheet.getByRole('button', { name: 'They match', exact: true }).click();
  assert.deepEqual((await calls(page, 'receive_verify')).map((c) => c.args), [{ matches: true }]);
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('Waiting for them to choose a file.'));
  assert.deepEqual(await buttonsOf(page), ['Cancel']);

  // The real extension has a line of its own, so a long or odd name cannot hide what kind of file it is.
  for (const [name, ext] of [
    ['invoice.pdf.exe', 'Ends in .exe'],
    [`Holiday photos ${'and more '.repeat(20)}.pdf.app`, 'Ends in .app'],
    ['README', 'No file extension'],
    ['.profile', 'No file extension'],
  ]) {
    await setReceive(page, { state: 'consent', ...OFFER, name });
    assert.equal(await visual(sheet.locator('.receive-file .receive-ext')), ext, name);
  }
  await setReceive(page, { state: 'consent', ...OFFER });
  assert.equal(await statusOf(page), 'They want to send you holiday.mp4 (120 MB).');
  assert.match(await visual(sheet.locator('.receive-file')), /^holiday\.mp4 Ends in \.mp4 120 MB · video\/mp4$/);
  assert.match(await sheetText(page), /Nothing has been sent yet\. Only accept a file you expect\./);
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Receive a file', 'focus is not on Accept');
  assert.deepEqual(await buttonsOf(page), ['Decline', 'Accept']);
  await sheet.getByRole('button', { name: 'Accept', exact: true }).click();
  assert.deepEqual((await calls(page, 'receive_consent')).map((c) => c.args), [{ accept: true }]);
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('Connecting'));
  assert.equal(await statusOf(page), 'Connecting…');
  assert.match(await sheetText(page), /Your address is hidden\./);
  assert.match(await sheetText(page), /You can close this window\. Drop carries on\./);
  assert.deepEqual(await buttonsOf(page), ['Stop']);

  await setReceive(page, { state: 'receiving', ...OFFER, hidden: true, acknowledged: 54_000_000, total: 120_000_400 });
  assert.equal(await statusOf(page), 'Receiving…');
  assert.equal(await visual(sheet.locator('.receive-progress')), 'holiday.mp4 44% of 120 MB');
  const bar = sheet.locator('progress');
  assert.equal(await bar.evaluate((n) => n.value), 44);
  assert.equal(await bar.getAttribute('aria-label'), 'Receiving holiday.mp4');
  await bar.evaluate((n) => { n.dataset.same = 'yes'; });
  await setReceive(page, { state: 'receiving', ...OFFER, hidden: true, acknowledged: 90_000_300, total: 120_000_400 });
  assert.equal(await bar.getAttribute('data-same'), 'yes', 'the bar updates in place');
  assert.equal(await bar.evaluate((n) => n.value), 75);
  await setReceive(page, { state: 'receiving', ...OFFER, acknowledged: 120_000_400, total: 120_000_400 });
  assert.equal(await bar.evaluate((n) => n.value), 99, 'it never says 100% before the file is checked');
  assert.doesNotMatch(await sheetText(page), /\/s\b|per second|left|remaining|minute|ETA/i, 'no time or rate while receiving');
  await setReceive(page, { state: 'receiving', ...OFFER, acknowledged: 60_000_000, total: 120_000_400, reconnecting: true });
  assert.equal(await statusOf(page), 'Reconnecting…');
  assert.equal(await sheet.locator('progress').evaluate((n) => n.value), 49);

  await setReceive(page, { state: 'verifying', ...OFFER });
  assert.equal(await statusOf(page), 'Checking the file…');
  assert.deepEqual(await buttonsOf(page), ['Stop']);

  await setReceive(page, KEPT);
  assert.equal(await statusOf(page), 'Received holiday.mp4.');
  assert.match(await sheetText(page), /It's in ~\/Downloads\/Wildbloom Received\/holiday\.mp4\. Wildbloom isn't keeping copies of it yet\./);
  assert.deepEqual(await buttonsOf(page), ['Show in Finder', 'Add to Wildbloom', 'Done']);
  await sheet.getByRole('button', { name: 'Show in Finder' }).click();
  assert.deepEqual((await calls(page, 'receive_reveal')).map((c) => c.args), [{ id: 'k1' }]);
  await sheet.getByRole('button', { name: 'Add to Wildbloom' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('Added'));
  assert.deepEqual((await calls(page, 'receive_add_to_wildbloom')).map((c) => c.args), [{ id: 'k1' }]);
  assert.equal(await statusOf(page), 'Added holiday.mp4 to Wildbloom.');
  assert.match(await sheetText(page), /It's in ~\/Wildbloom, and Wildbloom keeps 2 copies of it now\./);
  assert.deepEqual(await buttonsOf(page), ['Show in Finder', 'Done']);
  await sheet.getByRole('button', { name: 'Done' }).click();
  await sheet.waitFor({ state: 'detached' });
  assert.equal(await page.evaluate(() => document.activeElement.id), 'add-more');
  assert.equal((await calls(page, 'receive_cancel')).length, 0, 'nothing was cancelled');
  assert.equal((await calls(page, 'receive_start')).length, 1, 'one receive');
  await done(page);
});

scenario('receive: platform wording for the kept file and the button order', async () => {
  for (const [os, desktop, reveal] of [['windows', '', 'Show in Explorer'], ['linux', 'gnome', 'Show in Folder']]) {
    const page = await drop('list', { os, desktop });
    await ready(page);
    await openReceive(page);
    await setReceive(page, { state: 'check', link: RLINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt: nowSeconds + 500 });
    const expected = os === 'windows' ? ['They match', "They don't match", 'Cancel'] : ["They don't match", 'They match', 'Cancel'];
    assert.deepEqual(await buttonsOf(page), expected, `${os} button order`);
    await setReceive(page, KEPT);
    assert.ok((await buttonsOf(page)).includes(reveal), `${os}: ${reveal}`);
    await done(page);
  }
});

scenario('receive: closing the sheet never cancels, and reopening shows where it is', async () => {
  const page = await drop('list');
  await ready(page);
  await openReceive(page);
  await setReceive(page, { state: 'waiting', link: RLINK, words: WORDS, expiresAt: nowSeconds + 581 });
  await page.keyboard.press('Escape');
  await page.locator('dialog.receive').waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'receive_cancel')).length, 0, 'Escape does not cancel');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'add-more');
  await openReceive(page);
  assert.equal(await statusOf(page), 'Send the link, say the words another way. 9:41 left');
  assert.equal((await calls(page, 'receive_start')).length, 1, 'a running receive is shown, not restarted');
  await setReceive(page, { state: 'receiving', ...OFFER, acknowledged: 1000, total: 120_000_400 });
  await page.keyboard.press('Escape');
  await page.locator('dialog.receive').waitFor({ state: 'detached' });
  assert.equal((await calls(page, 'receive_cancel')).length, 0);
  await openReceive(page);
  assert.equal(await statusOf(page), 'Receiving…');
  await page.getByRole('button', { name: 'Stop' }).click();
  assert.equal((await calls(page, 'receive_cancel')).length, 1, 'Stop cancels');
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.startsWith('Stopped.'));
  assert.equal(await statusOf(page), 'Stopped. Nothing was kept.');
  assert.deepEqual(await buttonsOf(page), ['Close', 'Start again']);
  await page.getByRole('button', { name: 'Close' }).click();
  await page.locator('dialog.receive').waitFor({ state: 'detached' });
  await openReceive(page);
  assert.equal((await calls(page, 'receive_start')).length, 2, 'after the finished one is closed, the entry starts a new receive');
  assert.equal(await statusOf(page), 'Getting a link ready…');
  await done(page);
});

scenario('receive: a receive that is running comes back with the window, and a question reopens the sheet', async () => {
  let page = await harness('receive-r8', { width: 400, height: 600, scheme: 'light' });
  assert.equal(await page.locator('dialog.receive[open]').count(), 1, 'the sheet is back');
  assert.equal(await statusOf(page), 'Receiving…');
  assert.equal((await calls(page, 'receive_start')).length, 0);
  await done(page);

  page = await drop('list');
  await ready(page);
  await openReceive(page);
  await setReceive(page, { state: 'waiting', link: RLINK, words: WORDS, expiresAt: nowSeconds + 500 });
  await page.keyboard.press('Escape');
  await page.locator('dialog.receive').waitFor({ state: 'detached' });
  await setReceive(page, { state: 'opened', link: RLINK, words: WORDS, expiresAt: nowSeconds + 500 });
  assert.equal(await page.locator('dialog.receive').count(), 0, 'no interruption for a state that needs nothing');
  await setReceive(page, { state: 'check', link: RLINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt: nowSeconds + 500 });
  await page.locator('dialog.receive[open]').waitFor();
  assert.equal(await statusOf(page), 'Do these 3 words match theirs? 8:20 left');
  await page.keyboard.press('Escape');
  await page.locator('dialog.receive').waitFor({ state: 'detached' });
  await setReceive(page, { state: 'consent', ...OFFER });
  await page.locator('dialog.receive[open]').waitFor();
  assert.match(await statusOf(page), /They want to send you holiday\.mp4/);
  await page.keyboard.press('Escape');
  await page.locator('dialog.receive').waitFor({ state: 'detached' });
  await setReceive(page, KEPT);
  assert.equal(await page.locator('dialog.receive').count(), 0);
  assert.equal(await text(page.locator('#notices')), "Received holiday.mp4. It's in ~/Downloads/Wildbloom Received.");
  await setReceive(page, { state: 'failed', reason: 'lost' });
  assert.equal(await text(page.locator('#notices')), "The connection was lost and couldn't be restored. Nothing was kept.");
  assert.equal((await calls(page, 'receive_cancel')).length, 0);
  await done(page);
});

scenario('receive: declined, cancelled by them, refused start, busy', async () => {
  let page = await drop('list');
  await ready(page);
  await openReceive(page);
  await setReceive(page, { state: 'consent', ...OFFER });
  await page.getByRole('button', { name: 'Decline' }).click();
  assert.deepEqual((await calls(page, 'receive_consent')).map((c) => c.args), [{ accept: false }]);
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('You said no.'));
  assert.equal(await statusOf(page), 'You said no. Nothing was sent.');
  assert.deepEqual(await buttonsOf(page), ['Close', 'Start again']);
  await setReceive(page, { state: 'cancelled', by: 'them' });
  assert.equal(await statusOf(page), 'They closed the page. Nothing was kept.');
  await page.getByRole('button', { name: 'Start again' }).click();
  assert.equal((await calls(page, 'receive_start')).length, 2);
  await setReceive(page, { state: 'check', link: RLINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt: nowSeconds + 500 });
  await page.getByRole('button', { name: "They don't match" }).click();
  assert.deepEqual((await calls(page, 'receive_verify')).at(-1).args, { matches: false });
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes("didn't match"));
  assert.equal(await statusOf(page), "The 3 words didn't match, so nothing was sent.");
  await done(page);

  page = await drop('list');
  await ready(page);
  await page.evaluate(() => { window.__stub.receiveRefusal = 'node_unreachable'; });
  await openReceive(page);
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('approved'));
  assert.match(await statusOf(page), /^Can't reach your online node, or this computer isn't approved there\./);
  await page.evaluate(() => { window.__stub.receiveRefusal = 'unknown'; });
  await page.getByRole('button', { name: 'Start again' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('sharing service'));
  await done(page);

  page = await drop('list');
  await ready(page);
  await page.evaluate(() => { window.__stub.receive = { state: 'opened', link: 'https://wildbloom.example/send/#v1.x', words: ['a', 'b', 'c', 'd'], expiresAt: Math.floor(Date.now() / 1000) + 300 }; });
  // The start-up check saw nothing; a later start finds one running and shows it.
  await page.evaluate(() => { window.__stub.handlers.receive_state = (() => { let n = 0; return () => (n++ === 0 ? { state: 'idle' } : window.__stub.receive); })(); });
  await openReceive(page);
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('opened your link'));
  assert.equal((await calls(page, 'receive_start')).length, 1);
  await done(page);
});

scenario('receive: every failure has plain words, no jargon, and Start again', async () => {
  const page = await drop('list');
  await ready(page);
  await openReceive(page);
  const reasons = ['node_unreachable', 'no_turn', 'turn_refused', 'turn_limit', 'relay_unreachable', 'expired', 'wrong_words', 'mismatch', 'too_big', 'unsupported', 'protocol', 'peer_failed', 'peer_storage', 'connect', 'lost', 'verification', 'storage', 'no_relay', 'webview', 'a_reason_from_the_future'];
  const seen = new Set();
  for (const reason of reasons) {
    await setReceive(page, { state: 'failed', reason });
    const line = await statusOf(page);
    assert.ok(line.length > 20 && line.endsWith('.'), `${reason}: a sentence`);
    assert.doesNotMatch(line, /\b(TURN|ICE|STUN|SDP|DTLS|NAT)\b/, `${reason}: no jargon`);
    assert.doesNotMatch(line, /webrtc|\bpeers?\b|protocol|webview|data channel/i, `${reason}: no jargon`);
    assert.equal(seen.has(line), false, `${reason}: its own words`);
    seen.add(line);
    assert.deepEqual(await buttonsOf(page), ['Close', 'Start again']);
  }
  await setReceive(page, { state: 'failed', reason: 'too_big' });
  assert.equal(await statusOf(page), "Their file is over 250 MB, so Drop didn't take it.");
  await setReceive(page, { state: 'failed', reason: 'a_reason_from_the_future' });
  assert.equal(await statusOf(page), 'Something went wrong. Nothing was kept.');
  await done(page);
});

scenario('receive: Add to Wildbloom problems say what to do, folder off can be turned on', async () => {
  const page = await drop('list');
  await ready(page);
  await openReceive(page);
  await setReceive(page, KEPT);
  const sheet = page.locator('dialog.receive[open]');
  await page.evaluate(() => { window.__stub.addToWildbloomError = 'cannot_sync'; });
  await sheet.getByRole('button', { name: 'Add to Wildbloom' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive').textContent.includes("can't keep this file"));
  assert.match(await sheetText(page), /Wildbloom can't keep this file, for example because it's empty\. It stays in the Received folder\./);
  assert.equal(await statusOf(page), 'Received holiday.mp4.', 'the file is still kept');
  await page.evaluate(() => { window.__stub.addToWildbloomError = 'move_failed'; });
  await sheet.getByRole('button', { name: 'Add to Wildbloom' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive').textContent.includes("Couldn't move"));
  await page.evaluate(() => { window.__stub.addToWildbloomError = 'not_found'; });
  await sheet.getByRole('button', { name: 'Add to Wildbloom' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive').textContent.includes("isn't where Drop left it"));

  // The folder is off: the usual question, then the add goes through.
  await page.evaluate(() => {
    window.__stub.addToWildbloomError = null;
    let off = 2;
    window.__stub.handlers.receive_add_to_wildbloom = () => { if (off-- > 0) throw { code: 'folder_off' }; return { name: 'holiday (2).mp4', folder: '~/Wildbloom' }; };
  });
  await sheet.getByRole('button', { name: 'Add to Wildbloom' }).click();
  const confirm = page.locator('dialog.confirm[open]');
  await confirm.waitFor();
  assert.equal(await text(confirm.locator('h2')), 'Keep a readable copy of every file in ~/Wildbloom?');
  await confirm.locator('button', { hasText: 'Cancel' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive').textContent.includes('Your Wildbloom folder is off'));
  await sheet.getByRole('button', { name: 'Add to Wildbloom' }).click();
  await confirm.waitFor();
  await confirm.locator('button', { hasText: 'Turn on' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive .share-slot').textContent.includes('Added'));
  assert.deepEqual((await calls(page, 'set_watch_folder')).map((c) => c.args), [{ enabled: true }]);
  assert.equal(await statusOf(page), 'Added holiday (2).mp4 to Wildbloom.');

  await done(page);
});

scenario('receive: kept while the Wildbloom folder is off', async () => {
  const page = await harness('receive-r10b', { width: 400, height: 600, scheme: 'light' });
  assert.equal(await statusOf(page), 'Received holiday.mp4.');
  assert.match(await sheetText(page), /Your Wildbloom folder is off, so it can't be added yet\. Turn it on in Settings\./);
  assert.deepEqual(await buttonsOf(page), ['Show in Finder', 'Done']);
  await page.evaluate(() => { window.__stub.revealError = true; });
  await page.getByRole('button', { name: 'Show in Finder' }).click();
  await page.waitForFunction(() => document.querySelector('dialog.receive').textContent.includes("isn't where Drop left it"));
  await done(page);
});

scenario('receive: keyboard order stays inside the sheet, Enter and Space work', async () => {
  const page = await drop('list');
  await ready(page);
  await openReceive(page);
  await setReceive(page, { state: 'waiting', link: RLINK, words: WORDS, expiresAt: nowSeconds + 581 });
  const order = async (count) => {
    const stops = [];
    for (let i = 0; i < count; i++) {
      await page.keyboard.press('Tab');
      stops.push(await page.evaluate(() => (document.activeElement.closest('dialog.receive') ? document.activeElement.getAttribute('data-key') || document.activeElement.textContent : 'outside the sheet')));
    }
    return stops;
  };
  await page.locator('dialog.receive h2').focus();
  assert.deepEqual(await order(3), ['copy-link', 'copy-words', 'cancel'], 'link, words, then Cancel');
  await setReceive(page, { state: 'check', link: RLINK, words: WORDS, checkWords: ['apple', 'river', 'stone'], expiresAt: nowSeconds + 500 });
  await page.locator('dialog.receive h2').focus();
  assert.deepEqual(await order(3), ['no-match', 'match', 'cancel']);
  await page.locator('[data-key="match"]').focus();
  await page.keyboard.press('Enter');
  assert.deepEqual((await calls(page, 'receive_verify')).map((c) => c.args), [{ matches: true }]);
  assert.equal(await page.locator('[data-key="match"]').count(), 0, 'the question is gone once answered');
  await setReceive(page, { state: 'consent', ...OFFER });
  assert.deepEqual(await order(2), ['decline', 'accept']);
  await page.keyboard.press('Space');
  assert.deepEqual((await calls(page, 'receive_consent')).map((c) => c.args), [{ accept: true }], 'Space on the focused Accept');
  await done(page);
});

scenario('receive: an answer cannot be sent twice', async () => {
  const page = await drop('list');
  await ready(page);
  await openReceive(page);
  await setReceive(page, { state: 'consent', ...OFFER });
  await page.evaluate(() => { window.__stub.handlers.receive_consent = () => new Promise(() => {}); });
  await page.getByRole('button', { name: 'Accept' }).click();
  assert.equal(await page.getByRole('button', { name: 'Accept' }).isDisabled(), true);
  assert.equal(await page.getByRole('button', { name: 'Decline' }).isDisabled(), true);
  await page.getByRole('button', { name: 'Accept' }).click({ force: true, timeout: 500 }).catch(() => {});
  assert.equal((await calls(page, 'receive_consent')).length, 1);
  await done(page);
});

scenario('receive: hostile and very long names are text, and wrap without overflow', async () => {
  for (const key of ['r6b', 'r6c']) {
    const page = await harness(`receive-${key}`, { width: 340, height: 420, scheme: 'dark' });
    assert.equal(await page.locator('dialog.receive img').count(), 0);
    const fit = await page.evaluate(() => { const body = document.querySelector('dialog.receive .sheet-body'); return body.scrollWidth <= body.clientWidth; });
    assert.equal(fit, true, `${key} fits at 340`);
    await done(page);
  }
});

scenario('settings: hide my address when receiving', async () => {
  const page = await settingsPage({ scheme: 'dark' });
  const box_ = page.getByRole('checkbox', { name: 'Hide my address when receiving' });
  assert.equal(await box_.count(), 1);
  assert.equal(await box_.isChecked(), true, 'on by default');
  assert.equal(await text(page.locator('#drop-receiving-hint')), "The other person sees the relay's address instead of yours, and sends may be slower.");
  assert.equal(await box_.getAttribute('aria-describedby'), 'drop-receiving-hint');
  assert.equal(await text(page.locator('#drop-receiving-folder')), 'Received files go to ~/Downloads/Wildbloom Received.');
  // Show, beside the path, reveals the Received folder; a refusal says so.
  const show = page.getByRole('button', { name: 'Show the Received folder' });
  assert.equal(await text(show), 'Show');
  const [pathBox, showBox] = [await page.locator('#drop-receiving-folder').boundingBox(), await show.boundingBox()];
  assert.ok(showBox.x > pathBox.x && Math.abs(showBox.y - pathBox.y) < pathBox.height, 'Show sits beside the path');
  await show.click();
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'reveal_received_folder'));
  assert.equal((await calls(page, 'reveal_received_folder')).length, 1);
  assert.equal(await page.locator('#drop-settings-error').isHidden(), true);
  await page.evaluate(() => { window.__stub.handlers.reveal_received_folder = () => { throw { code: 'received_folder', message: "Couldn't open the Received folder." }; }; });
  await show.click();
  await page.locator('#drop-settings-error:not([hidden])').waitFor();
  assert.equal(await text(page.locator('#drop-settings-error')), "Couldn't open the Received folder.");
  // Without a folder to show, neither the path nor Show is there.
  await page.evaluate(() => { window.__stub.state.receiving.folder = ''; window.__stub.flush(); });
  await page.waitForFunction(() => document.querySelector('#drop-receiving-row').hidden);
  assert.equal(await show.isVisible(), false);
  await page.evaluate(() => { window.__stub.state.receiving.folder = '~/Downloads/Wildbloom Received'; window.__stub.flush(); });
  await page.waitForFunction(() => !document.querySelector('#drop-receiving-row').hidden);
  await box_.uncheck();
  await page.waitForFunction(() => window.__stub.calls.some((c) => c.command === 'set_receiving'));
  assert.deepEqual((await calls(page, 'set_receiving')).map((c) => c.args), [{ hideAddress: false }]);
  assert.equal(await box_.isChecked(), false);
  await page.evaluate(() => { window.__stub.state.receiving.hideAddress = true; window.__stub.flush(); });
  await page.waitForFunction(() => document.querySelector('#drop-hide-address').checked);
  await page.evaluate(() => { window.__stub.handlers.set_receiving = () => { throw { code: 'unknown' }; }; });
  await box_.click();
  await page.locator('#drop-settings-error:not([hidden])').waitFor();
  assert.equal(await text(page.locator('#drop-settings-error')), "Couldn't change that setting.");
  assert.equal(await box_.isChecked(), true, 'the box goes back');
  const result = await new AxeBuilder({ page }).include('#drop-settings').withTags(AXE_TAGS).analyze();
  assert.deepEqual(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })), []);
  for (const width of [820, 420, 320]) {
    await page.setViewportSize({ width, height: 900 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `overflow at ${width}`);
  }
  await done(page);
});

/* ---------- run ---------- */

const only = process.env.DROP_UI_ONLY;
let failures = 0;
try {
  for (const { name, fn } of results) {
    if (only && !name.includes(only)) continue;
    const started = Date.now();
    try {
      await fn();
      console.log(`ok   ${name} (${((Date.now() - started) / 1000).toFixed(1)}s)`);
    } catch (error) {
      failures++;
      console.log(`FAIL ${name}\n${error.stack || error}\n`);
    }
  }
  if (problems.length) {
    failures++;
    console.log(`FAIL page problems:\n${[...new Set(problems)].join('\n')}`);
  }
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
if (failures) {
  console.log(`Drop UI: ${failures} failing`);
  process.exit(1);
}
console.log('Drop UI passed: every row, status line, drag, share and first-run state, platform variants, keyboard, announcer, reduced motion and axe. IPC is mocked; the Rust side is tested separately.');
