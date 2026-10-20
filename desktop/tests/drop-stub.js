// Test-only stand-in for the Tauri globals that the Drop UI uses.
// Loaded by tests/drop-ui.mjs (as an init script) and by tests/drop-harness.html.
// Query parameters: state (fixture), os (mac, windows, linux), desktop (gnome, kde), status (comma list of flags).
(() => {
  const params = new URLSearchParams(location.search);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const DAY = 86400;
  const calls = [];
  const listeners = new Map();
  const NPUB = 'npub1q8w6ylv7dkj0ttcc5dyx8qx9d4rkzp3g2h7n0xwm9yzlvfsn6u3q47xk2';
  const KEY = `wbk1_${'k3Zq9vXb2LmN8cRt5YhPw4JdAe7GfUo6SiBn1VxQ0zTrMyCa'.slice(0, 48)}`;

  const row = (id, name, state, extra = {}) => ({ id, name, bytes: 2_400_000, added: nowSeconds - 3000 - Number(id.replace(/\D/g, '') || 0) * 600, state, progress: null, ...extra });

  const allRows = () => [
    row('f1', 'holiday.jpg', 'two_copies'),
    row('f2', 'tax-return-2026.pdf', 'copying', { progress: 45, bytes: 18_400_000 }),
    row('f3', 'notes.txt', 'failed', { bytes: 12_000 }),
    row('f4', 'contract-draft.docx', 'encrypting', { progress: 20, bytes: 3_100_000 }),
    row('f5', 'scan-0042.png', 'queued', { bytes: 5_000_000 }),
    row('f6', 'passport.pdf', 'no_online', { bytes: 800_000 }),
    row('f7', 'wedding-video.mov', 'waiting', { bytes: 640_000_000 }),
    row('f8', 'invoice-october.pdf', 'missing_online', { bytes: 240_000 }),
    row('f9', 'archive.zip', 'online_full', { bytes: 90_000_000 }),
    row('f10', 'family-tree.ged', 'missing_local', { bytes: 410_000 }),
    row('f11', 'photos-2019.tar', 'restoring', { progress: 62, bytes: 120_000_000 }),
    row('f12', 'quote.pdf', 'shared', { sharedUntil: nowSeconds + 20 * 3600 }),
    row('f13', 'draft.txt', 'stop_pending'),
    row('f14', 'receipt.pdf', 'sharing_ended', { sharingEnded: nowSeconds - 1800 }),
    row('f18', 'minutes.pdf', 'share_owner_only'),
    row('f15', 'broken.bin', 'unreadable', { bytes: 0 }),
    row('f16', 'holiday-photos-from-the-summer-trip-to-the-coast-with-everyone-final-version-2026.zip', 'two_copies', { bytes: 240_000_000 }),
    row('f17', '<img src=x onerror=alert(1)>.pdf', 'two_copies'),
  ];
  const goodRows = () => allRows().filter((r) => ['f1', 'f16', 'f17'].includes(r.id)).concat([row('f20', 'budget.xlsx', 'two_copies'), row('f21', 'cv.pdf', 'two_copies', { inWatchFolder: true })]);
  // Folder fixtures: linked rows (with and without a parent folder), a row that is not linked,
  // and one not_kept row for each reason.
  const folderRows = () => [
    row('f30', 'budget.xlsx', 'two_copies', { inWatchFolder: true, folder: 'Taxes/2026' }),
    row('f31', 'cv.pdf', 'two_copies', { inWatchFolder: true }),
    row('f32', 'film.mov', 'not_kept', { notKept: 'too_big', bytes: 900_000_000, folder: 'Videos' }),
    row('f33', 'draft: v2?.txt', 'not_kept', { notKept: 'name', bytes: 4_000 }),
    row('f34', 'notes-with-a-very-long-name.txt', 'not_kept', { notKept: 'too_long', bytes: 4_000, folder: 'Projects/Research/Archive/Interviews/Transcripts' }),
    row('f35', 'deep.txt', 'not_kept', { notKept: 'too_deep', bytes: 4_000, folder: 'a/b/c/d/e/f/g/h/i/j' }),
    row('f36', 'window-only.pdf', 'two_copies'),
  ];
  // Deletions from the Wildbloom folder held back by the mass-removal brake, beside two kept rows.
  const heldRows = () => [
    row('h1', 'report.pdf', 'held', { folder: 'Work/2026' }),
    row('h2', 'budget.xlsx', 'held', { folder: 'Work/2026' }),
    row('h3', 'minutes-from-the-very-long-planning-meeting-in-september-final.docx', 'held', { folder: 'Work/Meetings/Autumn/September' }),
    row('h4', 'holiday.jpg', 'held', { folder: 'Photos' }),
    row('h5', 'beach.jpg', 'held', { folder: 'Photos' }),
    row('h6', 'notes.txt', 'held'),
    row('h7', 'draft.txt', 'held'),
  ];
  const listRows = () => [row('f1', 'holiday.jpg', 'two_copies'), row('f2', 'tax-return-2026.pdf', 'copying', { progress: 45, bytes: 18_400_000 }), row('f3', 'notes.txt', 'failed', { bytes: 12_000 }), row('f12', 'quote.pdf', 'shared', { sharedUntil: nowSeconds + 20 * 3600 }), row('f9', 'archive.zip', 'two_copies', { bytes: 90_000_000 })];
  const manyRows = () => Array.from({ length: 24 }, (_, i) => row(`m${i}`, `document-${String(i + 1).padStart(2, '0')}.pdf`, 'two_copies', { added: nowSeconds - 100 * i }));

  const baseStatus = () => ({
    firstRun: null,
    node: 'ok',
    keychain: 'ok',
    online: { configured: true, url: 'https://storage.example', host: 'storage.example', reachable: true, failedChecks: 0, usedBytes: 1_200_000_000, limitBytes: 5_000_000_000, full: false },
    approval: { state: 'active', byNpub: NPUB, deviceNpub: NPUB, until: nowSeconds + 300 * DAY, limitBytes: 5_000_000_000 },
    recovery: { keyList: 'ok', savedAt: nowSeconds - 20 * DAY, confirmed: true },
    watchFolder: { enabled: false, state: 'off', path: '~/Wildbloom' },
    limits: { dropMaxBytes: 1_000_000_000, shareMaxBytes: 250_000_000 },
    browserApproval: false,
    sharing: { afterDownload: 'delete', expirySeconds: 86400 },
    receiving: { hideAddress: true, folder: '~/Downloads/Wildbloom Received', maxBytes: 250_000_000 },
  });

  const name = params.get('state') || 'list';
  const state = baseStatus();
  let files = listRows();
  const firstRun = (step) => { state.firstRun = { step, nodeSettingsExist: false }; };
  const noOnline = () => { state.online = { ...state.online, configured: false, url: '', usedBytes: 0, limitBytes: 0 }; state.approval = { state: 'none' }; };
  if (name === 'empty') { files = []; state.online.usedBytes = 0; }
  else if (name === 'good') files = goodRows();
  else if (name === 'all-states') files = allRows();
  else if (name === 'folder') { files = folderRows(); state.watchFolder = { enabled: true, state: 'on', path: '~/Wildbloom' }; }
  else if (name === 'held' || name === 'confirm-held') { files = heldRows().concat([row('f30', 'cv.pdf', 'two_copies', { inWatchFolder: true }), row('f31', 'plan.pdf', 'two_copies', { inWatchFolder: true, folder: 'Work' })]); state.watchFolder = { enabled: true, state: 'on', path: '~/Wildbloom' }; }
  else if (name === 'held-one') { files = heldRows().slice(0, 1).concat([row('f30', 'cv.pdf', 'two_copies', { inWatchFolder: true })]); state.watchFolder = { enabled: true, state: 'on', path: '~/Wildbloom' }; }
  else if (name === 'many') files = manyRows();
  else if (name === 'no-online') { noOnline(); files = [row('f1', 'holiday.jpg', 'no_online'), row('f2', 'notes.txt', 'no_online', { bytes: 12_000 })]; }
  else if (name.startsWith('first-run-1') || name === 'first-run-restore') { firstRun('node'); files = []; noOnline(); }
  else if (name.startsWith('first-run-2')) { firstRun('approve'); files = []; }
  else if (name.startsWith('first-run-3')) { firstRun('recovery'); files = []; }
  else if (name === 'first-run-keychain') { firstRun('keychain'); state.keychain = 'unavailable'; files = []; }
  for (const flag of (params.get('status') || '').split(',').filter(Boolean)) {
    if (flag === 'node') state.node = 'stopped';
    if (flag === 'keychain') state.keychain = 'unavailable';
    if (flag === 'expired') state.approval = { ...state.approval, state: 'expired' };
    if (flag === 'unreachable') state.online = { ...state.online, reachable: false, failedChecks: 3 };
    if (flag === 'full') state.online = { ...state.online, full: true };
    if (flag === 'ends') state.approval = { ...state.approval, until: nowSeconds + 12 * DAY };
    if (flag === 'recovery') state.recovery = { keyList: 'ok', confirmed: false };
    if (flag === 'keylist') state.recovery = { ...state.recovery, keyList: 'failed' };
    if (flag === 'folder') state.watchFolder = { enabled: true, state: 'on', path: '~/Wildbloom' };
    if (flag === 'folder-unavailable') state.watchFolder = { enabled: true, state: 'unavailable', path: '~/Wildbloom' };
    if (flag === 'folder-too-many') state.watchFolder = { enabled: true, state: 'too_many', path: '~/Wildbloom' };
    if (flag === 'no-online') noOnline();
    if (flag === 'held') files = files.concat(heldRows());
    if (flag === 'good') files = goodRows();
    if (flag === 'downloads') files = files.concat([row('f40', 'brief.pdf', 'shared', { sharedUntil: nowSeconds + 20 * 3600, downloadedAt: nowSeconds - 1080 }), row('f41', 'deck.key', 'sharing_ended', { sharingEnded: nowSeconds - 1080, downloadedAt: nowSeconds - 1080 }), row('f42', 'map.png', 'stop_pending', { downloadedAt: nowSeconds - 1080 })]);
    if (flag === 'shared') files = goodRows().concat([row('f12', 'quote.pdf', 'shared', { sharedUntil: nowSeconds + 20 * 3600 }), row('f22', 'plan.pdf', 'shared', { sharedUntil: nowSeconds + 3600 })]);
  }

  const stub = {
    state, files, calls, handlers: {}, menus: [], clipboard: '', clipboardRead: 'bunker://relay.example/pair?secret=abc', saveResult: '/tmp/test/Wildbloom recovery key.txt',
    receive: { state: 'idle' }, approval: { state: 'idle' }, windows: [], key: KEY, npub: NPUB,
    emit(eventName, payload) {
      for (const callback of listeners.get(eventName) || []) callback({ event: eventName, payload });
    },
    pushRow(next) {
      const index = stub.files.findIndex((item) => item.id === next.id);
      if (index >= 0) stub.files[index] = next; else stub.files.push(next);
      stub.emit('drop://file', next);
    },
    // Sets the receive state and sends it as receive://state, as Rust does.
    setReceive(next) { stub.receive = next; stub.emit('receive://state', structuredClone(next)); return next; },
    snapshot() { return structuredClone({ ...stub.state, files: stub.files }); },
    flush() { stub.emit('drop://status', structuredClone(stub.state)); },
  };

  const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
  const defaults = {
    platform_info: () => {
      const os = params.get('os') || 'mac';
      return { os: os === 'mac' ? 'macos' : os, desktop: params.get('desktop') === 'kde' ? 'KDE' : params.get('desktop') === 'gnome' ? 'ubuntu:GNOME' : '', computerName: 'Test computer' };
    },
    drop_status: (args) => {
      if (args && args.recheck === 'keylist' && stub.keyListFixed) stub.state.recovery.keyList = 'ok';
      if (args && args.recheck === 'keychain' && stub.keychainFixed) {
        stub.state.keychain = 'ok';
        if (stub.state.firstRun && stub.state.firstRun.step === 'keychain') stub.state.firstRun.step = 'node';
      }
      return stub.snapshot();
    },
    add_paths: ({ paths }) => {
      const result = { added: [], refused: [], duplicates: [] };
      for (const path of paths) {
        const base = path.split('/').pop();
        if (path.startsWith('/folder/')) result.refused.push({ name: base, reason: 'folder' });
        else if (path.startsWith('/big/')) result.refused.push({ name: base, reason: 'too_big', limitBytes: 1_000_000_000 });
        else if (path.startsWith('/nospace/')) result.refused.push({ name: base, reason: 'no_space' });
        else if (path.startsWith('/dup/')) result.duplicates.push({ name: base, id: 'f1' });
        else {
          const id = `n${stub.files.length + 1}`;
          stub.pushRow(row(id, base, 'encrypting', { progress: 0, added: Math.floor(Date.now() / 1000) }));
          result.added.push(id);
        }
      }
      return result;
    },
    pick_files: () => ({ added: [], refused: [], duplicates: [] }),
    retry: () => undefined,
    copy_back: () => undefined,
    save_copy: () => (stub.saveCancelled ? null : { folder: 'Downloads' }),
    open_drop_flow: () => undefined,
    remove: ({ id }) => { stub.files = stub.files.filter((item) => item.id !== id); stub.emit('drop://file', { id, removed: true }); },
    resolve_held_removals: ({ ids, choice }) => {
      if (choice !== 'remove' && choice !== 'put_back') throw { code: 'bad_choice' };
      const held = stub.files.filter((item) => item.state === 'held' && ids.includes(item.id));
      for (const item of held) {
        if (choice === 'remove') {
          stub.files = stub.files.filter((entry) => entry.id !== item.id);
          stub.emit('drop://file', { id: item.id, removed: true });
        } else stub.pushRow({ ...item, state: 'two_copies', inWatchFolder: true });
      }
      return { count: held.length };
    },
    stop_sharing: () => undefined,
    set_sharing: ({ afterDownload, expirySeconds }) => { stub.state.sharing = { afterDownload, expirySeconds }; },
    check_online_node: ({ url }) => {
      const host = hostOf(url);
      if (url.includes('silent')) throw { code: 'no_answer', host };
      if (url.includes('notnode')) throw { code: 'not_a_node', host };
      if (url.includes('badtls')) throw { code: 'tls', host };
      if (url.includes('keychain')) throw { code: 'keychain_unavailable' };
      return { ok: true, host, usedBytes: 0, limitBytes: 5_000_000_000 };
    },
    set_online_node: ({ url }) => {
      stub.state.online = { ...stub.state.online, configured: Boolean(url), url: url || '', host: hostOf(url || ''), limitBytes: url ? 5_000_000_000 : 0 };
      if (stub.state.firstRun) stub.state.firstRun.step = url ? 'approve' : 'recovery';
    },
    approval_status: () => ({ deviceNpub: NPUB, limitBytes: 5_000_000_000, until: nowSeconds + 365 * DAY, ownerNpub: NPUB, ...stub.approval }),
    approve_device: ({ bunkerUrl }) => {
      if (!/^bunker:\/\//i.test(bunkerUrl || '')) throw { code: 'bad_link' };
      stub.approval = { state: 'waiting' };
    },
    renew_approval: ({ bunkerUrl }) => defaults.approve_device({ bunkerUrl }),
    cancel_approval: () => { stub.approval = { state: 'idle' }; },
    recovery_key_for_display: () => ({ key: KEY }),
    save_recovery_file: () => (stub.saveCancelled ? null : { filename: 'Wildbloom recovery key.txt' }),
    confirm_recovery_saved: () => { stub.state.firstRun = null; stub.state.recovery = { savedAt: nowSeconds, confirmed: true }; },
    restore: ({ recoveryKey, url }) => {
      if (url && url.includes('nofiles')) throw { code: 'no_files', host: hostOf(url) };
      if (url && url.includes('wrongkey')) throw { code: 'wrong_key', host: hostOf(url) };
      stub.restoring = true;
      return { next: 'approve', host: hostOf(url || '') };
    },
    set_watch_folder: ({ enabled }) => { stub.state.watchFolder = { ...stub.state.watchFolder, enabled, state: enabled ? 'on' : 'off' }; },
    open_file: ({ id }) => { if (!stub.files.find((item) => item.id === id)?.inWatchFolder) throw { code: 'not_in_folder' }; },
    reveal_file: ({ id }) => { const item = stub.files.find((entry) => entry.id === id); if (!item || !(item.inWatchFolder || item.state === 'not_kept')) throw { code: 'not_in_folder' }; },
    open_watch_folder: () => undefined,
    share_start: () => ({ state: 'preparing', progress: 10 }),
    share_again: () => ({ state: 'preparing', progress: 10 }),
    share_verify: ({ matches }) => ({ state: matches ? 'sending' : 'mismatch' }),
    share_cancel: () => undefined,
    set_receiving: ({ hideAddress }) => {
      if (typeof hideAddress !== 'boolean') throw { code: 'bad_args' };
      stub.state.receiving = { ...stub.state.receiving, hideAddress };
    },
    // Receive a file. The same machine as the contract: one receive at a time, answers ignored out of turn.
    receive_state: () => structuredClone(stub.receive),
    receive_start: () => {
      if (stub.receiveRefusal) throw { code: stub.receiveRefusal };
      if (LIVE_RECEIVE.has(stub.receive.state)) throw { code: 'busy' };
      return structuredClone(stub.setReceive({ state: 'preparing' }));
    },
    receive_verify: ({ matches }) => {
      if (typeof matches !== 'boolean') throw { code: 'bad_args' };
      if (stub.receive.state !== 'check') return undefined;
      stub.setReceive(matches ? { state: 'waiting_file' } : { state: 'failed', reason: 'mismatch' });
    },
    receive_consent: ({ accept }) => {
      if (typeof accept !== 'boolean') throw { code: 'bad_args' };
      if (stub.receive.state !== 'consent') return undefined;
      const { name, size, type } = stub.receive;
      stub.setReceive(accept ? { state: 'connecting', name, size, type, hidden: stub.state.receiving.hideAddress } : { state: 'declined', name, size, type });
    },
    receive_cancel: () => {
      if (LIVE_RECEIVE.has(stub.receive.state)) stub.setReceive({ state: 'cancelled', by: 'you' });
    },
    receive_add_to_wildbloom: ({ id }) => {
      if (stub.receive.state !== 'kept' || stub.receive.id !== id) throw { code: 'not_found' };
      if (stub.addToWildbloomError) throw { code: stub.addToWildbloomError };
      return { name: stub.receive.name, folder: '~/Wildbloom' };
    },
    receive_reveal: ({ id }) => {
      if (stub.receive.state !== 'kept' || stub.receive.id !== id || stub.revealError) throw { code: 'not_found' };
    },
  };

  const LIVE_RECEIVE = new Set(['preparing', 'waiting', 'opened', 'check', 'waiting_file', 'consent', 'connecting', 'receiving', 'verifying']);

  const invoke = async (command, args) => {
    calls.push({ command, args });
    const handler = stub.handlers[command] || defaults[command];
    if (!handler) throw `Unexpected command ${command}`;
    return handler(args);
  };
  class LogicalPosition { constructor(x, y) { this.x = x; this.y = y; } }
  window.__stub = stub;
  window.__TAURI__ = {
    core: { invoke },
    event: {
      listen: async (eventName, callback) => {
        if (!listeners.has(eventName)) listeners.set(eventName, new Set());
        listeners.get(eventName).add(callback);
        return () => listeners.get(eventName).delete(callback);
      },
    },
    dpi: { LogicalPosition },
    menu: {
      Menu: {
        new: async ({ items }) => ({
          items,
          popup: async (at) => { stub.menus.push({ items, at }); stub.lastMenu = { items, at }; },
        }),
      },
    },
    dialog: {
      save: async (options) => { calls.push({ command: '(dialog.save)', args: options }); return stub.saveResult; },
      open: async (options) => { calls.push({ command: '(dialog.open)', args: options }); return stub.openResult ?? '/tmp/test/Wildbloom recovery key.txt'; },
    },
    clipboardManager: {
      writeText: async (text) => { stub.clipboard = text; },
      readText: async () => stub.clipboardRead,
    },
    webviewWindow: {
      WebviewWindow: { getByLabel: async (label) => ({ show: async () => stub.windows.push(`show ${label}`), setFocus: async () => stub.windows.push(`focus ${label}`) }) },
    },
  };
})();
