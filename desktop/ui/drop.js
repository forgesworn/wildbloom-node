// Wildbloom Drop, webview side. A view over Rust state: no crypto, no network.
// Every string from outside is rendered with textContent or text nodes only.
// The contract with the Rust side is in DROP-IPC.md.
(() => {
  'use strict';
  const tauri = window.__TAURI__ || {};
  const html = document.documentElement;
  const isDropWindow = Boolean(document.getElementById('drop-app'));

  /* ---------- small helpers ---------- */

  const h = (tag, props, ...kids) => {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') el.className = value;
      else if (key === 'text') el.textContent = value;
      else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else if (value === true) el.setAttribute(key, '');
      else el.setAttribute(key, String(value));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === undefined || kid === null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  };
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  let idCounter = 0;
  const uid = (prefix) => `${prefix}-${++idCounter}`;
  const plural = (n, one, many) => (n === 1 ? one : many);

  function normaliseError(error) {
    if (error && typeof error === 'object') {
      return { ...error, code: error.code || 'unknown', message: error.message ? String(error.message) : '' };
    }
    const text = String(error ?? '');
    return { code: /^[a-z][a-z0-9_]*$/.test(text) ? text : 'unknown', message: text };
  }
  async function call(command, args) {
    try {
      return await tauri.core.invoke(command, args);
    } catch (error) {
      throw normaliseError(error);
    }
  }
  async function listen(name, handler) {
    if (!tauri.event?.listen) return () => {};
    try {
      return await tauri.event.listen(name, (event) => handler(event.payload, event));
    } catch {
      return () => {};
    }
  }

  /* ---------- formatting ---------- */

  const UNITS = ['B', 'kB', 'MB', 'GB', 'TB'];
  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const exponent = Math.min(Math.floor(Math.log10(bytes) / 3), UNITS.length - 1);
    if (exponent === 0) return `${Math.round(bytes)} B`;
    const value = bytes / 1000 ** exponent;
    const text = value >= 100 ? value.toFixed(0) : value.toFixed(1);
    return `${text.replace(/\.0$/, '')} ${UNITS[exponent]}`;
  }
  const timeFormat = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
  const shortDate = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' });
  const shortDateYear = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  const longDate = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  function dayOffset(seconds) {
    const date = new Date(seconds * 1000);
    const now = new Date();
    const a = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    const b = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    return Math.round((a - b) / 86400000);
  }
  function dateWord(seconds, lower) {
    const offset = dayOffset(seconds);
    const date = new Date(seconds * 1000);
    const words = { '-1': 'Yesterday', 0: 'Today', 1: 'Tomorrow' };
    if (words[offset]) return lower ? words[offset].toLowerCase() : words[offset];
    return (date.getFullYear() === new Date().getFullYear() ? shortDate : shortDateYear).format(date);
  }
  /** "Today 09:12" for the Added column. */
  const stamp = (seconds) => `${dateWord(seconds)} ${timeFormat.format(new Date(seconds * 1000))}`;
  /** "09:12 tomorrow" or "09:12 on 17 Oct" for sentences. */
  function until(seconds) {
    const time = timeFormat.format(new Date(seconds * 1000));
    const word = dateWord(seconds, true);
    return /^(today|tomorrow|yesterday)$/.test(word) ? `${time} ${word}` : `${time} on ${word}`;
  }
  const fullDate = (seconds) => longDate.format(new Date(seconds * 1000));
  const shortNpub = (npub) => (npub && npub.length > 16 ? `${npub.slice(0, 7)}…${npub.slice(-4)}` : npub || '');
  function middleTruncate(name, max = 64) {
    if (name.length <= max) return name;
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 && name.length - dot <= 8 ? name.slice(dot) : '';
    // A long tail when there is room (the end of a name often tells versions
    // apart), giving way as the space shrinks, so a wide font or a narrow
    // window can always fit the name in two lines.  The extension stays.
    const budget = Math.max(max - 1, ext.length + 2);
    const tail = Math.min(Math.max(ext.length + 12, 24), Math.max(ext.length + 1, Math.floor(budget * 0.4)));
    const head = Math.max(budget - tail, 1);
    return `${name.slice(0, head)}…${name.slice(name.length - tail)}`;
  }
  const hostOf = (url) => {
    try {
      return new URL(url).host;
    } catch {
      return url || '';
    }
  };

  /* ---------- icons (currentColor SVG, always paired with text) ---------- */

  const SVG = 'http://www.w3.org/2000/svg';
  const ICONS = {
    check: [['path', { d: 'M3 8.5l3.2 3.2L13 4.8' }]],
    up: [['path', { d: 'M8 13V3M4 7l4-4 4 4' }]],
    down: [['path', { d: 'M8 3v10M4 9l4 4 4-4' }]],
    ring: [['circle', { cx: 8, cy: 8, r: 5.5 }]],
    pending: [['circle', { cx: 8, cy: 8, r: 5.5, 'stroke-dasharray': '2.2 2.6' }]],
    alert: [['circle', { cx: 8, cy: 8, r: 6 }], ['path', { d: 'M8 4.8v3.8' }], ['circle', { cx: 8, cy: 11.1, r: 0.6, class: 'fill' }]],
    refresh: [['path', { d: 'M13 8a5 5 0 1 1-1.6-3.7M13 2.6v2.8h-2.8' }]],
    share: [['circle', { cx: 4, cy: 8, r: 1.6 }], ['circle', { cx: 12, cy: 4, r: 1.6 }], ['circle', { cx: 12, cy: 12, r: 1.6 }], ['path', { d: 'M5.4 7.2l5.2-2.4M5.4 8.8l5.2 2.4' }]],
    refuse: [['circle', { cx: 8, cy: 8, r: 6 }], ['path', { d: 'M3.8 12.2l8.4-8.4' }]],
    more: [['circle', { cx: 3.5, cy: 8, r: 1.2, class: 'fill' }], ['circle', { cx: 8, cy: 8, r: 1.2, class: 'fill' }], ['circle', { cx: 12.5, cy: 8, r: 1.2, class: 'fill' }]],
  };
  function icon(name, extra) {
    const svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('class', `icon${extra ? ` ${extra}` : ''}`);
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    for (const [tag, attrs] of ICONS[name]) {
      const node = document.createElementNS(SVG, tag);
      for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
      svg.append(node);
    }
    return svg;
  }
  const iconSlot = (name, tone, extra) => h('span', { class: `icon-slot tone-${tone}`, 'aria-hidden': 'true' }, icon(name, extra));

  /* ---------- platform ---------- */

  const platform = { os: 'mac', desktop: 'other', computerName: '' };
  (function guess() {
    const text = `${navigator.userAgentData?.platform || ''} ${navigator.platform || ''} ${navigator.userAgent || ''}`;
    platform.os = /Win/i.test(text) ? 'windows' : /Linux|X11/i.test(text) && !/Android/i.test(text) ? 'linux' : 'mac';
    platform.desktop = platform.os === 'linux' ? 'other' : '';
  })();
  const primaryLeft = () => platform.os === 'windows' || (platform.os === 'linux' && platform.desktop === 'kde');
  function applyPlatform() {
    html.dataset.os = platform.os;
    html.dataset.desktop = platform.desktop;
    html.dataset.buttonOrder = primaryLeft() ? 'primary-left' : 'primary-right';
  }
  async function loadPlatform() {
    try {
      const info = await call('platform_info');
      const os = String(info.os || '').toLowerCase();
      platform.os = os.startsWith('mac') || os === 'darwin' ? 'mac' : os.startsWith('win') ? 'windows' : os === 'linux' ? 'linux' : platform.os;
      const desktop = String(info.desktop || '').toLowerCase();
      platform.desktop = platform.os !== 'linux' ? '' : desktop.includes('kde') ? 'kde' : desktop.includes('gnome') ? 'gnome' : 'other';
      platform.computerName = String(info.computerName || '');
    } catch {
      /* keep the guess */
    }
    applyPlatform();
  }
  applyPlatform();
  /** Dialog buttons: primary on the right (macOS, GNOME) or on the left (Windows, KDE). */
  function buttonRow(primary, secondary) {
    const ordered = !secondary ? [primary] : primaryLeft() ? [primary, secondary] : [secondary, primary];
    return h('div', { class: 'dialog-actions' }, ordered);
  }
  const casing = (mac, other) => (platform.os === 'mac' ? mac : other);
  const trashName = () => (platform.os === 'windows' ? 'Recycle Bin' : 'Trash');
  const revealText = () => (platform.os === 'mac' ? 'Show in Finder' : platform.os === 'windows' ? 'Show in Explorer' : 'Show in Folder');

  /* ---------- clipboard, dialogs, menus, windows ---------- */

  async function writeClipboard(text) {
    try {
      if (tauri.clipboardManager?.writeText) {
        await tauri.clipboardManager.writeText(text);
        return true;
      }
    } catch {
      /* fall through */
    }
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }
  async function readClipboard() {
    try {
      if (tauri.clipboardManager?.readText) return String((await tauri.clipboardManager.readText()) || '');
    } catch {
      /* fall through */
    }
    try {
      return String((await navigator.clipboard.readText()) || '');
    } catch {
      return null;
    }
  }
  async function openNodeSettings() {
    try {
      const window_ = await tauri.webviewWindow.WebviewWindow.getByLabel('main');
      if (window_) {
        await window_.show();
        await window_.setFocus();
      }
    } catch {
      /* the capability may be missing; nothing else to try from here */
    }
  }
  async function popupMenu(items, anchor, point) {
    const Menu = tauri.menu?.Menu;
    if (!Menu || !items.length) return;
    try {
      const menu = await Menu.new({ items: items.map((item) => ({ id: item.id, text: item.text, action: item.run })) });
      let at;
      if (tauri.dpi?.LogicalPosition) {
        const rect = anchor?.getBoundingClientRect();
        at = point ? new tauri.dpi.LogicalPosition(point.x, point.y) : rect ? new tauri.dpi.LogicalPosition(rect.left, rect.bottom) : undefined;
      }
      await menu.popup(at);
    } catch {
      /* native menus are best effort */
    }
  }

  const themeClass = isDropWindow ? '' : ' drop-dark';
  function showDialog(dialog, opener, onClosed) {
    document.body.append(dialog);
    dialog.addEventListener('close', () => {
      dialog.remove();
      if (opener && opener.isConnected) opener.focus({ preventScroll: true });
      if (onClosed) onClosed();
    });
    dialog.showModal();
  }

  /** Modal confirmation. Cancel is the default for destructive questions. */
  function confirmDialog({ title, paragraphs = [], confirmLabel, cancelLabel = 'Cancel', destructive = true, opener }) {
    return new Promise((resolve) => {
      const titleId = uid('confirm-title');
      let answer = false;
      const dialog = h('dialog', { class: `drop-scope${themeClass} confirm`, 'aria-labelledby': titleId });
      const cancel = h('button', { class: `btn ${destructive ? 'primary' : 'secondary'}`, type: 'button', 'data-key': 'cancel', onclick: () => dialog.close() }, cancelLabel);
      const accept = h('button', { class: `btn ${destructive ? 'secondary' : 'primary'}`, type: 'button', 'data-key': 'confirm', onclick: () => { answer = true; dialog.close(); } }, confirmLabel);
      dialog.append(h('h2', { id: titleId }, title), ...paragraphs.map((text) => h('p', {}, text)), buttonRow(destructive ? accept : accept, cancel));
      showDialog(dialog, opener, () => resolve(answer));
      (destructive ? cancel : accept).focus();
    });
  }

  /** Asked before the Wildbloom folder is turned on, in the Drop window and in node settings. */
  async function confirmFolderOn(opener) {
    await loadPlatform();
    return confirmDialog({
      title: 'Keep a readable copy of every file in ~/Wildbloom?',
      paragraphs: [`Each computer with the folder on holds the same files in the same folders. Changes and deletions there reach your other computers. Anything Wildbloom replaces or removes goes to the ${trashName()}. Update Wildbloom on all your computers first.`],
      confirmLabel: 'Turn on', destructive: false, opener,
    });
  }

  /* ---------- first run and settings flows (D1 to D4) ---------- */

  function nodeErrorText(code, host) {
    switch (code) {
      case 'empty': return "Enter your online node's address.";
      case 'not_https': return 'Use an address that starts with https://';
      case 'not_a_node': return `${host} isn't a Wildbloom Node.`;
      case 'tls': return `Couldn't make a secure connection to ${host}.`;
      case 'offline': return "You're offline. Connect to the internet, then try again.";
      default: return `${host} didn't respond. Check the address and your internet connection.`;
    }
  }
  function checkAddress(raw) {
    const text = String(raw || '').trim().replace(/\/+$/, '');
    if (!text) return { error: 'empty' };
    try {
      const parsed = new URL(text);
      if (parsed.protocol !== 'https:' || !parsed.host) return { error: 'not_https' };
      return { url: text, host: parsed.host };
    } catch {
      return { error: 'not_https' };
    }
  }
  const approvalErrorText = {
    timeout: () => "Your signer didn't answer within 2 minutes. Check it's on and connected, then try again.",
    declined: () => 'Your signer declined. Nothing was changed.',
    wrong_owner: (a) => `Your online node doesn't recognise ${shortNpub(a.ownerNpub)} as its owner. Approve with the key that runs the node.`,
    refused: (a) => `Your online node didn't accept the approval: ${a.detail || 'no reason given'}.`,
    offline: () => "You're offline. Connect to the internet, then try again.",
    bad_link: () => 'That isn\'t a signer connection link. It should start with bunker://',
  };
  const restoreErrorText = (code, host) => {
    if (code === 'bad_key') return "That isn't a Wildbloom recovery key. It starts with wbk1_";
    if (code === 'no_files') return `No files were found for this recovery key on ${host}.`;
    if (code === 'wrong_key') return `This recovery key doesn't unlock the files on ${host}.`;
    return nodeErrorText(code, host);
  };

  /**
   * One flow engine for the three places it appears: first run in the drop window,
   * and sheets opened from the status line or from node settings.
   * opts: { mode: 'first' | 'sheet', sequence, renew, browserApproval, resave, refresh, onFinish, onCancel, nodeSettingsExist }
   */
  function createFlow(host, opts) {
    const first = opts.mode === 'first';
    const draft = { url: opts.url || '', link: '', key: '', file: null, restoreHost: '' };
    let step = null;
    let disposed = false;
    let generation = 0;
    let sequenceIndex = 0;
    let restoring = false;
    let waiting = false;
    let recoveryKey = '';
    const stepNumber = { node: 1, approve: 2, recovery: 3 };

    const heading = (text, id) => h('h2', { id, tabindex: '-1' }, text);
    const eyebrow = (name) => (first && !restoring && stepNumber[name] ? h('p', { class: 'eyebrow' }, `Step ${stepNumber[name]} of 3`) : null);
    const show = (...nodes) => {
      host.replaceChildren(h('div', { class: 'flow' }, nodes));
    };
    const focusHeading = () => host.querySelector('h2')?.focus({ preventScroll: true });
    const field = (id, label, input, hint) => h('div', {}, h('label', { class: 'field-label', for: id }, label), input, hint);

    function go(next, focus = true) {
      generation++;
      step = next;
      ({ node: renderNode, approve: renderApprove, recovery: renderRecovery, restore: renderRestore, keychain: renderKeychain })[next]();
      if (focus) focusHeading();
    }
    async function advance() {
      if (disposed) return;
      if (first) {
        const status = await opts.refresh();
        if (disposed) return;
        const next = status?.firstRun?.step;
        if (!next) return finish();
        return go(next);
      }
      sequenceIndex++;
      const next = opts.sequence[sequenceIndex];
      return next ? go(next) : finish();
    }
    function finish() {
      if (disposed) return;
      recoveryKey = '';
      if (opts.onFinish) opts.onFinish();
    }
    function guardKeychain(error) {
      if (error.code === 'keychain_unavailable') {
        go('keychain');
        return true;
      }
      return false;
    }
    function secondary(label, onclick, extra) {
      return h('button', { class: 'btn quiet', type: 'button', onclick, ...extra }, label);
    }
    function cancelButton() {
      return opts.mode === 'sheet' ? secondary('Cancel', () => opts.onCancel && opts.onCancel()) : null;
    }

    /* D1 */
    function renderNode() {
      const inputId = uid('node-url');
      const hintId = uid('hint');
      const errorId = uid('error');
      const input = h('input', { class: 'field', id: inputId, type: 'text', inputmode: 'url', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', placeholder: 'https://storage.example', 'aria-describedby': `${hintId} ${errorId}` });
      input.value = draft.url;
      const error = h('p', { class: 'msg error', id: errorId, role: 'alert', hidden: true });
      const status = h('p', { class: 'msg', role: 'status' });
      const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Continue');
      let busy = false;
      const setError = (text) => {
        error.textContent = text || '';
        error.hidden = !text;
        input.setAttribute('aria-invalid', text ? 'true' : 'false');
      };
      const setBusy = (value, host_) => {
        busy = value;
        submit.textContent = value ? 'Checking…' : 'Continue';
        submit.setAttribute('aria-disabled', value ? 'true' : 'false');
        status.textContent = value ? `Checking ${host_}…` : '';
      };
      const form = h('form', { class: 'stack', novalidate: true, onsubmit: async (event) => {
        event.preventDefault();
        if (busy) return;
        draft.url = input.value;
        setError('');
        const checked = checkAddress(input.value);
        if (checked.error) {
          setError(nodeErrorText(checked.error, ''));
          input.focus();
          return;
        }
        setBusy(true, checked.host);
        try {
          const found = await call('check_online_node', { url: checked.url });
          if (disposed) return;
          setBusy(false);
          status.textContent = `Found it. ${formatBytes(Math.max(0, (found.limitBytes || 0) - (found.usedBytes || 0)))} free.`;
          await delay(600);
          if (disposed) return;
          await call('set_online_node', { url: checked.url });
          await advance();
        } catch (e) {
          if (disposed) return;
          setBusy(false);
          if (guardKeychain(e)) return;
          setError(nodeErrorText(e.code, e.host || checked.host));
          input.focus();
        }
      } },
      field(inputId, 'Online node address', input, h('p', { class: 'hint', id: hintId }, "The address of the Wildbloom Node you run online.")),
      error,
      h('div', { class: 'stack' }, submit, status),
      first ? secondary('Set up later and keep copies on this computer only', async () => {
        try {
          await call('set_online_node', { url: null });
          await advance();
        } catch (e) {
          if (!guardKeychain(e)) setError(e.message || 'Something went wrong.');
        }
      }) : null,
      first ? secondary('Restore from a recovery key', () => go('restore')) : null,
      cancelButton());
      show(eyebrow('node'), heading(opts.heading || 'Set up Wildbloom Drop'),
        h('p', { class: 'body' }, 'Drop a file here and Wildbloom keeps two encrypted copies: one on this computer and one on your online node.'),
        form,
        first && opts.nodeSettingsExist === false ? h('p', { class: 'hint' }, 'Wildbloom Node will run on this computer only. You can change that later in Node settings.') : null);
    }

    /* D2 */
    async function renderApprove(view = { phase: 'idle' }) {
      const myGeneration = ++generation;
      let facts = view.facts;
      if (!facts) {
        try {
          facts = await call('approval_status');
        } catch (e) {
          if (guardKeychain(e)) return;
          facts = {};
        }
        if (disposed || myGeneration !== generation) return;
        if (facts.state === 'waiting' && view.phase === 'idle') return renderApprove({ phase: 'waiting', facts });
      }
      waiting = view.phase === 'waiting';
      const inputId = uid('bunker');
      const hintId = uid('hint');
      const errorId = uid('error');
      const input = h('input', { class: 'field mono', id: inputId, type: 'text', inputmode: 'url', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', placeholder: 'bunker://', 'aria-describedby': `${hintId} ${errorId}` });
      input.value = draft.link;
      input.addEventListener('input', () => { draft.link = input.value; });
      const error = h('p', { class: 'msg error', id: errorId, role: 'alert', hidden: !view.error }, view.error || '');
      if (view.error) input.setAttribute('aria-invalid', 'true');
      const copyState = h('span', { class: 'sr-only', role: 'status' });
      const factsList = h('dl', { class: 'facts' },
        h('dt', {}, 'This computer'),
        h('dd', {}, h('span', {}, shortNpub(facts.deviceNpub)), h('button', { class: 'btn quiet', type: 'button', 'aria-label': 'Copy this computer\'s public key', onclick: async () => { copyState.textContent = (await writeClipboard(facts.deviceNpub || '')) ? 'Copied.' : "Couldn't copy."; } }, 'Copy'), copyState),
        h('dt', {}, 'Allowed'),
        h('dd', {}, facts.limitBytes ? `Up to ${formatBytes(facts.limitBytes)}, until ${fullDate(facts.until)}` : ''));
      const intro = h('p', { class: 'body' }, 'Your signer approves this computer once. After that, Wildbloom copies files to your online node without asking each time.');
      const title = heading(opts.renew ? 'Approve this computer again' : 'Approve this computer');
      const lead = [eyebrow('approve'), title, intro, factsList];

      if (view.phase === 'waiting' || view.phase === 'done') {
        const message = view.phase === 'done' ? `Approved by ${shortNpub(facts.byNpub)}.` : 'Waiting for your signer. Check your Heartwood device.';
        show(...lead, h('p', { class: 'msg ok', role: 'status' }, message), view.phase === 'waiting' ? h('div', { class: 'stack' }, h('button', { class: 'btn secondary block', type: 'button', onclick: async () => {
          generation++;
          waiting = false;
          try { await call('cancel_approval'); } catch { /* already finished */ }
          if (!disposed) renderApprove({ phase: 'idle' });
        } }, 'Cancel')) : null);
        if (view.phase === 'waiting') pollApproval(myGeneration);
        return;
      }

      const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Ask my signer to approve');
      const form = h('form', { class: 'stack', novalidate: true, onsubmit: async (event) => {
        event.preventDefault();
        const link = input.value.trim();
        draft.link = input.value;
        if (!/^bunker:\/\//i.test(link)) {
          renderApprove({ phase: 'idle', facts, error: approvalErrorText.bad_link(), focusInput: true });
          return;
        }
        waiting = true; // a dismissal while the request is in flight must still cancel it
        try {
          await call(opts.renew ? 'renew_approval' : 'approve_device', { bunkerUrl: link });
          if (!disposed) renderApprove({ phase: 'waiting', facts });
        } catch (e) {
          waiting = false;
          if (disposed || guardKeychain(e)) return;
          const text = (approvalErrorText[e.code] || (() => `Your online node didn't accept the approval: ${e.message || 'no reason given'}.`))({ ...e, detail: e.detail || e.message });
          renderApprove({ phase: 'idle', facts, error: text, focusInput: true });
        }
      } },
      h('div', {}, h('label', { class: 'field-label', for: inputId }, 'Signer connection link'),
        h('div', { class: 'inline' }, input, h('button', { class: 'btn secondary', type: 'button', onclick: async () => {
          const text = await readClipboard();
          if (text === null) { input.focus(); return; }
          input.value = text.trim();
          draft.link = input.value;
          input.focus();
        } }, 'Paste')),
        h('p', { class: 'hint', id: hintId }, 'From Heartwood or another NIP-46 signer. It starts with bunker://')),
      error,
      h('div', { class: 'stack' }, submit,
        opts.browserApproval ? secondary('Approve in your browser instead', async () => {
          waiting = true;
          try {
            await call(opts.renew ? 'renew_approval' : 'approve_device', { bunkerUrl: null, browser: true });
            if (!disposed) renderApprove({ phase: 'waiting', facts });
          } catch (e) {
            waiting = false;
            if (!guardKeychain(e)) renderApprove({ phase: 'idle', facts, error: e.message || 'Something went wrong.' });
          }
        }) : null,
        cancelButton()));
      show(...lead, form);
      if (view.error) input.focus();
    }
    async function pollApproval(myGeneration) {
      while (!disposed && myGeneration === generation) {
        await delay(1000);
        if (disposed || myGeneration !== generation) return;
        let status;
        try {
          status = await call('approval_status');
        } catch (e) {
          if (!guardKeychain(e)) renderApprove({ phase: 'idle', error: e.message || 'Something went wrong.' });
          return;
        }
        if (disposed || myGeneration !== generation) return;
        if (status.state !== 'waiting') waiting = false;
        if (status.state === 'approved') {
          renderApprove({ phase: 'done', facts: status });
          await delay(600);
          if (!disposed) await advance();
          return;
        }
        if (status.state === 'restore_failed') {
          go('restore');
          showRestoreError(restoreErrorText(status.code, draft.restoreHost));
          return;
        }
        if (status.state === 'failed') {
          const text = (approvalErrorText[status.code] || approvalErrorText.refused)(status);
          renderApprove({ phase: 'idle', error: text, facts: status });
          return;
        }
        if (status.state === 'idle') {
          renderApprove({ phase: 'idle', facts: status });
          return;
        }
      }
    }

    /* D3 */
    async function renderRecovery() {
      const myGeneration = ++generation;
      let key = '';
      try {
        key = String((await call('recovery_key_for_display')).key || '');
      } catch (e) {
        if (guardKeychain(e)) return;
        show(heading('Save your recovery key'), h('p', { class: 'msg error', role: 'alert' }, e.message || "Couldn't read your recovery key."), cancelButton());
        focusHeading();
        return;
      }
      if (disposed || myGeneration !== generation) return;
      recoveryKey = key;
      const resave = Boolean(opts.resave);
      let used = false;
      const saved = h('p', { class: 'msg ok', role: 'status' });
      const checkbox = h('input', { type: 'checkbox', id: uid('saved') });
      const finishButton = h('button', { class: 'btn primary block', type: 'button', disabled: !resave, onclick: async () => {
        try {
          if (!resave) await call('confirm_recovery_saved');
          recoveryKey = '';
          if (first) await advance();
          else finish();
        } catch (e) {
          if (!guardKeychain(e)) saved.textContent = e.message || "Couldn't finish.";
        }
      } }, resave ? 'Done' : 'Finish');
      const update = () => { finishButton.disabled = !resave && !(used && checkbox.checked); };
      checkbox.addEventListener('change', update);
      const groups = key.match(/.{1,6}/g) || [];
      show(eyebrow('recovery'), heading('Save your recovery key'),
        h('p', { class: 'body' }, "If this computer is lost or breaks, this key is the only way to unlock your files on your online node. Wildbloom can't recover it for you."),
        h('p', { class: 'key', id: 'recovery-key-text' }, groups.map((part) => h('span', { class: 'grp' }, part))),
        h('div', { class: 'inline' },
          h('button', { class: 'btn secondary', type: 'button', onclick: async () => {
            try {
              // Rust opens the save dialog; the page never names a path.
              const result = await call('save_recovery_file');
              if (!result) return;
              used = true;
              saved.textContent = `Saved to ${result.filename}.`;
              update();
            } catch (e) {
              if (!guardKeychain(e)) saved.textContent = e.message || "Couldn't save the file.";
            }
          } }, 'Save recovery file…'),
          h('button', { class: 'btn quiet', type: 'button', onclick: async () => {
            if (await writeClipboard(recoveryKey)) {
              used = true;
              saved.textContent = 'Copied.';
              update();
            } else {
              saved.textContent = "Couldn't copy. Select the key and copy it yourself.";
            }
          } }, 'Copy')),
        saved,
        h('p', { class: 'hint' }, "Keep it in a password manager or print the file. Don't keep it only on this computer. Anyone with this key and access to your online node could unlock your files."),
        resave ? null : h('label', { class: 'check', for: checkbox.id }, checkbox, h('span', {}, "I've saved my recovery key somewhere other than this computer")),
        finishButton, cancelButton());
      focusHeading();
    }

    /* D4 */
    function showRestoreError(text) {
      const target = host.querySelector('[data-restore-error]');
      if (target) {
        target.textContent = text;
        target.hidden = !text;
      }
    }
    function renderRestore() {
      restoring = true;
      const keyId = uid('recovery');
      const urlId = uid('restore-url');
      const errorId = uid('error');
      const keyInput = h('input', { class: 'field mono', id: keyId, type: 'text', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', placeholder: 'wbk1_', 'aria-describedby': errorId });
      keyInput.value = draft.key;
      const urlInput = h('input', { class: 'field', id: urlId, type: 'text', inputmode: 'url', autocomplete: 'off', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', placeholder: 'https://storage.example', 'aria-describedby': errorId });
      urlInput.value = draft.url;
      const fileNote = h('p', { class: 'hint', role: 'status' });
      const error = h('p', { class: 'msg error', id: errorId, role: 'alert', 'data-restore-error': true, hidden: true });
      const status = h('p', { class: 'msg', role: 'status' });
      const submit = h('button', { class: 'btn primary block', type: 'submit' }, 'Continue');
      let busy = false;
      const setError = (text) => {
        showRestoreError(text);
        keyInput.setAttribute('aria-invalid', text ? 'true' : 'false');
      };
      const useFile = (file) => {
        draft.file = file;
        keyInput.value = '';
        keyInput.disabled = Boolean(file);
        fileNote.textContent = file ? `Using ${file.name}. The online node address comes from the file unless you type one.` : '';
      };
      if (draft.file) useFile(draft.file);
      const form = h('form', { class: 'stack', novalidate: true, onsubmit: async (event) => {
        event.preventDefault();
        if (busy) return;
        draft.key = keyInput.value;
        draft.url = urlInput.value;
        setError('');
        const key = keyInput.value.trim();
        if (!draft.file && !key.startsWith('wbk1_')) {
          setError(restoreErrorText('bad_key'));
          keyInput.focus();
          return;
        }
        let address = { url: '', host: '' };
        if (urlInput.value.trim() || !draft.file) {
          address = checkAddress(urlInput.value);
          if (address.error) {
            setError(nodeErrorText(address.error, ''));
            urlInput.focus();
            return;
          }
        }
        draft.restoreHost = address.host;
        busy = true;
        submit.textContent = 'Checking…';
        submit.setAttribute('aria-disabled', 'true');
        status.textContent = `Checking ${address.host || 'the recovery file'}…`;
        try {
          const result = await call('restore', { recoveryKey: draft.file ? null : key, recoveryFile: draft.file ? draft.file.path : null, url: address.url || null });
          if (disposed) return;
          draft.restoreHost = result?.host || address.host;
          draft.key = '';
          restoring = true;
          if (result?.next === 'done') {
            await advance();
          } else {
            go('approve');
          }
        } catch (e) {
          if (disposed) return;
          busy = false;
          submit.textContent = 'Continue';
          submit.setAttribute('aria-disabled', 'false');
          status.textContent = '';
          if (guardKeychain(e)) return;
          setError(restoreErrorText(e.code, e.host || address.host));
        }
      } },
      field(keyId, 'Recovery key', h('div', { class: 'inline' }, keyInput,
        h('button', { class: 'btn secondary', type: 'button', onclick: async () => {
          const text = await readClipboard();
          if (text === null) { keyInput.focus(); return; }
          useFile(null);
          keyInput.value = text.trim();
          keyInput.focus();
        } }, 'Paste'))),
      h('div', { class: 'stack' }, h('button', { class: 'btn secondary', type: 'button', onclick: async () => {
        if (!tauri.dialog?.open) return;
        try {
          const path = await tauri.dialog.open({ multiple: false, directory: false, filters: [{ name: 'Text', extensions: ['txt'] }] });
          if (path) useFile({ path: String(path), name: String(path).split(/[\\/]/).pop() });
        } catch { /* cancelled */ }
      } }, 'Open recovery file…'), fileNote),
      field(urlId, 'Online node address', urlInput),
      error,
      h('div', { class: 'stack' }, submit, status),
      first || opts.mode === 'sheet' ? secondary('Back', () => { restoring = false; go('node'); }) : null);
      show(heading('Restore your files'),
        h('p', { class: 'body' }, 'Enter your recovery key and approve this computer. Wildbloom copies your files back from your online node.'),
        form);
    }

    /* Keychain unavailable (replaces the screen) */
    function renderKeychain() {
      const copy = {
        mac: ['Wildbloom needs your keychain', 'Wildbloom keeps its keys in your login keychain. Allow access when macOS asks, then try again.'],
        windows: ['Wildbloom needs Credential Manager', 'Wildbloom keeps its keys in Windows Credential Manager. Try again, and if this keeps happening, restart your computer.'],
        linux: ['Wildbloom needs your keyring', 'Wildbloom keeps its keys in your keyring. Install or unlock GNOME Keyring or KWallet, then try again.'],
      }[platform.os];
      const message = h('p', { class: 'msg error', role: 'alert', hidden: true });
      show(heading(copy[0]), h('p', { class: 'body' }, copy[1]), message,
        h('button', { class: 'btn primary block', type: 'button', onclick: async () => {
          try {
            const status = await opts.refresh({ recheck: 'keychain' });
            if (disposed) return;
            if (status?.keychain === 'unavailable' || (first && status?.firstRun?.step === 'keychain')) {
              message.textContent = "Still can't reach it.";
              message.hidden = false;
              return;
            }
            if (first) {
              if (!status?.firstRun) return finish();
              go(status.firstRun.step === 'keychain' ? 'node' : status.firstRun.step);
            } else {
              go(opts.sequence[sequenceIndex]);
            }
          } catch (e) {
            message.textContent = e.message || "Still can't reach it.";
            message.hidden = false;
          }
        } }, 'Try again'), cancelButton());
    }

    return {
      get step() { return step; },
      start(name) {
        if (!first) sequenceIndex = 0;
        go(name || (first ? 'node' : opts.sequence[0]));
      },
      go,
      dispose() {
        disposed = true;
        generation++;
        recoveryKey = '';
        draft.key = '';
        if (waiting) call('cancel_approval').catch(() => {});
        host.replaceChildren();
      },
    };
  }

  /** Flow in a modal sheet. Resolves true when the flow finished, false when dismissed. */
  function openFlowSheet(options, opener) {
    return new Promise((resolve) => {
      let finished = false;
      const titleHost = h('div');
      const dialog = h('dialog', { class: `drop-scope${themeClass} flow-sheet`, 'aria-label': options.label || 'Wildbloom Drop' }, titleHost);
      const flow = createFlow(titleHost, {
        ...options,
        mode: 'sheet',
        onFinish: () => { finished = true; dialog.close(); },
        onCancel: () => dialog.close(),
      });
      showDialog(dialog, opener, () => { flow.dispose(); resolve(finished); });
      flow.start();
    });
  }

  window.WildbloomDrop = {
    h, call, listen, delay, uid, plural, icon, iconSlot, formatBytes, until, stamp, fullDate, shortNpub, hostOf,
    buttonRow, confirmDialog, confirmFolderOn, openFlowSheet, writeClipboard, readClipboard, openNodeSettings, popupMenu,
    platform, loadPlatform, middleTruncate, casing,
  };

  if (!isDropWindow) return;

  /* ====================================================================== */
  /* Drop window                                                             */
  /* ====================================================================== */

  const $ = (id) => document.getElementById(id);
  const el = {
    header: $('drop-header'), footer: $('drop-footer'),
    statusLine: $('status-line'), statusIcon: $('status-icon'), statusText: $('status-text'), statusAction: $('status-action'),
    viewFirst: $('view-first'), viewDrop: $('view-drop'),
    zone: $('zone'), zoneTitle: $('zone-title'), addFiles: $('add-files'), folderToggle: $('folder-toggle'),
    notices: $('notices'), find: $('find'), findInput: $('find-input'),
    listRegion: $('list-region'), files: $('files'), filesHeading: $('files-heading'), noMatch: $('no-match'),
    overlay: $('drag-overlay'), dragMessage: $('drag-message'), announcer: $('drop-announcer'),
    footerOnline: $('footer-online'), footerSettings: $('footer-settings'),
  };

  let state = {
    firstRun: null, node: 'ok', keychain: 'ok',
    online: { configured: false, url: '', reachable: true, failedChecks: 0, usedBytes: 0, limitBytes: 0, full: false },
    approval: { state: 'none' }, recovery: { confirmed: true }, watchFolder: { enabled: false, path: '' },
    limits: { dropMaxBytes: 1e9, shareMaxBytes: 250e6 }, browserApproval: false,
  };
  const rows = new Map();
  const rowEls = new Map();
  let flow = null;
  let loaded = false;
  let loadError = null;

  /* ---------- announcer: transitions only, batched, one message per 2 s ---------- */

  const announcer = { pending: [], timer: null, last: 0 };
  function say(message) {
    el.announcer.textContent = '';
    setTimeout(() => { el.announcer.textContent = message; }, 30);
  }
  function queueAnnouncement(kind, name) {
    announcer.pending.push({ kind, name });
    if (announcer.timer) return;
    const wait = Math.max(1000, announcer.last + 2000 - Date.now());
    announcer.timer = setTimeout(flushAnnouncements, wait);
  }
  function flushAnnouncements() {
    announcer.timer = null;
    const done = announcer.pending.filter((item) => item.kind === 'done').map((item) => item.name);
    const failed = announcer.pending.filter((item) => item.kind === 'failed').map((item) => item.name);
    announcer.pending = [];
    const parts = [];
    if (done.length) parts.push(done.length === 1 ? `${done[0]} now has 2 copies.` : `${done.length} files now have 2 copies.`);
    if (failed.length) parts.push(failed.length === 1 ? `${failed[0]} couldn't be copied online.` : `${failed.length} files couldn't be copied online.`);
    if (!parts.length) return;
    announcer.last = Date.now();
    say(parts.join(' '));
  }

  /* ---------- row model ---------- */

  const TWO_COPIES = new Set(['two_copies', 'shared', 'sharing_ended', 'stop_pending', 'share_owner_only']);
  const FAILED = new Set(['failed', 'missing_online']);
  const BUSY = new Set(['encrypting', 'queued', 'copying']);

  function notKeptReason(row) {
    switch (row.notKept) {
      case 'too_big': return `over ${formatBytes(state.limits.dropMaxBytes)}`;
      case 'name': return 'rename it to keep it';
      case 'too_long': return 'its folder path is too long';
      case 'too_deep': return "it's too many folders deep";
      default: return '';
    }
  }

  function describe(row) {
    const size = formatBytes(row.bytes);
    const added = row.added ? stamp(row.added) : '';
    const percent = Number.isFinite(row.progress) ? `${Math.round(row.progress)}%` : null;
    const meta = (text, cls) => ({ text, cls });
    switch (row.state) {
      case 'encrypting': return { icon: 'refresh', spin: true, tone: 'accent', lead: 'Encrypting', rest: percent ? [meta(percent)] : [], bar: true, bar_label: `Encrypting ${row.name}` };
      case 'queued': return { icon: 'ring', tone: 'muted', lead: '1 copy', rest: [meta('copying online next')] };
      case 'copying': return { icon: 'up', tone: 'accent', lead: 'Copying online', rest: percent ? [meta(percent)] : [], bar: true, bar_label: `Copying ${row.name} online` };
      case 'two_copies': return { icon: 'check', tone: 'success', lead: '2 copies', rest: [meta(size, 'col-size'), meta(added)] };
      case 'no_online': return { icon: 'ring', tone: 'muted', lead: '1 copy', rest: [meta('on this computer')] };
      case 'waiting': return { icon: 'pending', tone: 'muted', lead: '1 copy', rest: [meta('waiting for your online node')] };
      case 'failed': return { icon: 'alert', tone: 'warning', lead: '1 copy', rest: [meta('online copy failed')] };
      case 'missing_online': return { icon: 'alert', tone: 'warning', lead: '1 copy', rest: [meta('online copy missing')] };
      case 'online_full': return { icon: 'alert', tone: 'warning', lead: '1 copy', rest: [meta('online space full')] };
      case 'missing_local': return { icon: 'alert', tone: 'warning', lead: '1 copy', rest: [meta('online only')] };
      case 'restoring': return { icon: 'down', tone: 'accent', lead: 'Restoring', rest: percent ? [meta(percent)] : [], bar: true, bar_label: `Restoring ${row.name}` };
      case 'shared': return { icon: 'check', extra: 'share', tone: 'success', lead: '2 copies', rest: [meta(`shared until ${until(row.sharedUntil)}`)] };
      case 'stop_pending': return { icon: 'pending', tone: 'muted', lead: '2 copies', rest: [meta('removing shared copy when online')] };
      case 'sharing_ended': return { icon: 'check', tone: 'success', lead: '2 copies', rest: [meta(`sharing ended ${until(row.sharingEnded)}`)] };
      case 'share_owner_only': return { icon: 'alert', tone: 'warning', lead: '2 copies', rest: [meta('only your online node’s owner can remove the shared copy now')] };
      case 'not_kept': return { icon: 'alert', tone: 'warning', lead: 'Not kept', rest: [meta(notKeptReason(row))] };
      case 'unreadable': return { icon: 'alert', tone: 'error', lead: "Couldn't read this file. Check you can open it, then add it again.", rest: [] };
      default: return { icon: 'ring', tone: 'muted', lead: String(row.state || ''), rest: [] };
    }
  }

  const ITEM = {
    share: () => ({ id: 'share', text: casing('Share…', 'Share…') }),
    shareAgain: () => ({ id: 'share-again', text: casing('Share Again…', 'Share again…') }),
    retry: () => ({ id: 'retry', text: 'Retry' }),
    copyAgain: () => ({ id: 'copy-again', text: casing('Copy Again', 'Copy again') }),
    copyBack: () => ({ id: 'copy-back', text: casing('Copy Back', 'Copy back') }),
    stop: () => ({ id: 'stop', text: casing('Stop Sharing…', 'Stop sharing…') }),
    save: () => ({ id: 'save', text: casing('Save a Copy…', 'Save a copy…') }),
    remove: () => ({ id: 'remove', text: 'Remove…' }),
    open: () => ({ id: 'open', text: 'Open' }),
    reveal: () => ({ id: 'reveal', text: revealText() }),
  };
  function menuFor(row) {
    const items = baseMenuFor(row);
    // Linked rows have a file in the Wildbloom folder to open or show.
    if (row.inWatchFolder && row.state !== 'not_kept' && row.state !== 'unreadable') return [ITEM.open(), ITEM.reveal(), ...items];
    return items;
  }
  function baseMenuFor(row) {
    const online = state.online.configured;
    switch (row.state) {
      case 'encrypting': return [ITEM.remove()];
      case 'queued':
      case 'copying':
      case 'two_copies':
      case 'share_owner_only':
      case 'sharing_ended': return [online ? ITEM.share() : null, ITEM.save(), ITEM.remove()].filter(Boolean);
      case 'no_online':
      case 'waiting':
      case 'online_full': return [ITEM.save(), ITEM.remove()];
      case 'failed': return [ITEM.retry(), ITEM.save(), ITEM.remove()];
      case 'missing_online': return [ITEM.copyAgain(), ITEM.save(), ITEM.remove()];
      case 'missing_local': return [ITEM.copyBack(), ITEM.save(), ITEM.remove()];
      case 'shared': return [ITEM.shareAgain(), ITEM.stop(), ITEM.save(), ITEM.remove()];
      case 'stop_pending': return [ITEM.save()];
      case 'unreadable': return [ITEM.remove()];
      case 'not_kept': return [ITEM.reveal()];
      default: return [];
    }
  }
  const canShare = (row) => ['queued', 'copying', 'two_copies', 'sharing_ended', 'share_owner_only', 'shared'].includes(row.state) || row.state === 'no_online';
  function inlineAction(row) {
    switch (row.state) {
      case 'failed': return { label: 'Retry', aria: `Retry copying ${row.name}`, run: () => call('retry', { id: row.id }) };
      case 'missing_online': return { label: 'Copy again', aria: `Copy ${row.name} again`, run: () => call('retry', { id: row.id }) };
      case 'missing_local': return { label: 'Copy back', aria: `Copy ${row.name} back to this computer`, run: () => call('copy_back', { id: row.id }) };
      case 'unreadable': return { label: 'Remove', aria: `Remove ${row.name}`, run: () => call('remove', { id: row.id }) };
      default: return null;
    }
  }

  async function runRowAction(id, action, opener) {
    const row = rows.get(id);
    if (!row) return;
    try {
      if (action === 'share' || action === 'share-again') {
        if (window.WildbloomShare) window.WildbloomShare.open(row, opener, action === 'share-again', { limits: state.limits });
      } else if (action === 'retry' || action === 'copy-again') await call('retry', { id });
      else if (action === 'copy-back') await call('copy_back', { id });
      else if (action === 'save') {
        // Rust opens the save dialog; the page never names a path.
        const result = await call('save_copy', { id });
        if (result) notice(`Saved ${row.name} to ${result.folder || 'your computer'}.`);
      } else if (action === 'stop') {
        const yes = await confirmDialog({
          title: `Stop sharing ${row.name}?`,
          paragraphs: ['The shared copy is deleted. Anyone who hasn\'t downloaded it yet won\'t be able to. Anyone who already has it keeps their copy.'],
          confirmLabel: 'Stop sharing', opener,
        });
        if (yes) await call('stop_sharing', { id });
      } else if (action === 'open' || action === 'reveal') {
        try {
          await call(action === 'open' ? 'open_file' : 'reveal_file', { id });
        } catch (e) {
          if (e.code !== 'not_in_folder') throw e;
          notice("That file isn't in your Wildbloom folder.");
        }
      } else if (action === 'remove') {
        const paragraphs = state.watchFolder?.enabled
          ? [`${row.name} is removed from Wildbloom on all your computers. Copies in your Wildbloom folders go to the ${trashName()}. Its encrypted copies and key are deleted, which can't be undone.`]
          : ["Both copies and the key that unlocks them are deleted. This can't be undone. The original file on your computer isn't touched."];
        if (row.inWatchFolder && !state.watchFolder?.enabled) paragraphs.push("It stays in your Wildbloom folder, but Wildbloom won't keep copies of it.");
        const yes = await confirmDialog({ title: `Remove ${row.name} from Wildbloom?`, paragraphs, confirmLabel: 'Remove', opener });
        if (yes) await call('remove', { id });
      }
    } catch (e) {
      if (e.code === 'keychain_unavailable') state.keychain = 'unavailable';
      notice(e.message || "That didn't work. Try again.");
      renderStatusLine();
    }
  }

  /* ---------- rendering rows ---------- */

  function buildRow(row, animate) {
    const d = describe(row);
    const name = h('h3', { class: 'row-name', title: row.name, 'aria-label': row.name }, row.name);
    const actions = h('div', { class: 'row-actions' });
    const menu = menuFor(row);
    if (canShare(row)) {
      const noOnline = row.state === 'no_online';
      const describedBy = noOnline ? uid('why') : null;
      actions.append(h('button', {
        class: 'btn quiet', type: 'button', 'data-ctl': 'share', 'aria-label': `Share ${row.name}`,
        'aria-disabled': noOnline ? 'true' : null, 'aria-describedby': describedBy,
        onclick: (event) => {
          if (noOnline) { notice('Add your online node to share files.'); return; }
          runRowAction(row.id, row.state === 'shared' ? 'share-again' : 'share', event.currentTarget);
        },
      }, 'Share'));
      if (noOnline) actions.append(h('span', { id: describedBy, class: 'sr-only' }, 'Add your online node to share files.'));
    }
    const inline = inlineAction(row);
    if (inline) {
      actions.append(h('button', { class: 'btn quiet', type: 'button', 'data-ctl': 'inline', 'aria-label': inline.aria, onclick: () => inline.run().catch((e) => notice(e.message || "That didn't work. Try again.")) }, inline.label));
    }
    if (menu.length && row.state !== 'unreadable') {
      actions.append(h('button', {
        class: 'btn quiet icon', type: 'button', 'data-ctl': 'more', 'aria-label': `More actions for ${row.name}`, 'aria-haspopup': 'menu',
        onclick: (event) => openRowMenu(row.id, event.currentTarget),
      }, icon('more')));
    }
    const slot = iconSlot(d.icon, d.tone, d.spin ? 'spin' : '');
    if (animate) slot.classList.add('fade');
    if (d.extra === 'share') {
      slot.classList.add('multi');
      slot.append(icon('share'));
    }
    const status = h('p', { class: 'row-status' }, slot, h('span', { class: `lead tone-${d.tone}` }, d.lead));
    for (const part of d.rest) {
      if (!part.text) continue;
      status.append(h('span', { class: 'sep', 'aria-hidden': 'true' }, ' · '), h('span', { class: `plain ${part.cls || ''}` }, part.text));
    }
    const title = h('div', { class: 'row-title' }, name);
    if (row.folder) title.append(h('p', { class: 'row-folder' }, row.folder));
    const li = h('li', { class: 'row', 'data-id': row.id, 'data-state': row.state }, title, actions, status);
    if (d.bar) {
      li.append(h('progress', { max: '100', value: Number.isFinite(row.progress) ? String(Math.round(row.progress)) : null, 'aria-label': d.bar_label }));
    }
    return li;
  }

  function openRowMenu(id, anchor, point) {
    const row = rows.get(id);
    if (!row) return;
    const items = menuFor(row).map((item) => ({ ...item, run: () => runRowAction(id, item.id, anchor) }));
    popupMenu(items, anchor, point);
  }

  function upsertRow(row) {
    const before = rows.get(row.id);
    rows.set(row.id, row);
    if (before) {
      if (!TWO_COPIES.has(before.state) && TWO_COPIES.has(row.state)) queueAnnouncement('done', row.name);
      if (!FAILED.has(before.state) && FAILED.has(row.state)) queueAnnouncement('failed', row.name);
    }
    const existing = rowEls.get(row.id);
    const next = buildRow(row, Boolean(before) && before.state !== row.state);
    if (existing) {
      const focused = existing.contains(document.activeElement) ? document.activeElement.getAttribute('data-ctl') : null;
      if (before && before.state === row.state && BUSY.has(row.state) && before.name === row.name && existing.querySelector('progress')) {
        const bar = existing.querySelector('progress');
        const fresh = next.querySelector('progress');
        if (bar && fresh) {
          bar.value = fresh.value;
          const lead = existing.querySelector('.row-status');
          lead.replaceWith(next.querySelector('.row-status'));
          return layoutChanged();
        }
      }
      existing.replaceWith(next);
      rowEls.set(row.id, next);
      if (focused) next.querySelector(`[data-ctl="${focused}"]`)?.focus({ preventScroll: true }) || next.querySelector('[data-ctl]')?.focus({ preventScroll: true });
    } else {
      rowEls.set(row.id, next);
      el.files.append(next);
    }
    layoutChanged();
  }
  function removeRow(id) {
    rows.delete(id);
    const li = rowEls.get(id);
    if (li) {
      if (li.contains(document.activeElement)) {
        const sibling = li.nextElementSibling || li.previousElementSibling;
        li.remove();
        (sibling?.querySelector('[data-ctl]') || el.addFiles).focus({ preventScroll: true });
      } else li.remove();
    }
    rowEls.delete(id);
    layoutChanged();
  }
  function syncRows(list) {
    const ids = new Set(list.map((row) => row.id));
    for (const id of [...rows.keys()]) if (!ids.has(id)) removeRow(id);
    for (const row of list) {
      const existing = rows.get(row.id);
      const mine = existing && JSON.stringify(existing) === JSON.stringify(row);
      if (!mine) upsertRow(row);
    }
  }
  /** Two lines at most, then cut from the middle so the extension always stays visible. */
  function fitName(heading) {
    const full = heading.getAttribute('title') || '';
    heading.textContent = full;
    if (heading.offsetParent === null || full.length < 24) return;
    const limit = Math.round(parseFloat(getComputedStyle(heading).lineHeight) * 2) + 1;
    if (heading.scrollHeight <= limit) return;
    let low = 12;
    let high = full.length;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      heading.textContent = middleTruncate(full, mid);
      if (heading.scrollHeight <= limit) low = mid;
      else high = mid - 1;
    }
    heading.textContent = middleTruncate(full, low);
  }
  function fitNames() {
    for (const heading of el.files.querySelectorAll('.row-name')) fitName(heading);
  }
  let fitWidth = 0;
  function watchWidth() {
    // Names are fitted to the rendered font, so fit again once fonts settle.
    document.fonts?.ready.then(() => fitNames());
    document.fonts?.addEventListener?.('loadingdone', () => fitNames());
    window.addEventListener('load', () => fitNames());
    if (!window.ResizeObserver) return;
    new ResizeObserver(() => {
      const width = el.files.clientWidth;
      if (width === fitWidth) return;
      fitWidth = width;
      fitNames();
    }).observe(el.files);
  }
  function layoutChanged() {
    const sorted = [...rows.values()].sort((a, b) => (b.added || 0) - (a.added || 0));
    let previous = null;
    for (const row of sorted) {
      const li = rowEls.get(row.id);
      const wanted = previous ? previous.nextElementSibling : el.files.firstElementChild;
      if (li !== wanted) el.files.insertBefore(li, wanted);
      previous = li;
    }
    applyFilter();
    renderStatusLine();
    renderZone();
    renderFooter();
    fitNames();
  }
  function applyFilter() {
    const query = el.findInput.value.trim().toLowerCase();
    let shown = 0;
    for (const [id, li] of rowEls) {
      const match = !query || (rows.get(id)?.name || '').toLowerCase().includes(query);
      li.hidden = !match;
      if (match) shown++;
    }
    const finder = rows.size > 20;
    el.find.hidden = !finder;
    el.noMatch.hidden = !(finder && query && shown === 0);
    el.noMatch.textContent = el.noMatch.hidden ? '' : `No files match “${el.findInput.value.trim()}”.`;
    el.files.hidden = rows.size === 0;
    el.filesHeading.hidden = rows.size === 0;
    el.listRegion.hidden = rows.size === 0;
    if (query) fitNames();
  }

  /* ---------- status line (section 6.1) ---------- */

  function resolveStatus() {
    const failed = [...rows.values()].filter((row) => FAILED.has(row.state)).length;
    const notKept = [...rows.values()].filter((row) => row.state === 'not_kept').length;
    const count = rows.size - notKept;
    const copying = [...rows.values()].filter((row) => BUSY.has(row.state)).length;
    const nowSeconds = Date.now() / 1000;
    const approval = state.approval || {};
    if (loadError) return { id: 'load', icon: 'alert', tone: 'error', text: "Can't reach Wildbloom Node.", action: { label: 'Try again', run: () => refreshStatus() } };
    if (state.node !== 'ok') return { id: 'node', icon: 'alert', tone: 'error', text: 'Wildbloom Node has stopped.', action: { label: 'Open node settings', run: openNodeSettings } };
    if (state.keychain === 'unavailable') return { id: 'keychain', icon: 'alert', tone: 'error', text: "Wildbloom can't reach your keychain.", action: { label: 'Try again', run: () => refreshStatus({ recheck: 'keychain' }) } };
    if (state.watchFolder?.state === 'unavailable') return { id: 'folder-unavailable', icon: 'alert', tone: 'warning', text: "Your Wildbloom folder can't be found. Changes there are paused.", action: { label: 'Use folder again', run: async () => { await call('set_watch_folder', { enabled: true }); await refreshStatus(); } } };
    if (state.watchFolder?.state === 'too_many') return { id: 'folder-too-many', icon: 'alert', tone: 'warning', text: 'Your Wildbloom folder has more than 20,000 items. Changes there are paused.', action: null };
    if (approval.state === 'expired') return { id: 'expired', icon: 'alert', tone: 'warning', text: 'Approval for this computer has ended. New files stay on this computer.', action: { label: 'Approve again', run: (opener) => openFlowSheet({ sequence: ['approve'], renew: true, refresh: refreshStatus, browserApproval: state.browserApproval }, opener).then(refreshAfter) } };
    if (state.online.configured && (state.online.failedChecks || 0) > 2) return { id: 'unreachable', icon: 'alert', tone: 'warning', text: "Can't reach your online node. Files stay on this computer and copy when it's back.", action: { label: 'Try now', run: () => refreshStatus({ recheck: 'online' }) } };
    if (state.online.full) return { id: 'full', icon: 'alert', tone: 'warning', text: 'Your online space is full. New files stay on this computer.', action: { label: 'Settings', run: openNodeSettings } };
    if (failed > 0) return { id: 'failed', icon: 'alert', tone: 'warning', text: `${failed} ${plural(failed, 'file has', 'files have')} only 1 copy.`, action: { label: 'Retry all', run: () => call('retry', { id: null }) } };
    if (state.recovery && state.recovery.keyList === 'failed') return { id: 'keylist', icon: 'alert', tone: 'warning', text: "Wildbloom couldn't update the list it needs to restore your files. Your files are safe on this computer.", action: { label: 'Try again', run: () => refreshStatus({ recheck: 'keylist' }) } };
    if (notKept > 0) return { id: 'not-kept', icon: 'alert', tone: 'warning', text: `${notKept} ${plural(notKept, 'file', 'files')} in your Wildbloom folder can't be kept.`, action: null };
    if (copying > 0) return { id: 'copying', icon: 'up', tone: 'accent', text: `Copying ${copying} ${plural(copying, 'file', 'files')} to your online node`, action: null };
    if (!state.online.configured) return { id: 'no-online', icon: 'ring', tone: 'muted', text: 'Files have 1 copy, on this computer.', action: { label: 'Add online node', run: (opener) => openFlowSheet({ sequence: ['node', 'approve'], refresh: refreshStatus, browserApproval: state.browserApproval }, opener).then(refreshAfter) } };
    if (approval.state === 'active' && approval.until && approval.until - nowSeconds < 30 * 86400) return { id: 'ends', icon: 'ring', tone: 'warning', text: `Approval for this computer ends on ${fullDate(approval.until)}.`, action: { label: 'Renew', run: (opener) => openFlowSheet({ sequence: ['approve'], renew: true, refresh: refreshStatus, browserApproval: state.browserApproval }, opener).then(refreshAfter) } };
    if (state.recovery && state.recovery.confirmed === false) return { id: 'recovery', icon: 'alert', tone: 'warning', text: "Your recovery key isn't saved yet.", action: { label: 'Save it', run: (opener) => openFlowSheet({ sequence: ['recovery'], resave: false, refresh: refreshStatus }, opener).then(refreshAfter) } };
    if (count >= 1) return { id: 'good', icon: 'check', tone: 'success', text: count === 1 ? 'Your file has 2 copies.' : `All ${count} files have 2 copies.`, action: null };
    return { id: 'empty', icon: 'ring', tone: 'muted', text: 'No files yet', action: null };
  }
  const refreshAfter = () => refreshStatus();
  let statusAction = null;
  function renderStatusLine() {
    if (state.firstRun) return;
    const status = resolveStatus();
    el.statusLine.dataset.status = status.id;
    el.statusIcon.replaceChildren(icon(status.icon, status.icon === 'refresh' ? 'spin' : ''));
    el.statusIcon.className = `icon-slot tone-${status.tone}`;
    if (el.statusText.textContent !== status.text) el.statusText.textContent = status.text;
    statusAction = status.action;
    el.statusAction.hidden = !status.action;
    if (status.action) el.statusAction.textContent = status.action.label;
  }

  function renderZone() {
    const empty = rows.size === 0;
    el.zone.classList.toggle('empty', empty);
    const folder = state.watchFolder || {};
    el.folderToggle.textContent = folder.enabled ? 'Open your Wildbloom folder' : 'Turn on your Wildbloom folder';
  }
  function renderFooter() {
    const online = state.online;
    el.footerOnline.textContent = online.configured ? `Online: ${formatBytes(online.usedBytes)} of ${formatBytes(online.limitBytes)} used` : 'Online: not set up';
  }

  function notice(text) {
    el.notices.replaceChildren(h('p', {}, text));
  }
  function clearNotices() {
    el.notices.replaceChildren();
  }
  function handleAddResult(result) {
    clearNotices();
    if (!result) return;
    const lines = [];
    for (const item of result.refused || []) {
      if (item.reason === 'folder') lines.push("Folders can't be added yet. Drop the files inside, or zip the folder first.");
      else if (item.reason === 'too_big') lines.push(`${item.name} is over ${formatBytes(item.limitBytes || state.limits.dropMaxBytes)} and can't be added yet.`);
      else if (item.reason === 'no_space') lines.push(`Not enough space on this computer for ${item.name}.`);
      else lines.push(`Couldn't add ${item.name}.`);
    }
    for (const item of result.duplicates || []) {
      lines.push(`${item.name} is already kept.`);
      flash(item.id);
    }
    const unique = [...new Set(lines)];
    if (unique.length) el.notices.replaceChildren(...unique.map((line) => h('p', {}, line)));
  }
  function flash(id) {
    const li = rowEls.get(id);
    if (!li) return;
    li.classList.remove('flash');
    void li.offsetWidth;
    li.classList.add('flash');
    li.addEventListener('animationend', () => li.classList.remove('flash'), { once: true });
  }
  async function addPaths(paths) {
    if (!paths || !paths.length) return;
    try {
      handleAddResult(await call('add_paths', { paths }));
    } catch (e) {
      if (e.code === 'keychain_unavailable') { state.keychain = 'unavailable'; renderStatusLine(); }
      else notice(e.message || "Couldn't add those files.");
    }
  }
  async function pickFiles() {
    if (state.firstRun) return;
    try {
      handleAddResult(await call('pick_files'));
    } catch (e) {
      if (e.code === 'keychain_unavailable') { state.keychain = 'unavailable'; renderStatusLine(); }
      else notice(e.message || "Couldn't add those files.");
    }
  }

  /* ---------- status snapshot, first run ---------- */

  function mergeStatus(next) {
    const { files, ...rest } = next;
    state = { ...state, ...rest };
    return files;
  }
  async function refreshStatus(args) {
    try {
      const snapshot = await call('drop_status', args);
      loadError = null;
      const files = mergeStatus(snapshot);
      loaded = true;
      render();
      if (files) syncRows(files);
      return state;
    } catch (e) {
      if (!loaded) { loadError = e; render(); }
      throw e;
    }
  }
  function render() {
    const first = state.firstRun;
    el.viewFirst.hidden = !first;
    el.viewDrop.hidden = Boolean(first);
    el.header.hidden = Boolean(first);
    el.footer.hidden = Boolean(first);
    if (first) {
      if (!flow) {
        flow = createFlow(el.viewFirst, { mode: 'first', refresh: refreshStatus, browserApproval: state.browserApproval, nodeSettingsExist: first.nodeSettingsExist, url: state.online?.url || '' });
        flow.start(first.step === 'keychain' ? 'keychain' : first.step);
      } else if (first.step === 'keychain' && flow.step !== 'keychain') flow.go('keychain');
      return;
    }
    if (flow) {
      flow.dispose();
      flow = null;
    }
    renderStatusLine();
    renderZone();
    renderFooter();
    applyFilter();
  }

  /* ---------- drag and drop ---------- */

  let dragging = false;
  function overlayAllowed() {
    return !state.firstRun && !document.querySelector('dialog[open]');
  }
  function showOverlay(kind) {
    el.overlay.classList.toggle('refuse', kind !== 'ok');
    el.overlay.classList.add('on');
    const limit = formatBytes(state.limits.dropMaxBytes);
    const text = kind === 'folder' ? "Folders can't be added yet" : kind === 'big' ? `Too big to add: over ${limit}` : 'Drop to keep 2 copies';
    el.dragMessage.replaceChildren(kind === 'ok' ? '' : icon('refuse'), text);
  }
  function hideOverlay() {
    dragging = false;
    el.overlay.classList.remove('on');
  }
  function bindDrag() {
    listen('tauri://drag-enter', () => {
      if (!overlayAllowed()) return;
      dragging = true;
      showOverlay('ok');
    });
    listen('drop://drag-info', (info) => {
      if (!dragging) return;
      const files = info.files || 0;
      const folders = info.folders || 0;
      if (files === 0 && folders > 0) showOverlay('folder');
      else if (files > 0 && folders === 0 && (info.tooBig || 0) >= files) showOverlay('big');
      else showOverlay('ok');
    });
    listen('tauri://drag-leave', hideOverlay);
    listen('tauri://drag-drop', (event) => {
      const wasDragging = dragging;
      hideOverlay();
      if (wasDragging || overlayAllowed()) addPaths(event.paths);
    });
    for (const type of ['dragover', 'drop']) document.addEventListener(type, (event) => event.preventDefault());
  }

  /* ---------- keyboard ---------- */

  function visibleRows() {
    return [...el.files.children].filter((li) => !li.hidden);
  }
  function focusControl(li, ctl) {
    const target = li.querySelector(`[data-ctl="${ctl}"]`) || li.querySelector('[data-ctl="share"]') || li.querySelector('[data-ctl]');
    if (target) {
      target.focus();
      target.scrollIntoView({ block: 'nearest' });
    }
  }
  function onListKeydown(event) {
    const control = event.target.closest?.('[data-ctl]');
    if (!control || event.altKey || event.ctrlKey || event.metaKey) return;
    const list = visibleRows();
    const index = list.indexOf(control.closest('li'));
    if (index < 0) return;
    const ctl = control.getAttribute('data-ctl');
    let target = null;
    if (event.key === 'ArrowDown') target = list[Math.min(index + 1, list.length - 1)];
    else if (event.key === 'ArrowUp') target = list[Math.max(index - 1, 0)];
    else if (event.key === 'Home') target = list[0];
    else if (event.key === 'End') target = list[list.length - 1];
    if (!target) return;
    event.preventDefault();
    focusControl(target, ctl);
  }
  function onKeydown(event) {
    const mod = platform.os === 'mac' ? event.metaKey && !event.ctrlKey : event.ctrlKey && !event.metaKey;
    const key = event.key.length === 1 ? event.key.toLowerCase() : event.key;
    if (event.key === 'F5' || (mod && key === 'r')) {
      event.preventDefault();
      return;
    }
    if (!mod || event.altKey) return;
    const modal = document.querySelector('dialog[open]');
    if (key === ',') {
      event.preventDefault();
      openNodeSettings();
    } else if (modal || state.firstRun) {
      /* the rest only apply to the list */
    } else if (key === 'o' && !event.shiftKey) {
      event.preventDefault();
      pickFiles();
    } else if (key === 'o' && event.shiftKey && state.watchFolder?.enabled) {
      event.preventDefault();
      call('open_watch_folder').catch(() => {});
    } else if (key === 's' && event.shiftKey) {
      const li = document.activeElement?.closest?.('li.row');
      const button = li?.querySelector('[data-ctl="share"]');
      if (button) {
        event.preventDefault();
        button.click();
      }
    } else if (key === 'f' && !el.find.hidden) {
      event.preventDefault();
      el.findInput.focus();
      el.findInput.select();
    }
  }

  /* ---------- start ---------- */

  function bind() {
    el.addFiles.addEventListener('click', pickFiles);
    el.folderToggle.addEventListener('click', async () => {
      try {
        if (state.watchFolder?.enabled) await call('open_watch_folder');
        else {
          if (!(await confirmFolderOn(el.folderToggle))) return;
          await call('set_watch_folder', { enabled: true });
          await refreshStatus();
        }
      } catch (e) {
        notice(e.message || "That didn't work. Try again.");
      }
    });
    el.statusAction.addEventListener('click', async (event) => {
      if (!statusAction) return;
      try {
        await statusAction.run(event.currentTarget);
      } catch (e) {
        notice(e.message || "That didn't work. Try again.");
      }
    });
    el.footerSettings.addEventListener('click', openNodeSettings);
    el.findInput.addEventListener('input', applyFilter);
    el.files.addEventListener('keydown', onListKeydown);
    el.files.addEventListener('contextmenu', (event) => {
      const li = event.target.closest?.('li.row');
      if (!li) return;
      event.preventDefault();
      openRowMenu(li.getAttribute('data-id'), li.querySelector('[data-ctl="more"]'), { x: event.clientX, y: event.clientY });
    });
    document.addEventListener('contextmenu', (event) => {
      const target = event.target;
      const text = target.closest?.('input[type="text"], input:not([type]), textarea, [contenteditable]');
      if (!text && !event.defaultPrevented) event.preventDefault();
    });
    document.addEventListener('keydown', onKeydown);
    window.addEventListener('focus', () => { if (loaded && !state.firstRun) renderStatusLine(); });
    bindDrag();
    watchWidth();
  }

  async function start() {
    bind();
    applyPlatform();
    listen('drop://file', (payload) => {
      if (!payload) return;
      if (payload.removed) removeRow(payload.id);
      else upsertRow(payload);
    });
    listen('drop://status', (payload) => {
      if (!payload) return;
      mergeStatus(payload);
      render();
    });
    listen('drop://open-flow', (payload) => {
      // The node window's "Save recovery key again…" opens here: only this
      // window may read the recovery key.
      if (payload && payload.flow === 'recovery' && !state.firstRun && !document.querySelector('dialog[open]')) {
        openFlowSheet({ sequence: ['recovery'], resave: state.recovery?.confirmed !== false, label: 'Recovery key', refresh: refreshStatus }, el.footerSettings).then(refreshAfter);
      }
    });
    listen('drop://notice', (payload) => {
      if (payload && payload.kind === 'keeps_running') notice('Wildbloom keeps running. Open it again from your apps.');
    });
    await loadPlatform();
    try {
      await refreshStatus();
    } catch {
      /* the status line shows the failure */
    }
  }
  start();
})();
