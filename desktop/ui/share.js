// Wildbloom Drop, Share sheet. A view over Rust state: the shared copy, the
// pairing and the words all live in Rust; this file only draws share://state
// payloads and sends the owner's choices back. No crypto, no network.
(() => {
  'use strict';
  const D = window.WildbloomDrop;
  if (!D) return;
  const { h, call, listen, uid, icon, iconSlot, until, buttonRow, confirmDialog, writeClipboard } = D;

  let current = null;

  const ENDED = new Set(['expired', 'wrong_words', 'mismatch', 'left']);
  const LIVE = new Set(['ready', 'opened', 'check']);

  function clock(seconds) {
    const total = Math.max(0, Math.ceil(seconds));
    return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`;
  }

  function open(row, opener, again, context) {
    if (current) return;
    const titleId = uid('share-title');
    const heading = h('h2', { id: titleId, tabindex: '-1' }, `Share ${row.name}`);
    const top = h('div', { class: 'share-top' });
    const statusSlot = h('div', { role: 'status', class: 'share-slot' });
    const bottom = h('div', { class: 'share-bottom' });
    const live = h('div', { class: 'sr-only', role: 'status', 'aria-live': 'polite' });
    const dialog = h('dialog', { class: 'drop-scope sheet', 'aria-labelledby': titleId }, h('div', { class: 'sheet-body' }, heading, top, statusSlot, bottom, live));
    const session = {
      row, opener, dialog, heading, top, statusSlot, bottom, live,
      payload: null, started: false, timer: null, announced: new Set(), copyTimers: new Set(),
      limit: context?.limits?.shareMaxBytes || 250e6,
    };
    current = session;

    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      requestClose(session);
    });
    dialog.addEventListener('close', () => {
      clearInterval(session.timer);
      for (const timer of session.copyTimers) clearTimeout(timer);
      dialog.remove();
      if (current === session) current = null;
      const target = document.querySelector(`li.row[data-id="${CSS.escape(row.id)}"] [data-ctl="share"]`);
      const back = target || (opener && opener.isConnected ? opener : null);
      if (back) back.focus({ preventScroll: true });
    });
    document.body.append(dialog);
    dialog.showModal();
    heading.focus({ preventScroll: true });

    if (row.bytes > session.limit) {
      render(session, { id: row.id, state: 'too_big' });
      return;
    }
    session.started = true;
    call(again ? 'share_again' : 'share_start', { id: row.id })
      .then((payload) => { if (current === session && payload && !session.payload) render(session, { id: row.id, ...payload }); })
      .catch((error) => {
        if (current === session) render(session, { id: row.id, state: error.code === 'node_unreachable' ? 'node_unreachable' : 'relay_unreachable' });
      });
  }

  function requestClose(session) {
    const state = session.payload?.state;
    if (session.started && state !== 'sent' && state !== 'too_big') {
      call('share_cancel', { id: session.row.id }).catch(() => {});
    }
    session.dialog.close();
  }

  function say(session, message) {
    session.live.textContent = '';
    setTimeout(() => { session.live.textContent = message; }, 30);
  }

  function statusLine(session, tone, iconName, text, withTime) {
    const line = h('p', { class: `share-status` }, iconSlot(iconName, tone, iconName === 'refresh' ? 'spin' : ''), h('span', {}, text));
    const nodes = [line];
    if (withTime) nodes.push(h('p', { class: 'share-time', 'aria-hidden': 'true', 'data-time': true }, ''));
    session.statusSlot.replaceChildren(...nodes);
  }

  function button(label, kind, key, onclick, primary) {
    return h('button', { class: `btn ${kind}`, type: 'button', 'data-key': key, 'data-primary': primary ? 'true' : null, onclick }, label);
  }

  function copyButton(session, label, key, text, doneMessage) {
    const node = button(label, key === 'copy-link' ? 'secondary' : 'quiet', key, async () => {
      const ok = await writeClipboard(text);
      node.textContent = ok ? 'Copied' : "Couldn't copy";
      if (ok) say(session, doneMessage);
      const timer = setTimeout(() => { node.textContent = label; session.copyTimers.delete(timer); }, 2000);
      session.copyTimers.add(timer);
    });
    return node;
  }

  function stepLink(session, p) {
    const titleId = uid('step');
    const input = h('input', { class: 'field mono', type: 'text', readonly: true, tabindex: '-1', 'aria-labelledby': titleId, onfocus: (event) => event.target.select() });
    input.value = p.link || '';
    return h('section', { class: 'share-step', 'aria-labelledby': titleId },
      h('p', { class: 'step-title', id: titleId }, h('span', { class: 'num', 'aria-hidden': 'true' }, '1'), h('span', {}, 'Send them this link')),
      h('div', { class: 'step-body' }, input, copyButton(session, 'Copy link', 'copy-link', p.link || '', 'Link copied.')));
  }
  function stepWords(session, p) {
    const titleId = uid('step');
    const words = p.words || [];
    return h('section', { class: 'share-step', 'aria-labelledby': titleId },
      h('p', { class: 'step-title', id: titleId }, h('span', { class: 'num', 'aria-hidden': 'true' }, '2'), h('span', {}, 'Phone them and read out these words')),
      h('div', { class: 'step-body' },
        h('ol', { class: 'words', 'aria-label': `Words to read out: ${words.join(', ')}` }, words.map((word) => h('li', {}, word))),
        copyButton(session, 'Copy words', 'copy-words', words.join(' '), 'Words copied.'),
        h('p', { class: 'share-hint' }, "Don't send the words with the link. Anyone with both can get the file.")));
  }
  function stepCheck(p) {
    const titleId = uid('step');
    const words = p.checkWords || [];
    return h('section', { class: 'share-step', 'aria-labelledby': titleId },
      h('p', { class: 'step-title', id: titleId }, h('span', { class: 'num', 'aria-hidden': 'true' }, '3'), h('span', {}, 'Read these words to them')),
      h('div', { class: 'step-body' },
        h('ol', { class: 'words', 'aria-label': `Check words to read out: ${words.join(', ')}` }, words.map((word) => h('li', {}, word))),
        h('p', { class: 'share-hint' }, 'Ask if they see the same 3 words.')));
  }

  function render(session, p) {
    const previous = session.payload?.state;
    session.payload = p;
    const { row, dialog, heading } = session;
    const focusedKey = dialog.contains(document.activeElement) ? document.activeElement.getAttribute?.('data-key') : null;
    const hadFocusInside = dialog.contains(document.activeElement) && document.activeElement !== heading && document.activeElement !== dialog;

    // Progress ticks update in place so nothing is rebuilt or re-announced.
    if (p.state === 'preparing' && previous === 'preparing') {
      const bar = session.top.querySelector('progress');
      if (bar) bar.value = Math.round(p.progress || 0);
      const text = session.statusSlot.querySelector('.share-status span:last-child');
      if (text) text.textContent = progressText(p);
      return;
    }

    clearInterval(session.timer);
    session.timer = null;
    heading.textContent = p.state === 'sent' ? 'Sent' : `Share ${row.name}`;
    const links = () => [stepLink(session, p), stepWords(session, p)];
    const close = () => button('Close', 'secondary', 'close', () => requestClose(session));
    const startAgain = () => button('Start again', 'primary', 'start-again', () => restart('share_again'), true);
    const tryAgain = () => button('Try again', 'primary', 'try-again', () => restart('share_start'), true);
    const restart = (command) => {
      session.payload = null;
      session.announced.clear();
      render(session, { id: row.id, state: 'preparing', progress: 0 });
      call(command, { id: row.id })
        .then((next) => { if (current === session && next && session.payload?.state === 'preparing') render(session, { id: row.id, ...next }); })
        .catch((error) => { if (current === session) render(session, { id: row.id, state: error.code === 'node_unreachable' ? 'node_unreachable' : 'relay_unreachable' }); });
    };

    let topNodes = [];
    let bottomNodes = [];
    switch (p.state) {
      case 'too_big':
        statusLine(session, 'warning', 'alert', "Files over 250 MB can't be shared yet.");
        bottomNodes = [buttonRow(close())];
        break;
      case 'preparing':
        statusLine(session, 'accent', 'refresh', progressText(p));
        topNodes = [h('progress', { max: '100', value: String(Math.round(p.progress || 0)), 'aria-label': `Making a copy of ${row.name} to share` })];
        bottomNodes = [buttonRow(button('Cancel', 'secondary', 'cancel', () => requestClose(session)))];
        break;
      case 'ready':
      case 'opened':
      case 'check':
        topNodes = links();
        if (p.state === 'check') topNodes.push(stepCheck(p));
        if (p.state === 'ready') statusLine(session, 'muted', 'pending', 'Waiting for them to open the link', true);
        else if (p.state === 'opened') statusLine(session, 'accent', 'check', "They've opened the link.", true);
        else statusLine(session, 'accent', 'check', "They've opened the link.", true);
        if (p.state === 'check') {
          const match = button('They match, send file', 'primary', 'match', () => verify(session, true), true);
          const differ = button("They don't match", 'secondary', 'no-match', () => verify(session, false));
          bottomNodes = [buttonRow(match, differ)];
        } else {
          bottomNodes = [buttonRow(button('Cancel', 'secondary', 'cancel', () => requestClose(session)))];
        }
        break;
      case 'wrong_words':
        if (p.triesLeft > 0) {
          topNodes = links();
          statusLine(session, 'warning', 'alert', `They typed the wrong words. They can try ${p.triesLeft} more ${p.triesLeft === 1 ? 'time' : 'times'}.`, true);
          bottomNodes = [buttonRow(button('Cancel', 'secondary', 'cancel', () => requestClose(session)))];
        } else {
          statusLine(session, 'warning', 'alert', 'Someone typed the wrong words, so this link stopped working. Check you read them clearly.');
          bottomNodes = [buttonRow(startAgain(), close())];
        }
        break;
      case 'sending':
        statusLine(session, 'accent', 'refresh', 'Sending…');
        bottomNodes = [buttonRow(button('Cancel', 'secondary', 'cancel', () => requestClose(session)))];
        break;
      case 'sent': {
        statusLine(session, 'success', 'check', `They can download ${row.name} now.`);
        const when = p.deleteAt ? until(p.deleteAt) : null;
        topNodes = [
          h('p', {}, when ? `Wildbloom deletes the shared copy at ${when}, or sooner if you stop sharing. This computer needs to be on to delete it.` : 'Wildbloom deletes the shared copy after 24 hours, or sooner if you stop sharing. This computer needs to be on to delete it.'),
          h('p', { class: 'share-hint' }, "Stopping can't take back a copy they've already downloaded."),
        ];
        const done = button('Done', 'primary', 'done', () => requestClose(session), true);
        const stop = button('Stop sharing…', 'secondary', 'stop', async (event) => {
          const yes = await confirmDialog({
            title: `Stop sharing ${row.name}?`,
            paragraphs: ["The shared copy is deleted. Anyone who hasn't downloaded it yet won't be able to. Anyone who already has it keeps their copy."],
            confirmLabel: 'Stop sharing', opener: event.currentTarget,
          });
          if (!yes) return;
          try {
            await call('stop_sharing', { id: row.id });
          } catch { /* the row shows a pending state */ }
          session.dialog.close();
        });
        bottomNodes = [buttonRow(done, stop)];
        break;
      }
      case 'expired':
        statusLine(session, 'warning', 'alert', 'The link ran out of time before they connected.');
        bottomNodes = [buttonRow(startAgain(), close())];
        break;
      case 'mismatch':
        statusLine(session, 'warning', 'alert', "Sharing stopped because the words didn't match. Nothing was sent.");
        bottomNodes = [buttonRow(startAgain(), close())];
        break;
      case 'left':
        statusLine(session, 'warning', 'alert', 'They left before the file was sent.');
        bottomNodes = [buttonRow(startAgain(), close())];
        break;
      case 'relay_unreachable':
        statusLine(session, 'warning', 'alert', "Can't reach the sharing service. Check your internet connection.");
        bottomNodes = [buttonRow(tryAgain(), close())];
        break;
      case 'node_unreachable':
        statusLine(session, 'warning', 'alert', "Can't reach your online node, so the shared copy couldn't be made.");
        bottomNodes = [buttonRow(tryAgain(), close())];
        break;
      default:
        statusLine(session, 'warning', 'alert', "Sharing stopped. Nothing was sent.");
        bottomNodes = [buttonRow(close())];
    }
    session.top.replaceChildren(...topNodes);
    session.bottom.replaceChildren(...bottomNodes);
    // After a send the confirmation leads; otherwise the status follows the steps.
    if (p.state === 'sent') session.top.before(session.statusSlot);
    else session.top.after(session.statusSlot);

    if (LIVE.has(p.state) || (p.state === 'wrong_words' && p.triesLeft > 0)) startCountdown(session, p);

    // Focus: keep it where it was when that control survives; otherwise move it to the primary action.
    const same = focusedKey ? dialog.querySelector(`[data-key="${CSS.escape(focusedKey)}"]`) : null;
    if (same) same.focus({ preventScroll: true });
    else if (hadFocusInside || (document.activeElement === document.body)) {
      (session.bottom.querySelector('[data-primary]') || session.bottom.querySelector('button') || heading).focus({ preventScroll: true });
    }
  }

  function progressText(p) {
    return Number.isFinite(p.progress) ? `Making a copy to share · ${Math.round(p.progress)}%` : 'Making a copy to share';
  }

  async function verify(session, matches) {
    try {
      const next = await call('share_verify', { id: session.row.id, matches });
      if (current === session && next && next.state && session.payload?.state === 'check') render(session, { id: session.row.id, ...next });
    } catch (error) {
      if (current === session) render(session, { id: session.row.id, state: 'relay_unreachable' });
    }
  }

  function startCountdown(session, p) {
    const expiresAt = p.expiresAt;
    if (!Number.isFinite(expiresAt)) return;
    const tick = () => {
      const remaining = expiresAt - Date.now() / 1000;
      const node = session.statusSlot.querySelector('[data-time]');
      if (node) node.textContent = `${clock(remaining)} left`;
      if (remaining <= 120 && remaining > 60 && !session.announced.has(120)) {
        session.announced.add(120);
        say(session, '2 minutes left.');
      }
      if (remaining <= 60 && remaining > 0 && !session.announced.has(60)) {
        session.announced.add(60);
        say(session, '1 minute left.');
      }
    };
    tick();
    session.timer = setInterval(tick, 1000);
  }

  listen('share://state', (payload) => {
    if (!payload || !current || payload.id !== current.row.id) return;
    render(current, payload);
  });

  window.WildbloomShare = { open };
})();
