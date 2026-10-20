// Wildbloom Drop, Receive sheet: someone's phone sends one file straight to
// this computer. A view over Rust state: the pairing, the words, the transfer
// and the file all live in Rust; this file only draws receive://state payloads
// and sends the owner's choices back. No crypto, no network.
//
// Closing the sheet never ends a receive (Rust owns it). Only Cancel and Stop
// call receive_cancel, and reopening the sheet shows where the receive is.
(() => {
  'use strict';
  const D = window.WildbloomDrop;
  const S = window.WildbloomShare;
  if (!D || !S || !S.parts) return;
  const { h, call, uid, formatBytes, buttonRow, confirmFolderOn, revealText } = D;
  const { statusLine, button, stepLink, stepWords, stepCheck, startCountdown } = S.parts;

  let current = null;
  // A finished receive stays on show until the sheet has been closed on it once; then the entry starts a new one.
  let dismissedFinal = false;

  const LIVE = new Set(['preparing', 'waiting', 'opened', 'check', 'waiting_file', 'consent', 'connecting', 'receiving', 'verifying']);
  const FINAL = new Set(['kept', 'declined', 'cancelled', 'failed']);
  const COUNTING = new Set(['waiting', 'opened', 'check']);
  const WORDS_HINT = "Don't send the words with the link. Anyone with both could send you a file.";

  /** Why a receive failed, in plain words. Every line says what became of the file. */
  function failureText(reason, context) {
    const limit = formatBytes(context?.receiving?.maxBytes || 250e6);
    switch (reason) {
      case 'node_unreachable': return "Can't reach your online node, or this computer isn't approved there. Nothing was received.";
      case 'no_turn': return "Your online node can't help with direct transfers yet, so it can't receive files this way.";
      case 'turn_refused': return 'Your online node refused to set up the transfer. Nothing was received.';
      case 'turn_limit': return 'Too many tries this hour. Try again later.';
      case 'relay_unreachable': return "Can't reach the sharing service. Check your internet connection.";
      case 'expired': return 'The link ran out of time before they sent a file.';
      case 'wrong_words': return 'Someone opened the link with the wrong words, so it stopped working. Start again for a new link.';
      case 'mismatch': return "The 3 words didn't match, so nothing was sent.";
      case 'too_big': return `Their file is over ${limit}, so Drop didn't take it.`;
      case 'unsupported': return "Their browser can't connect this way. If you hide your address, try turning that off in Settings.";
      case 'protocol': return 'Something unexpected arrived, so the transfer stopped. Nothing was kept.';
      case 'peer_failed': return 'Their side ran into a problem. Nothing was kept.';
      case 'peer_storage': return "Their device ran out of room, so the transfer stopped. Nothing was kept.";
      case 'connect': return "This computer and theirs couldn't connect. Nothing was kept.";
      case 'lost': return "The connection was lost and couldn't be restored. Nothing was kept.";
      case 'verification': return "The file didn't check out, so Drop threw it away. Nothing was kept.";
      case 'storage': return "There isn't enough room on this computer. Nothing was kept.";
      case 'no_relay': return "Hiding your address needs your online node, and it wasn't available. You can turn this off in Settings.";
      case 'webview': return "Drop couldn't set up the connection on this computer. Nothing was kept.";
      default: return 'Something went wrong. Nothing was kept.';
    }
  }
  const endedText = (p, context) => (p.state === 'failed' ? failureText(p.reason, context)
    : p.state === 'declined' ? 'You said no. Nothing was sent.'
      : p.by === 'them' ? 'They closed the page. Nothing was kept.' : 'Stopped. Nothing was kept.');

  /**
   * The extension the kept file will have, as Drop names it in the Received folder (`received::candidate`): the last
   * `.xxx` unless the dot is the first character, and none when it is too long to leave room for a name. Shown on its
   * own line, so a long or odd name cannot hide what kind of file it is.
   */
  function extensionOf(name) {
    if (typeof name !== 'string') return '';
    const at = name.lastIndexOf('.');
    if (at <= 0) return '';
    const ext = name.slice(at);
    return ext.length >= 90 ? '' : ext;
  }

  const percentOf = (p) => (p.total > 0 ? Math.max(0, Math.min(99, Math.floor((p.acknowledged / p.total) * 100))) : 0);

  function open(opener, context, initial) {
    if (current) return;
    const titleId = uid('receive-title');
    const heading = h('h2', { id: titleId, tabindex: '-1' }, 'Receive a file');
    const top = h('div', { class: 'share-top' });
    const statusSlot = h('div', { role: 'status', class: 'share-slot' });
    const bottom = h('div', { class: 'share-bottom' });
    const live = h('div', { class: 'sr-only', role: 'status', 'aria-live': 'polite' });
    const dialog = h('dialog', { class: 'drop-scope sheet receive', 'aria-labelledby': titleId }, h('div', { class: 'sheet-body' }, heading, statusSlot, top, bottom, live));
    const session = {
      context, opener, dialog, heading, top, statusSlot, bottom, live,
      payload: null, timer: null, announced: new Set(), copyTimers: new Set(), heard: false, added: null, addNote: '',
    };
    current = session;

    // Escape and closing only hide the sheet. The receive carries on.
    dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      dialog.close();
    });
    dialog.addEventListener('close', () => {
      clearInterval(session.timer);
      for (const timer of session.copyTimers) clearTimeout(timer);
      if (FINAL.has(session.payload?.state)) dismissedFinal = true;
      dialog.remove();
      if (current === session) current = null;
      if (opener && opener.isConnected) opener.focus({ preventScroll: true });
    });
    document.body.append(dialog);
    dialog.showModal();
    heading.focus({ preventScroll: true });

    if (initial) {
      render(session, initial);
      return;
    }
    call('receive_state')
      .then((next) => {
        if (current !== session || session.heard) return;
        const shown = next && (LIVE.has(next.state) || (FINAL.has(next.state) && !dismissedFinal));
        if (shown) render(session, next);
        else start(session);
      })
      .catch(() => { if (current === session && !session.heard) start(session); });
  }

  function start(session) {
    session.added = null;
    session.addNote = '';
    session.announced.clear();
    dismissedFinal = false;
    render(session, { state: 'preparing' });
    call('receive_start')
      .then((next) => {
        if (current !== session || !next || session.heard) return;
        if (!session.payload || session.payload.state === 'preparing') render(session, next);
      })
      .catch((error) => {
        if (current !== session) return;
        if (error && error.code === 'busy') {
          call('receive_state').then((next) => { if (current === session && next && next.state !== 'idle') render(session, next); }).catch(() => {});
          return;
        }
        render(session, { state: 'failed', reason: error && error.code === 'node_unreachable' ? 'node_unreachable' : 'relay_unreachable' });
      });
  }

  function say(session, message) {
    session.live.textContent = '';
    setTimeout(() => { session.live.textContent = message; }, 30);
  }

  /** Cancel (before the file starts) and Stop (once it is on its way) end the receive. */
  function stopButton(label) {
    return button(label, 'secondary', 'cancel', async (event) => {
      event.currentTarget.disabled = true;
      try {
        await call('receive_cancel');
      } catch {
        event.currentTarget.disabled = false;
      }
    });
  }

  /** The owner's one answer: both buttons go quiet until the next state arrives. */
  function answerButtons(first, second) {
    const pair = [first, second];
    const lock = (on) => pair.forEach((node) => { node.disabled = on; });
    return { lock, pair };
  }
  function answer(command, args, buttons) {
    return async () => {
      buttons.lock(true);
      try {
        await call(command, args);
      } catch {
        buttons.lock(false);
      }
    };
  }

  async function addToWildbloom(session, node) {
    const p = session.payload;
    node.disabled = true;
    try {
      const result = await call('receive_add_to_wildbloom', { id: p.id });
      session.added = result;
      session.addNote = '';
    } catch (error) {
      node.disabled = false;
      const code = error && error.code;
      if (code === 'folder_off') {
        const yes = await confirmFolderOn(node).catch(() => false);
        if (yes) {
          try {
            await call('set_watch_folder', { enabled: true });
            session.context.refresh();
            node.disabled = false;
            return addToWildbloom(session, node);
          } catch { /* the note below says it */ }
        }
        session.addNote = 'Your Wildbloom folder is off, so the file stays in the Received folder.';
      } else if (code === 'folder_unavailable') session.addNote = "Your Wildbloom folder can't be found. The file stays in the Received folder.";
      else if (code === 'cannot_sync') session.addNote = "Wildbloom can't keep this file, for example because it's empty. It stays in the Received folder.";
      else if (code === 'not_found') session.addNote = "The file isn't where Drop left it any more.";
      else session.addNote = "Couldn't move the file. It stays in the Received folder.";
    }
    render(session, p);
  }

  async function reveal(session, node) {
    try {
      await call('receive_reveal', { id: session.payload.id });
    } catch {
      session.addNote = "The file isn't where Drop left it any more.";
      node.disabled = false;
      render(session, session.payload);
    }
  }

  function render(session, p) {
    const previous = session.payload?.state;
    session.payload = p;
    if (LIVE.has(p.state)) dismissedFinal = false;
    const { dialog, heading, context } = session;
    const focusedKey = dialog.contains(document.activeElement) ? document.activeElement.getAttribute?.('data-key') : null;
    const hadFocusInside = dialog.contains(document.activeElement) && document.activeElement !== heading && document.activeElement !== dialog;

    // Progress ticks update in place so nothing is rebuilt or re-announced.
    if (p.state === 'receiving' && previous === 'receiving' && !p.reconnecting === !session.reconnecting) {
      const bar = session.top.querySelector('progress');
      const percent = percentOf(p);
      if (bar) bar.value = percent;
      const meta = session.top.querySelector('.receive-meta');
      if (meta) meta.textContent = `${percent}% of ${formatBytes(p.size)}`;
      for (const mark of [25, 50, 75]) {
        if (percent >= mark && !session.announced.has(`p${mark}`)) { session.announced.add(`p${mark}`); say(session, `${mark}% received.`); }
      }
      return;
    }
    session.reconnecting = Boolean(p.reconnecting);

    clearInterval(session.timer);
    session.timer = null;
    const close = () => button('Close', 'secondary', 'close', () => dialog.close());
    const doneButton = (primary) => button('Done', primary ? 'primary' : 'secondary', 'done', () => dialog.close(), primary);
    const again = (label) => button(label, 'primary', 'start-again', () => start(session), true);
    const body = (text) => h('p', { class: 'share-body' }, text);
    const links = (done) => [stepLink(session, p, done), stepWords(session, p, done, WORDS_HINT, 'Say these words another way, like a call or a message')];
    const file = () => {
      const ext = extensionOf(p.name);
      return h('div', { class: 'receive-file' },
        h('p', { class: 'receive-name' }, p.name || 'A file'),
        h('p', { class: 'receive-ext' }, ext ? `Ends in ${ext}` : 'No file extension'),
        h('p', { class: 'receive-meta' }, [formatBytes(p.size), p.type].filter(Boolean).join(' · ')));
    };

    let topNodes = [];
    let bottomNodes = [];
    let focusHeading = false;
    switch (p.state) {
      case 'preparing':
        statusLine(session, 'accent', 'refresh', 'Getting a link ready…');
        bottomNodes = [buttonRow(stopButton('Cancel'))];
        break;
      case 'waiting':
        statusLine(session, 'muted', 'pending', 'Send the link, say the words another way.', true);
        topNodes = links(false);
        if (context?.receiving?.maxBytes) topNodes.push(h('p', { class: 'share-hint' }, `They can send one file, up to ${formatBytes(context.receiving.maxBytes)}.`));
        bottomNodes = [buttonRow(stopButton('Cancel'))];
        break;
      case 'opened':
        statusLine(session, 'accent', 'check', 'Someone opened your link.', true);
        topNodes = [...links(false), body('Waiting for them to type the words.')];
        bottomNodes = [buttonRow(stopButton('Cancel'))];
        break;
      case 'check': {
        statusLine(session, 'accent', 'check', 'Do these 3 words match theirs?', true);
        topNodes = [...links(true), stepCheck(p, 'Check these words with them', 'Say them out loud and ask if they see the same 3 words.')];
        const yes = button('They match', 'primary', 'match', () => {}, true);
        const no = button("They don't match", 'secondary', 'no-match', () => {});
        const buttons = answerButtons(yes, no);
        yes.onclick = answer('receive_verify', { matches: true }, buttons);
        no.onclick = answer('receive_verify', { matches: false }, buttons);
        bottomNodes = [buttonRow(yes, no), buttonRow(stopButton('Cancel'))];
        break;
      }
      case 'waiting_file':
        statusLine(session, 'muted', 'pending', 'Waiting for them to choose a file.');
        bottomNodes = [buttonRow(stopButton('Cancel'))];
        break;
      case 'consent': {
        statusLine(session, 'accent', 'down', `They want to send you ${p.name || 'a file'} (${formatBytes(p.size).replace(' ', '\u00a0')}).`);
        topNodes = [file(), body('Nothing has been sent yet. Only accept a file you expect.')];
        const accept = button('Accept', 'primary', 'accept', () => {});
        const decline = button('Decline', 'secondary', 'decline', () => {});
        const buttons = answerButtons(accept, decline);
        accept.onclick = answer('receive_consent', { accept: true }, buttons);
        decline.onclick = answer('receive_consent', { accept: false }, buttons);
        bottomNodes = [buttonRow(accept, decline)];
        // The owner decides: focus never lands on Accept, so a key press meant for the last question can't accept a file.
        focusHeading = true;
        break;
      }
      case 'connecting':
        statusLine(session, 'accent', 'refresh', p.reconnecting ? 'Reconnecting…' : 'Connecting…');
        topNodes = [h('div', { class: 'receive-progress' }, h('p', { class: 'receive-name' }, p.name || 'A file')),
          ...(p.hidden ? [body('Your address is hidden.')] : []), h('p', { class: 'share-hint' }, 'You can close this window. Drop carries on.')];
        bottomNodes = [buttonRow(stopButton('Stop'))];
        break;
      case 'receiving': {
        const percent = percentOf(p);
        statusLine(session, 'accent', p.reconnecting ? 'refresh' : 'down', p.reconnecting ? 'Reconnecting…' : 'Receiving…');
        topNodes = [
          h('div', { class: 'receive-progress' },
            h('p', { class: 'receive-name' }, p.name || 'A file'),
            h('progress', { max: '100', value: String(percent), 'aria-label': `Receiving ${p.name || 'the file'}` }),
            h('p', { class: 'receive-meta' }, `${percent}% of ${formatBytes(p.size)}`)),
          ...(p.hidden ? [body('Your address is hidden.')] : []),
          h('p', { class: 'share-hint' }, 'You can close this window. Drop carries on.'),
        ];
        bottomNodes = [buttonRow(stopButton('Stop'))];
        break;
      }
      case 'verifying':
        statusLine(session, 'accent', 'refresh', 'Checking the file…');
        topNodes = [body("Every byte has arrived. It can't be opened until the check is done.")];
        bottomNodes = [buttonRow(stopButton('Stop'))];
        break;
      case 'kept': {
        const added = session.added;
        const name = added?.name || p.name || 'the file';
        statusLine(session, 'success', 'check', added ? `Added ${name} to Wildbloom.` : `Received ${name}.`);
        const where = added ? added.folder : p.path || p.folder;
        topNodes = [h('p', { class: 'receive-path' }, added ? `It's in ${where}, and Wildbloom keeps 2 copies of it now.` : `It's in ${where}. Wildbloom isn't keeping copies of it yet.`)];
        if (!added && p.canAdd === false) topNodes.push(body('Your Wildbloom folder is off, so it can\'t be added yet. Turn it on in Settings.'));
        if (session.addNote) topNodes.push(body(session.addNote));
        const canAdd = !added && p.canAdd !== false;
        const show = button(revealText(), 'secondary', 'reveal', (event) => reveal(session, event.currentTarget));
        if (canAdd) {
          const add = button('Add to Wildbloom', 'primary', 'add', (event) => addToWildbloom(session, event.currentTarget), true);
          bottomNodes = [buttonRow(add, show), buttonRow(button('Done', 'quiet', 'done', () => dialog.close()))];
        } else {
          bottomNodes = [buttonRow(doneButton(true), show)];
        }
        break;
      }
      case 'declined':
      case 'cancelled':
        statusLine(session, 'muted', 'ring', endedText(p, context));
        bottomNodes = [buttonRow(again('Start again'), close())];
        break;
      case 'failed':
        statusLine(session, 'warning', 'alert', endedText(p, context));
        bottomNodes = [buttonRow(again('Start again'), close())];
        break;
      default:
        statusLine(session, 'warning', 'alert', 'Something went wrong. Nothing was kept.');
        bottomNodes = [buttonRow(again('Start again'), close())];
    }
    session.top.replaceChildren(...topNodes);
    session.bottom.replaceChildren(...bottomNodes);

    if (COUNTING.has(p.state)) startCountdown(session, p);

    // Focus: keep it where it was when that control survives; otherwise move it to the primary action.
    const same = focusedKey ? dialog.querySelector(`[data-key="${CSS.escape(focusedKey)}"]`) : null;
    if (focusHeading) heading.focus({ preventScroll: true });
    else if (same) same.focus({ preventScroll: true });
    else if (hadFocusInside || document.activeElement === document.body) {
      (session.bottom.querySelector('[data-primary]') || session.bottom.querySelector('button') || heading).focus({ preventScroll: true });
    }
  }

  /** Every receive://state, whether or not the sheet is open. */
  function onState(payload, context, opener) {
    if (!payload || !payload.state) return;
    if (current) {
      current.heard = true;
      current.context = context;
      render(current, payload);
      return;
    }
    if (LIVE.has(payload.state)) dismissedFinal = false;
    // With the sheet closed: bring it back when the owner has a question to answer, and say how it ended otherwise.
    if ((payload.state === 'check' || payload.state === 'consent') && context.canOpen()) {
      open(opener, context, payload);
    } else if (payload.state === 'kept') {
      context.notice(`Received ${payload.name || 'a file'}. It's in ${payload.folder || 'your Received folder'}.`);
    } else if (payload.state === 'failed' || (payload.state === 'cancelled' && payload.by === 'them')) {
      context.notice(endedText(payload, context));
    }
  }

  /** At start-up: a receive that is still running comes back with the window. */
  async function resume(context, opener) {
    try {
      const next = await call('receive_state');
      if (next && LIVE.has(next.state) && !current && context.canOpen()) open(opener, context, next);
    } catch { /* nothing to resume */ }
  }

  window.WildbloomReceive = { open, onState, resume, isOpen: () => Boolean(current), failureText };
})();
