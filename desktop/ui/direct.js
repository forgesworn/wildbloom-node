// The hidden direct-send window (desktop/ui/DROP-IPC.md, "Hidden direct-send
// window"). Rust creates it for one transfer, after the owner accepts the
// file, and destroys it afterwards. It runs the one RTCPeerConnection and the
// frame logic with the web project's own code (vendor/wildbloom-direct.js,
// built from forgesworn/wildbloom by scripts/vendor-direct.mjs) and hands each
// DATA frame's bytes to Rust, which writes them, verifies the envelope with the
// key only Rust holds, and keeps the file.
//
// It never logs: requests carry Drop's TURN credential and the SDP, and the
// sink carries the file's (encrypted) bytes. Nothing goes to browser storage.
import {
  DirectPeer,
  NoRelayError,
  SinkStorageError,
  TransferError,
  encodeStop,
  receiveEnvelope,
} from './vendor/wildbloom-direct.js';

/** How long a last frame (KEPT or STOP) gets to leave before the connection closes; the contract allows a second. */
const FLUSH_MS = 900;

const tauri = window.__TAURI__;

/** The transfer this window serves; there is never more than one. */
let current;

/** Reports go one after another, so Rust reads states, `channel` and `ended` in the order they happened. */
let reports = Promise.resolve();
function report(body) {
  reports = reports.then(() => tauri.core.invoke('direct_peer_report', { report: body })).catch(() => undefined);
  return reports;
}
const done = (transfer, seq) => report({ kind: 'done', transfer, seq });
const refuse = (transfer, seq, reason) => report({ kind: 'error', transfer, seq, reason });

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for the send buffer to empty, up to `ms`: closing a connection discards what it has not sent. */
async function drained(channel, ms) {
  const until = Date.now() + ms;
  while (channel?.open && channel.bufferedAmount > 0 && Date.now() < until) await pause(10);
}

/** A command's refusal as the sink must throw it: STOP 3 for no room, STOP 2 for anything else. */
function sinkFailure(error) {
  const code = typeof error === 'string' ? error : error?.code;
  return code === 'sink_storage' ? new SinkStorageError() : new Error('sink_failed');
}

/**
 * The DirectSink that forwards to Rust, one step at a time, in order. A write
 * resolves only once Rust has the bytes on disk, so receiveEnvelope's ACK for
 * them follows the write.
 */
function rustSink(transfer) {
  let offset = 0;
  return {
    async write(bytes) {
      try {
        await tauri.core.invoke('direct_sink_write', bytes, {
          headers: { 'Wildbloom-Transfer': transfer, 'Wildbloom-Offset': String(offset) },
        });
      } catch (error) {
        throw sinkFailure(error);
      }
      offset += bytes.length;
    },
    async end({ sha256, size }) {
      try {
        await tauri.core.invoke('direct_sink_end', { transfer, sha256: hex(sha256), size });
      } catch (error) {
        throw sinkFailure(error);
      }
    },
    async abort() {
      await tauri.core.invoke('direct_sink_abort', { transfer }).catch(() => undefined);
    },
  };
}

/**
 * The channel receiveEnvelope sees. `gate.silent` stops everything it would
 * send, so a close can put its own STOP on the wire in place of the STOP 1
 * an abort sends; `gate.closed` ends it from the connection's state, because
 * WebKit never fires the channel's close when the other end vanishes.
 */
function gated(channel, gate) {
  return {
    get open() {
      return !gate.silent && channel.open;
    },
    get bufferedAmount() {
      return channel.bufferedAmount;
    },
    get bufferedAmountLowThreshold() {
      return channel.bufferedAmountLowThreshold;
    },
    set bufferedAmountLowThreshold(value) {
      channel.bufferedAmountLowThreshold = value;
    },
    get maxMessageSize() {
      return channel.maxMessageSize;
    },
    send(frame) {
      if (!gate.silent) channel.send(frame);
    },
    close() {
      channel.close();
    },
    listen(handlers) {
      gate.closed = () => handlers.closed();
      const stop = channel.listen(handlers);
      return () => {
        gate.closed = undefined;
        stop();
      };
    },
  };
}

function create(request) {
  const { transfer: id, seq } = request;
  if (current) {
    // One transfer at a time: anything left over goes without a word.
    current.closing = true;
    current.gate.silent = true;
    current.run.abort();
    current.peer.close();
    current = undefined;
  }
  let peer;
  try {
    peer = new DirectPeer({ iceServers: request.iceServers, hide: request.relayOnly === true });
  } catch (error) {
    return refuse(id, seq, error instanceof NoRelayError ? 'no-relay' : 'create');
  }
  const transfer = {
    id,
    peer,
    envelopeBytes: request.envelopeBytes,
    size: request.size,
    run: new AbortController(),
    gate: { silent: false, closed: undefined },
    channel: undefined,
    answered: false,
    receiving: false,
    closing: false,
    violated: false,
    state: undefined,
  };
  current = transfer;
  peer.onState((state, violation) => {
    if (violation) transfer.violated = true;
    if (state !== transfer.state) {
      transfer.state = state;
      void report({ kind: 'state', transfer: id, state });
    }
    if (state === 'closed') transfer.gate.closed?.();
  });
  return done(id, seq);
}

async function describe(transfer, seq, restart) {
  let sdp;
  try {
    sdp = await transfer.peer.offer(restart);
  } catch {
    return refuse(transfer.id, seq, restart ? 'restart' : 'offer');
  }
  return report({ kind: 'offer', transfer: transfer.id, seq, sdp });
}

async function answer(transfer, request) {
  try {
    await transfer.peer.applyAnswer(request.sdp);
  } catch {
    return refuse(transfer.id, request.seq, 'answer');
  }
  await done(transfer.id, request.seq);
  if (!transfer.answered) {
    transfer.answered = true;
    void receive(transfer);
  }
}

/** Waits for the data channel, then receives the envelope into the sink and says how it ended. */
async function receive(transfer) {
  let channel;
  try {
    channel = await transfer.peer.channel;
  } catch {
    if (!transfer.closing) void report({ kind: 'ended', transfer: transfer.id, outcome: transfer.violated ? 'protocol' : 'closed' });
    return;
  }
  if (transfer.closing) return;
  transfer.channel = channel;
  void report({ kind: 'channel', transfer: transfer.id });
  transfer.receiving = true;
  let outcome = 'kept';
  try {
    await receiveEnvelope({
      channel: gated(channel, transfer.gate),
      envelopeBytes: transfer.envelopeBytes,
      plaintextBytes: transfer.size,
      sink: rustSink(transfer.id),
      signal: transfer.run.signal,
    });
  } catch (error) {
    outcome = error instanceof TransferError ? error.kind : 'webview';
    // The other end opened a channel or track the protocol forbids, and the peer closed itself.
    if (outcome === 'closed' && transfer.violated) outcome = 'protocol';
  } finally {
    transfer.receiving = false;
  }
  void report({ kind: 'ended', transfer: transfer.id, outcome });
}

/**
 * Ends the transfer. With `stop` set and the frame logic still running, STOP
 * goes out with that reason (1 the owner cancelled, 2 a failure Rust found, 3
 * no room) and nothing after it; with `stop` null nothing is sent. Then the
 * last frame gets a moment to leave and the connection closes.
 */
async function close(transfer, request) {
  transfer.closing = true;
  const { stop } = request;
  if (transfer.receiving && transfer.channel) {
    if (stop === 1 || stop === 2 || stop === 3) {
      try {
        if (transfer.channel.open) transfer.channel.send(encodeStop(stop));
      } catch {
        // The channel is going; there is nobody to tell.
      }
    }
    transfer.gate.silent = true;
    transfer.run.abort();
  }
  await drained(transfer.channel, FLUSH_MS);
  transfer.peer.close();
  if (current === transfer) current = undefined;
  return done(transfer.id, request.seq);
}

function handle(request) {
  if (!request || typeof request !== 'object' || typeof request.transfer !== 'string') return;
  const { op, transfer: id, seq } = request;
  if (op === 'create') return create(request);
  const transfer = current?.id === id ? current : undefined;
  if (op === 'close') return transfer ? close(transfer, request) : done(id, seq);
  if (!transfer) return refuse(id, seq, 'unknown-transfer');
  switch (op) {
    case 'offer':
      return describe(transfer, seq, false);
    case 'restart':
      return describe(transfer, seq, true);
    case 'answer':
      return answer(transfer, request);
    default:
      return refuse(id, seq, 'unknown-op');
  }
}

// Subscribe first; Rust sends nothing before `ready`.
if (tauri?.core && tauri.event) {
  tauri.event.listen('direct://peer', (event) => {
    void handle(event.payload);
  }).then(() => report({ kind: 'ready' }), () => undefined);
}
