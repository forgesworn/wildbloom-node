// Builds and checks vectors/group-grants-v1.json for docs/GROUP-GRANTS.md.
//
//   npm ci && node vectors.mjs --write    regenerate the vectors file
//   npm ci && node vectors.mjs --check    regenerate in memory and require the
//                                         committed file to match byte for byte
//
// Every case states its expected outcome by hand.  A small reference model of
// the spec's rules runs over every case and must reach the same outcome, so a
// disagreement between the written intent and the rules stops the script.
// Ids and signatures are made with @noble/curves (BIP-340, fixed auxiliary
// bytes, so the output is deterministic) and checked again with nostr-tools'
// verifyEvent, which hashes and verifies independently of this file's
// serialiser.  Keys, hashes and domains are synthetic.
import assert from 'node:assert/strict';
import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1.js';
import { verifyEvent } from 'nostr-tools/pure';

const here = dirname(fileURLToPath(import.meta.url));
const output = resolve(here, '../../vectors/group-grants-v1.json');
const versions = {
  curves: JSON.parse(readFileSync(join(here, 'node_modules/@noble/curves/package.json'), 'utf8')).version,
  nostrTools: JSON.parse(readFileSync(join(here, 'node_modules/nostr-tools/package.json'), 'utf8')).version,
};

// ---------------------------------------------------------------------------
// Constants of the profile (docs/GROUP-GRANTS.md, "Limits")
// ---------------------------------------------------------------------------

const KIND = 27541;
const BLOSSOM_AUTH = 24242;
const DAY = 86_400;
const LIMITS = {
  eventBytes: 16_384,
  eventTags: 16,
  futureSkew: 30,
  grantLifetime: 90 * DAY,
  stateRetention: 90 * DAY,
  getLifetime: 300,
  uploadLifetime: 300,
  listLifetime: 300,
  deleteLifetime: 7 * DAY + 1,
  selfDeleteGrace: 7 * DAY,
  authValuesPerTag: 32,
  authContentBytes: 1024,
};
const SCOPES = ['upload', 'get', 'delete', 'purge', 'turn', 'relay-read', 'relay-write'];
const LIFETIME_BY_VERB = {
  get: LIMITS.getLifetime,
  upload: LIMITS.uploadLifetime,
  list: LIMITS.listLifetime,
  delete: LIMITS.deleteLifetime,
};

const T0 = 1_800_000_000;
const MONTH = 30 * DAY;
const AUX = new Uint8Array(32);
const SERVER = 'grove.example.net';
const OTHER_SERVER = 'heath.example.net';

const HEX = (n) => new RegExp(`^[0-9a-f]{${n}}$`);
const HEX32 = HEX(32);
const HEX64 = HEX(64);
const HEX128 = HEX(128);
const DECIMAL = /^(0|[1-9][0-9]{0,18})$/;
const HOST = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const sha256 = (data) => createHash('sha256').update(data).digest();
const sha256hex = (data) => sha256(data).toString('hex');
const clone = (value) => JSON.parse(JSON.stringify(value));

// ---------------------------------------------------------------------------
// Fixture: keys, rooms, node, blobs
// ---------------------------------------------------------------------------

const KEY_LABELS = [
  'nodeOwner',
  'authorityA',
  'authorityB',
  'authorityC',
  'alicePhone',
  'bobLaptop',
  'coordinatorA',
  'carolPhone',
  'stranger',
];
const keys = {};
for (const label of KEY_LABELS) {
  const secret = sha256(`group-grants/1 synthetic key ${label}`);
  keys[label] = {
    secret: secret.toString('hex'),
    pubkey: Buffer.from(schnorr.getPublicKey(secret)).toString('hex'),
  };
}
const pub = (label) => keys[label].pubkey;

// The two rooms are KithMoot's own vector rooms (kithmoot
// vectors/kithmoot-vectors.json, roomDerivation typical-secret-1 and -2), so
// a reader can trace a room id here back to that file.
function roomId(secretHex) {
  return Buffer.from(
    hkdfSync('sha256', Buffer.from(secretHex, 'hex'), Buffer.alloc(0), 'kithmoot/v1/room-id', 32),
  ).toString('hex');
}
const rooms = {
  a: {
    secretHex: '3235bdb7cf4e08d8eb9f1441bd2158825c0e84150ac0fc123a106455130eeecf',
    roomId: '2848bdd5c60a79e2dfe667ae9616c1107f61709032b66e556e28f4a96e69450b',
    from: 'kithmoot vectors/kithmoot-vectors.json roomDerivation typical-secret-1',
  },
  b: {
    secretHex: 'd65ea38d656270d9eebcb949759dec4599cade320bd53cf2bce301e2c23fd72d',
    roomId: 'fcdc853ddc1be7f7d978367e1a5156b55f11e4c22a49db949f5bb939a303762a',
    from: 'kithmoot vectors/kithmoot-vectors.json roomDerivation typical-secret-2',
  },
};
for (const room of Object.values(rooms)) assert.equal(roomId(room.secretHex), room.roomId);
const ROOM_A = rooms.a.roomId;
const ROOM_B = rooms.b.roomId;

const node = {
  servers: [SERVER],
  otherServer: OTHER_SERVER,
  owners: [pub('nodeOwner')],
  enrolments: [
    { keeper: pub('authorityA'), ceiling: 10_737_418_240 },
    { keeper: pub('authorityB'), ceiling: 1_073_741_824 },
  ],
};

const blobs = {};
for (const label of ['blob1', 'blob2', 'blob3', 'blob4']) {
  const text = `group-grants/1 synthetic ${label}\n`;
  blobs[label] = { text, sha256: sha256hex(text) };
}
const H = (label) => blobs[label].sha256;

// ---------------------------------------------------------------------------
// Event construction
// ---------------------------------------------------------------------------

function sign(label, { created_at, kind, tags, content }) {
  const pubkey = pub(label);
  const id = sha256hex(JSON.stringify([0, pubkey, created_at, kind, tags, content]));
  const sig = Buffer.from(
    schnorr.sign(Buffer.from(id, 'hex'), Buffer.from(keys[label].secret, 'hex'), AUX),
  ).toString('hex');
  return { id, pubkey, created_at, kind, tags, content, sig };
}

const grantId = (label) => sha256hex(`group-grants/1 grant id ${label}`).slice(0, 32);

// A kind 27541 grant, in the tag order writers emit.  `edit` changes the tag
// list before signing, so the result is a correctly signed event with one fault.
function grant({
  signer = 'authorityA',
  id,
  d = ROOM_A,
  device,
  server = SERVER,
  scopes,
  bytes,
  status = 'active',
  created = T0,
  expiration = T0 + MONTH,
  edit,
}) {
  let tags = [
    ['t', 'grant'],
    ['grant', grantId(id)],
    ['d', d],
    ['device', pub(device)],
    ['server', server],
    ...scopes.map((scope) => ['scope', scope]),
    ...(bytes === undefined ? [] : [['bytes', String(bytes)]]),
    ['status', status],
    ['expiration', String(expiration)],
  ];
  if (edit) tags = edit(tags);
  return sign(signer, { created_at: created, kind: KIND, tags, content: '' });
}

function reset({ signer = 'authorityA', d = ROOM_A, server = SERVER, created, expiration, edit }) {
  let tags = [
    ['t', 'reset'],
    ['d', d],
    ['server', server],
    ['expiration', String(expiration ?? created + LIMITS.grantLifetime)],
  ];
  if (edit) tags = edit(tags);
  return sign(signer, { created_at: created, kind: KIND, tags, content: '' });
}

const STORE = ['upload', 'get', 'delete'];
const GIB = 1_073_741_824;
const fixtureGrants = {
  alice: () => grant({ id: 'alice', device: 'alicePhone', scopes: STORE, bytes: GIB }),
  bob: () => grant({ id: 'bob', device: 'bobLaptop', scopes: ['get'] }),
  coordinator: () =>
    grant({ id: 'coordinator', device: 'coordinatorA', scopes: ['upload', 'get', 'purge'], bytes: 10 * GIB }),
  carol: () =>
    grant({ signer: 'authorityB', id: 'carol', d: ROOM_B, device: 'carolPhone', scopes: STORE, bytes: GIB }),
};

// A kind 24242 authorisation header.
function auth(label, {
  verb,
  hashes = [],
  servers = [SERVER],
  created,
  lifetime = 60,
  expiration,
  kind = BLOSSOM_AUTH,
  content,
  encoding = 'base64',
  edit,
}) {
  let tags = [
    ['t', verb],
    ['expiration', String(expiration ?? created + lifetime)],
    ...servers.map((server) => ['server', server]),
    ...hashes.map((hash) => ['x', hash]),
  ];
  if (edit) tags = edit(tags);
  const event = sign(label, {
    created_at: created,
    kind,
    tags,
    content: content ?? `group-grants/1 synthetic ${verb}`,
  });
  return { event, header: `Nostr ${Buffer.from(JSON.stringify(event)).toString(encoding)}` };
}

function corruptSig(event) {
  const last = event.sig.at(-1);
  return { ...event, sig: event.sig.slice(0, -1) + (last === '0' ? '1' : '0') };
}

function headerFor(event, encoding = 'base64') {
  return `Nostr ${Buffer.from(JSON.stringify(event)).toString(encoding)}`;
}

// Request shapes.
const get = (hash, header, extra = []) => ({
  method: 'GET',
  path: `/${hash}`,
  headers: [...(header ? [['Authorization', header]] : []), ...extra],
});
const head = (hash, header) => ({ method: 'HEAD', path: `/${hash}`, headers: [['Authorization', header]] });
const upload = (blob, header) => ({
  method: 'PUT',
  path: '/upload',
  headers: [
    ['Authorization', header],
    ['X-SHA-256', H(blob)],
    ['Content-Length', String(Buffer.byteLength(blobs[blob].text))],
  ],
  body: blob,
});
const del = (hash, header) => ({ method: 'DELETE', path: `/${hash}`, headers: [['Authorization', header]] });

// ---------------------------------------------------------------------------
// Reference model of the rules in docs/GROUP-GRANTS.md
// ---------------------------------------------------------------------------

const R = (status, reason, extra = {}) => ({ status, reason, ...extra });

function strictShape(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
  const fields = Object.keys(event).sort().join(',');
  if (fields !== 'content,created_at,id,kind,pubkey,sig,tags') return false;
  return (
    HEX64.test(event.id) &&
    HEX64.test(event.pubkey) &&
    HEX128.test(event.sig) &&
    Number.isSafeInteger(event.created_at) &&
    event.created_at >= 0 &&
    Number.isSafeInteger(event.kind) &&
    typeof event.content === 'string' &&
    Array.isArray(event.tags) &&
    event.tags.every((tag) => Array.isArray(tag) && tag.every((part) => typeof part === 'string'))
  );
}

function signatureValid(event) {
  const id = sha256hex(
    JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]),
  );
  if (id !== event.id) return false;
  try {
    return schnorr.verify(Buffer.from(event.sig, 'hex'), Buffer.from(id, 'hex'), Buffer.from(event.pubkey, 'hex'));
  } catch {
    return false;
  }
}

const GRANT_TAGS = ['t', 'grant', 'd', 'device', 'server', 'scope', 'bytes', 'status', 'expiration'];
const RESET_TAGS = ['t', 'd', 'server', 'expiration'];

// Rules that need only the event, the node's configuration and the clock.
function checkEvent(event, config, now) {
  if (Buffer.byteLength(JSON.stringify(event)) > LIMITS.eventBytes) return R(413, 'too-large');
  const bad = R(400, 'malformed');
  if (!strictShape(event) || event.kind !== KIND || event.content !== '') return bad;
  if (event.tags.length > LIMITS.eventTags || event.tags.some((tag) => tag.length !== 2)) return bad;
  const named = (name) => event.tags.filter((tag) => tag[0] === name).map((tag) => tag[1]);
  const verbs = named('t');
  if (verbs.length !== 1 || !['grant', 'reset'].includes(verbs[0])) return bad;
  const verb = verbs[0];
  const allowed = verb === 'grant' ? GRANT_TAGS : RESET_TAGS;
  if (event.tags.some((tag) => !allowed.includes(tag[0]))) return bad;
  const one = (name) => {
    const values = named(name);
    return values.length === 1 ? values[0] : undefined;
  };
  const singletons = verb === 'grant'
    ? ['grant', 'd', 'device', 'server', 'status', 'expiration']
    : ['d', 'server', 'expiration'];
  if (singletons.some((name) => one(name) === undefined)) return bad;
  const fields = { verb, keeper: event.pubkey, d: one('d'), server: one('server') };
  if (!HEX64.test(fields.d) || !HOST.test(fields.server)) return bad;
  const expiration = one('expiration');
  if (!DECIMAL.test(expiration)) return bad;
  fields.expiration = Number(expiration);
  if (verb === 'grant') {
    fields.grant = one('grant');
    fields.device = one('device');
    fields.status = one('status');
    fields.scopes = named('scope');
    const bytes = named('bytes');
    if (!HEX32.test(fields.grant) || !HEX64.test(fields.device)) return bad;
    if (!['active', 'revoked'].includes(fields.status)) return bad;
    if (fields.scopes.length === 0 || new Set(fields.scopes).size !== fields.scopes.length) return bad;
    if (fields.scopes.some((scope) => !SCOPES.includes(scope))) return bad;
    if (fields.scopes.includes('upload') !== (bytes.length === 1) || bytes.length > 1) return bad;
    if (bytes.length === 1) {
      if (!DECIMAL.test(bytes[0]) || BigInt(bytes[0]) < 1n || BigInt(bytes[0]) > 2n ** 63n - 1n) return bad;
      fields.bytes = Number(bytes[0]);
    }
    if (fields.device === event.pubkey) return bad;
  }
  if (fields.expiration <= event.created_at || fields.expiration - event.created_at > LIMITS.grantLifetime) {
    return R(400, 'lifetime');
  }
  if (!signatureValid(event)) return R(401, 'signature');
  if (!config.enrolments.some((enrolment) => enrolment.keeper === event.pubkey)) return R(403, 'keeper');
  if (!config.servers.includes(fields.server)) return R(403, 'server');
  if (event.created_at > now + LIMITS.futureSkew) return R(403, 'future');
  if (fields.expiration <= now) return R(403, 'expired');
  return { ok: true, fields };
}

function newNode(config = node) {
  return {
    config,
    grants: new Map(), // keeper|grant -> row
    floors: new Map(), // keeper|d|server -> { createdAt, eventId }
    groupOfKey: new Map(), // key -> keeper|d
    claims: new Map(), // sha256 -> Map(key -> group)
    spent: new Map(), // delete event id -> expiration
  };
}

const enrolled = (state, keeper) => state.config.enrolments.some((enrolment) => enrolment.keeper === keeper);
const floorOf = (state, row) => state.floors.get(`${row.keeper}|${row.d}|${row.server}`)?.createdAt;

function rowActive(state, row, now) {
  const floor = floorOf(state, row);
  return (
    row.status === 'active' &&
    row.expiration > now &&
    enrolled(state, row.keeper) &&
    state.config.servers.includes(row.server) &&
    !(floor !== undefined && floor >= row.createdAt)
  );
}

// When a row stopped being active: its revocation, a reset floor or its expiry.
function endedAt(state, row, now) {
  if (rowActive(state, row, now)) return undefined;
  const ends = [];
  if (row.status === 'revoked' && row.revokedAt !== undefined) ends.push(row.revokedAt);
  const floor = floorOf(state, row);
  if (floor !== undefined && floor >= row.activeCreatedAt) ends.push(floor);
  if (row.activeExpiration !== undefined && row.activeExpiration <= now) ends.push(row.activeExpiration);
  return ends.length ? Math.min(...ends) : undefined;
}

function activeGrant(state, key, scope, now) {
  for (const row of state.grants.values()) {
    if (row.device === key && rowActive(state, row, now) && row.scopes.includes(scope)) return row;
  }
  return undefined;
}

function deleteGrace(state, key, now) {
  for (const row of state.grants.values()) {
    if (row.device !== key || !row.activeScopes?.includes('delete')) continue;
    const ended = endedAt(state, row, now);
    if (ended !== undefined && now < ended + LIMITS.selfDeleteGrace) return true;
  }
  return false;
}

function postEvent(state, event, now) {
  const checked = checkEvent(event, state.config, now);
  if (!checked.ok) return checked;
  const f = checked.fields;
  if (f.verb === 'reset') {
    const key = `${f.keeper}|${f.d}|${f.server}`;
    const floor = state.floors.get(key);
    if (floor?.eventId === event.id) return R(200, 'unchanged');
    if (floor !== undefined && event.created_at <= floor.createdAt) return R(409, 'stale');
    state.floors.set(key, { createdAt: event.created_at, eventId: event.id });
    return R(201, 'accepted', { state: 'reset' });
  }
  const reserved = new Set([...state.config.owners, ...state.config.enrolments.map((e) => e.keeper)]);
  const group = `${f.keeper}|${f.d}`;
  if (reserved.has(f.device)) return R(409, 'key-conflict');
  if (state.groupOfKey.has(f.device) && state.groupOfKey.get(f.device) !== group) return R(409, 'key-conflict');
  const floor = state.floors.get(`${f.keeper}|${f.d}|${f.server}`);
  if (floor !== undefined && event.created_at <= floor.createdAt) return R(409, 'floor');
  const rowKey = `${f.keeper}|${f.grant}`;
  const row = state.grants.get(rowKey);
  if (row) {
    if (row.eventId === event.id) return R(200, 'unchanged');
    if (row.d !== f.d || row.device !== f.device || row.server !== f.server) return R(409, 'scope-changed');
    if (event.created_at <= row.createdAt) return R(409, 'stale');
    if (row.status === 'revoked' && f.status === 'active') return R(409, 'revoked');
  }
  if (f.status === 'active') {
    for (const [key, other] of state.grants) {
      if (key === rowKey) continue;
      if (other.keeper === f.keeper && other.d === f.d && other.device === f.device &&
          other.server === f.server && rowActive(state, other, now)) {
        return R(409, 'scope-taken');
      }
    }
  }
  const active = f.status === 'active';
  state.grants.set(rowKey, {
    keeper: f.keeper,
    d: f.d,
    device: f.device,
    server: f.server,
    scopes: f.scopes,
    bytes: f.bytes,
    status: f.status,
    eventId: event.id,
    createdAt: event.created_at,
    expiration: f.expiration,
    retainUntil: Math.max(row?.retainUntil ?? 0, f.expiration),
    activeScopes: active ? f.scopes : row?.activeScopes,
    activeCreatedAt: active ? event.created_at : row?.activeCreatedAt,
    activeExpiration: active ? f.expiration : row?.activeExpiration,
    revokedAt: active ? undefined : event.created_at,
  });
  state.groupOfKey.set(f.device, group);
  return R(201, 'accepted', { state: f.status });
}

function decodeBase64(text) {
  let standard;
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(text)) standard = text;
  else if (/^[A-Za-z0-9_-]+={0,2}$/.test(text)) standard = text.replace(/-/g, '+').replace(/_/g, '/');
  else return undefined;
  if (standard.includes('=') && standard.length % 4 !== 0) return undefined;
  const bare = standard.replace(/=+$/, '');
  if (bare.length % 4 === 1) return undefined;
  return Buffer.from(bare, 'base64');
}

function endpoint(request) {
  const { method, path } = request;
  const blob = /^\/([0-9a-f]{64})(?:\.[a-z0-9]{1,10})?$/.exec(path);
  if ((method === 'GET' || method === 'HEAD') && blob) return { verb: 'get', hash: blob[1] };
  if ((method === 'PUT' || method === 'HEAD') && path === '/upload') {
    const header = request.headers.find(([name]) => name.toLowerCase() === 'x-sha-256');
    return { verb: 'upload', hash: header?.[1] };
  }
  if (method === 'DELETE' && blob) return { verb: 'delete', hash: blob[1] };
  return undefined;
}

const holds = (state, key, hash) => state.claims.get(hash)?.has(key) ?? false;
const groupHolds = (state, group, hash) =>
  [...(state.claims.get(hash)?.values() ?? [])].some((holder) => holder === group);
const addClaim = (state, hash, key, group) => {
  if (!state.claims.has(hash)) state.claims.set(hash, new Map());
  state.claims.get(hash).set(key, group);
};

function authorise(state, request, now) {
  const target = endpoint(request);
  if (!target) return R(400, 'bad-request');
  const headers = request.headers.filter(([name]) => name.toLowerCase() === 'authorization');
  if (headers.length !== 1) return R(401, 'missing');
  const value = headers[0][1];
  if (!value.startsWith('Nostr ')) return R(401, 'encoding');
  const bytes = decodeBase64(value.slice('Nostr '.length));
  if (!bytes || bytes.length === 0 || bytes.length > LIMITS.eventBytes) return R(401, 'encoding');
  let event;
  try {
    event = JSON.parse(bytes.toString('utf8'));
  } catch {
    return R(401, 'event');
  }
  if (!strictShape(event) || event.kind !== BLOSSOM_AUTH || event.content.trim() === '' ||
      Buffer.byteLength(event.content) > LIMITS.authContentBytes) {
    return R(401, 'event');
  }
  const named = (name) => event.tags.filter((tag) => tag[0] === name);
  const t = named('t');
  const expiration = named('expiration');
  const servers = named('server');
  const xs = named('x');
  if (t.length !== 1 || t[0].length !== 2 || expiration.length !== 1 || expiration[0].length !== 2 ||
      !DECIMAL.test(expiration[0][1]) || servers.length > LIMITS.authValuesPerTag ||
      xs.length > LIMITS.authValuesPerTag || [...servers, ...xs].some((tag) => tag.length !== 2)) {
    return R(401, 'event');
  }
  if (!signatureValid(event)) return R(401, 'signature');
  if (t[0][1] !== target.verb) return R(401, 'verb');
  if (servers.length === 0 || !servers.some((tag) => state.config.servers.includes(tag[1]))) {
    return R(401, 'server');
  }
  if (!target.hash || !HEX64.test(target.hash)) return R(400, 'bad-request');
  if (xs.length === 0 || xs.some((tag) => !HEX64.test(tag[1])) || !xs.some((tag) => tag[1] === target.hash)) {
    return R(401, 'hash');
  }
  const expires = Number(expiration[0][1]);
  if (event.created_at > now + LIMITS.futureSkew) return R(401, 'future');
  if (expires <= now) return R(401, 'expired');
  if (expires < event.created_at || expires - event.created_at > LIFETIME_BY_VERB[target.verb]) {
    return R(401, 'lifetime');
  }

  const signer = event.pubkey;
  const hash = target.hash;
  const owner = state.config.owners.includes(signer);
  if (target.verb === 'get') {
    if (owner) return state.claims.get(hash)?.size ? R(200, 'ok') : R(404, 'absent');
    if (!activeGrant(state, signer, 'get', now)) return R(403, 'not-granted');
    if (!groupHolds(state, state.groupOfKey.get(signer), hash)) return R(404, 'absent');
    const range = request.headers.some(([name]) => name.toLowerCase() === 'range');
    return range ? R(206, 'partial') : R(200, 'ok');
  }
  if (target.verb === 'upload') {
    if (owner) {
      const existed = state.claims.get(hash)?.size > 0;
      addClaim(state, hash, signer, 'owner');
      return existed ? R(200, 'ok') : R(201, 'created');
    }
    if (!activeGrant(state, signer, 'upload', now)) return R(403, 'not-granted');
    const group = state.groupOfKey.get(signer);
    const held = groupHolds(state, group, hash);
    addClaim(state, hash, signer, group);
    return held ? R(200, 'ok') : R(201, 'created');
  }
  // delete
  const purge = activeGrant(state, signer, 'purge', now);
  const own = activeGrant(state, signer, 'delete', now) || deleteGrace(state, signer, now);
  if (!purge && !own) return R(403, 'not-granted');
  const group = state.groupOfKey.get(signer);
  const present = purge ? groupHolds(state, group, hash) : holds(state, signer, hash);
  if (state.spent.has(event.id)) return present ? R(409, 'spent') : R(404, 'absent');
  if (!present) return R(404, 'absent');
  const claims = state.claims.get(hash);
  if (purge) {
    for (const [key, holder] of [...claims]) if (holder === group) claims.delete(key);
  } else {
    claims.delete(signer);
  }
  if (claims.size === 0) state.claims.delete(hash);
  state.spent.set(event.id, expires);
  return R(200, 'ok');
}

const granted = (state, key, scope, now) => Boolean(activeGrant(state, key, scope, now));

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

function grantEventCases() {
  const alice = (options = {}) => grant({ id: 'alice', device: 'alicePhone', scopes: STORE, bytes: GIB, ...options });
  const swap = (name, value) => (tags) => tags.map((tag) => (tag[0] === name ? [name, value] : tag));
  const cases = [
    ['good-grant', 'A keeper-signed grant for a device with the three storage scopes and a byte ceiling.',
      T0, alice(), [201, 'accepted', 'active']],
    ['good-grant-get-only', 'Read only: no `bytes` tag, because there is no `upload` scope.',
      T0, fixtureGrants.bob(), [201, 'accepted', 'active']],
    ['good-grant-every-scope', 'Every scope at once. A node accepts scopes it does not serve (turn, relays) and ignores them.',
      T0, grant({ id: 'all', device: 'alicePhone', scopes: SCOPES, bytes: GIB }), [201, 'accepted', 'active']],
    ['good-revocation-first', 'A revocation for a grant id this node has never seen is recorded, so the grant cannot land later.',
      T0, alice({ status: 'revoked' }), [201, 'accepted', 'revoked']],
    ['good-reset', 'A reset for one room at one node.',
      T0, reset({ created: T0 }), [201, 'accepted', 'reset']],
    ['good-created-at-skew-limit', '`created_at` exactly 30 seconds ahead of the node clock is accepted.',
      T0, alice({ created: T0 + 30, expiration: T0 + 30 + MONTH }), [201, 'accepted', 'active']],
    ['good-lifetime-limit', '`expiration` exactly 90 days after `created_at`.',
      T0, alice({ expiration: T0 + LIMITS.grantLifetime }), [201, 'accepted', 'active']],
    ['expired', '`expiration` equal to the node clock is expired.',
      T0 + MONTH, alice(), [403, 'expired']],
    ['created-at-beyond-skew', '`created_at` 31 seconds ahead of the node clock.',
      T0, alice({ created: T0 + 31, expiration: T0 + 31 + MONTH }), [403, 'future']],
    ['wrong-node', 'Signed for another node.',
      T0, alice({ server: OTHER_SERVER }), [403, 'server']],
    ['unenrolled-keeper', 'Signed by a key the node owner has not enrolled.',
      T0, alice({ signer: 'authorityC' }), [403, 'keeper']],
    ['bad-signature', 'The last hex digit of `sig` changed.',
      T0, corruptSig(alice()), [401, 'signature']],
    ['id-mismatch', 'A tag changed after signing, so `id` no longer matches.',
      T0, { ...alice(), tags: swap('bytes', String(2 * GIB))(alice().tags) }, [401, 'signature']],
    ['lifetime-too-long', '`expiration` one second more than 90 days after `created_at`.',
      T0, alice({ expiration: T0 + LIMITS.grantLifetime + 1 }), [400, 'lifetime']],
    ['expiration-before-created-at', '`expiration` not after `created_at`.',
      T0 - 10, alice({ created: T0, expiration: T0 }), [400, 'lifetime']],
    ['upload-without-bytes', 'An `upload` scope needs a `bytes` ceiling.',
      T0, alice({ edit: (tags) => tags.filter((tag) => tag[0] !== 'bytes') }), [400, 'malformed']],
    ['bytes-without-upload', 'A `bytes` tag without an `upload` scope.',
      T0, grant({ id: 'bob', device: 'bobLaptop', scopes: ['get'], bytes: GIB }), [400, 'malformed']],
    ['bytes-zero', 'A zero ceiling.',
      T0, alice({ bytes: 0 }), [400, 'malformed']],
    ['bytes-leading-zero', 'Decimals are canonical: no leading zero.',
      T0, alice({ edit: swap('bytes', `0${GIB}`) }), [400, 'malformed']],
    ['unknown-scope', 'A scope outside the table.',
      T0, alice({ edit: (tags) => [...tags, ['scope', 'list']] }), [400, 'malformed']],
    ['duplicate-scope', 'The same scope twice.',
      T0, alice({ edit: (tags) => [...tags, ['scope', 'get']] }), [400, 'malformed']],
    ['duplicate-device', 'Two `device` tags.',
      T0, alice({ edit: (tags) => [...tags, ['device', pub('bobLaptop')]] }), [400, 'malformed']],
    ['persona-tag', "A Bothy-style `p` persona tag. Group grants never name the participant.",
      T0, alice({ edit: (tags) => [...tags, ['p', pub('stranger')]] }), [400, 'malformed']],
    ['recovery-tag', 'A device-grant-style `recovery` tag. Group grants have no recovery identity.',
      T0, alice({ edit: (tags) => [...tags, ['recovery', pub('stranger')]] }), [400, 'malformed']],
    ['tag-with-three-values', 'Every tag has exactly one value.',
      T0, alice({ edit: (tags) => tags.map((tag) => (tag[0] === 'server' ? [...tag, 'wss'] : tag)) }), [400, 'malformed']],
    ['content-not-empty', 'Content must be empty.',
      T0, (() => {
        const base = alice();
        return sign('authorityA', { created_at: base.created_at, kind: KIND, tags: base.tags, content: 'grant' });
      })(), [400, 'malformed']],
    ['uppercase-device', 'Keys are lower-case hex.',
      T0, alice({ edit: swap('device', pub('alicePhone').toUpperCase()) }), [400, 'malformed']],
    ['short-room', '`d` must be 64 hex characters.',
      T0, alice({ d: ROOM_A.slice(0, 62) }), [400, 'malformed']],
    ['short-grant-id', '`grant` must be 32 hex characters.',
      T0, alice({ edit: swap('grant', grantId('alice').slice(0, 30)) }), [400, 'malformed']],
    ['device-is-signer', 'A keeper cannot grant its own key.',
      T0, grant({ id: 'self', device: 'authorityA', scopes: ['get'] }), [400, 'malformed']],
    ['wrong-kind', 'The same tags under the device grant kind 27540.',
      T0, (() => {
        const base = alice();
        return sign('authorityA', { created_at: base.created_at, kind: 27540, tags: base.tags, content: '' });
      })(), [400, 'malformed']],
    ['unknown-status', 'Status is `active` or `revoked`.',
      T0, alice({ status: 'paused' }), [400, 'malformed']],
    ['server-with-scheme', '`server` is a bare lower-case host name.',
      T0, alice({ server: `https://${SERVER}` }), [400, 'malformed']],
    ['reset-with-device', 'A reset names no device.',
      T0, reset({ created: T0, edit: (tags) => [...tags, ['device', pub('alicePhone')]] }), [400, 'malformed']],
    ['extra-event-field', 'An event field outside NIP-01 is refused, so what is verified is what is read.',
      T0, { ...alice(), relay: 'wss://relay.example.net/' }, [400, 'malformed']],
    ['device-is-node-owner', "The node owner's key can never be a group device.",
      T0, grant({ id: 'owner', device: 'nodeOwner', scopes: ['get'] }), [409, 'key-conflict']],
    ['device-is-enrolled-keeper', 'An enrolled keeper key can never be a group device.',
      T0, grant({ id: 'keeper-b', device: 'authorityB', scopes: ['get'] }), [409, 'key-conflict']],
  ];
  return cases.map(([name, note, now, event, [status, reason, state]]) => {
    const expect = { status, reason, ...(state ? { state } : {}) };
    const got = postEvent(newNode(), event, now);
    assert.deepEqual(got, expect, `grantEvents ${name}`);
    return { name, note, now, event, expect };
  });
}

// The state every request case starts from: four grants, then three uploads.
function requestFixture() {
  const steps = [
    ...['alice', 'bob', 'coordinator', 'carol'].map((label) => ({
      now: T0,
      post: fixtureGrants[label](),
      expect: { status: 201, reason: 'accepted', state: 'active' },
    })),
    { now: T0 + 60,
      request: upload('blob1', auth('alicePhone', { verb: 'upload', hashes: [H('blob1')], created: T0 + 59 }).header),
      expect: { status: 201, reason: 'created' } },
    { now: T0 + 60,
      request: upload('blob2', auth('carolPhone', { verb: 'upload', hashes: [H('blob2')], created: T0 + 59 }).header),
      expect: { status: 201, reason: 'created' } },
    { now: T0 + 60,
      request: upload('blob3', auth('nodeOwner', { verb: 'upload', hashes: [H('blob3')], created: T0 + 59 }).header),
      expect: { status: 201, reason: 'created' } },
  ];
  return { note: 'Applied in order to a node with the fixture enrolments before each request case. Each request case starts again from this state.', steps };
}

function runSteps(state, steps, label) {
  for (const [index, step] of steps.entries()) {
    let got;
    if (step.post) got = postEvent(state, step.post, step.now);
    else if (step.request) got = authorise(state, step.request, step.now);
    else got = { granted: granted(state, step.check.key, step.check.scope, step.now) };
    assert.deepEqual(got, step.expect, `${label} step ${index}`);
  }
}

function requestCases(fixture) {
  const now = T0 + 3600;
  const c = now - 1;
  const a = (label, options) => auth(label, { created: c, ...options }).header;
  const getAuth = (label, hash, options = {}) => a(label, { verb: 'get', hashes: [hash], ...options });
  const cases = [
    ['get', 'A granted device reads a blob its group holds.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'))), [200, 'ok']],
    ['get-range', 'A range read is authorised exactly as a full read.',
      get(H('blob1'), getAuth('alicePhone', H('blob1')), [['Range', 'bytes=0-9']]), [206, 'partial']],
    ['head', 'HEAD uses `t=get` too.',
      head(H('blob1'), getAuth('alicePhone', H('blob1'))), [200, 'ok']],
    ['get-other-member', 'Any device of the group with `get` reads what another member uploaded.',
      get(H('blob1'), getAuth('bobLaptop', H('blob1'))), [200, 'ok']],
    ['get-coordinator', "The keeper's coordinator reads for verification.",
      get(H('blob1'), getAuth('coordinatorA', H('blob1'))), [200, 'ok']],
    ['get-base64url', 'BUD-11 base64url without padding decodes as well as standard base64.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { encoding: 'base64url' })), [200, 'ok']],
    ['get-anonymous', 'No Authorization header: knowing the hash is not enough.',
      get(H('blob1')), [401, 'missing']],
    ['get-two-headers', 'Exactly one Authorization header.',
      { ...get(H('blob1'), getAuth('alicePhone', H('blob1'))),
        headers: [['Authorization', getAuth('alicePhone', H('blob1'))], ['Authorization', getAuth('bobLaptop', H('blob1'))]] },
      [401, 'missing']],
    ['get-stranger', 'A valid signature from a key with no grant at this node.',
      get(H('blob1'), getAuth('stranger', H('blob1'))), [403, 'not-granted']],
    ['get-wrong-room', 'A device granted for room B asks for a blob only room A holds: indistinguishable from absent.',
      get(H('blob1'), getAuth('carolPhone', H('blob1'))), [404, 'absent']],
    ['get-other-room-blob', "Room A's device asks for room B's blob.",
      get(H('blob2'), getAuth('alicePhone', H('blob2'))), [404, 'absent']],
    ['get-owner-blob', "A group device cannot read the node owner's own files.",
      get(H('blob3'), getAuth('alicePhone', H('blob3'))), [404, 'absent']],
    ['get-absent', 'A hash nobody holds.',
      get(H('blob4'), getAuth('alicePhone', H('blob4'))), [404, 'absent']],
    ['get-hash-not-covered', 'The `x` tags do not include the requested hash.',
      get(H('blob1'), getAuth('alicePhone', H('blob2'))), [401, 'hash']],
    ['get-without-x', 'BUD-11 makes `x` optional for get; group mode requires it.',
      get(H('blob1'), a('alicePhone', { verb: 'get' })), [401, 'hash']],
    ['get-wrong-server', 'Scoped to another node only.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { servers: [OTHER_SERVER] })), [401, 'server']],
    ['get-without-server', 'BUD-11 allows an unscoped token; group mode refuses it.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { servers: [] })), [401, 'server']],
    ['get-two-servers', 'A token scoped to two nodes, this one among them.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { servers: [OTHER_SERVER, SERVER] })), [200, 'ok']],
    ['get-expired', '`expiration` equal to the node clock.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { created: now - 60, expiration: now })), [401, 'expired']],
    ['get-skew-limit', '`created_at` exactly 30 seconds ahead is accepted.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { created: now + 30 })), [200, 'ok']],
    ['get-beyond-skew', '`created_at` 31 seconds ahead.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { created: now + 31 })), [401, 'future']],
    ['get-lifetime-limit', 'A read token may live 300 seconds.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { lifetime: 300 })), [200, 'ok']],
    ['get-lifetime-too-long', 'A read token of 301 seconds.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { lifetime: 301 })), [401, 'lifetime']],
    ['get-wrong-verb', 'An upload token presented for a read.',
      get(H('blob1'), a('alicePhone', { verb: 'upload', hashes: [H('blob1')] })), [401, 'verb']],
    ['get-bad-signature', 'The token signature does not verify.',
      get(H('blob1'), headerFor(corruptSig(auth('alicePhone', { verb: 'get', hashes: [H('blob1')], created: c }).event))),
      [401, 'signature']],
    ['get-grant-event-as-token', 'A kind 27541 grant presented as a Blossom token is refused: the kinds do not mix.',
      get(H('blob1'), headerFor(fixtureGrants.alice())), [401, 'event']],
    ['get-empty-content', 'BUD-11 content must say what the token is for.',
      get(H('blob1'), getAuth('alicePhone', H('blob1'), { content: '' })), [401, 'event']],
    ['upload', 'A device with `upload` stores a new blob for its group.',
      upload('blob4', a('alicePhone', { verb: 'upload', hashes: [H('blob4')] })), [201, 'created']],
    ['upload-group-already-holds', 'Another device uploads what its group already holds.',
      upload('blob1', a('coordinatorA', { verb: 'upload', hashes: [H('blob1')] })), [200, 'ok']],
    ['upload-other-group-holds', "Room A uploads bytes only room B holds: 201, so the status says nothing about another group.",
      upload('blob2', a('alicePhone', { verb: 'upload', hashes: [H('blob2')] })), [201, 'created']],
    ['upload-without-scope', 'A read-only device cannot upload.',
      upload('blob4', a('bobLaptop', { verb: 'upload', hashes: [H('blob4')] })), [403, 'not-granted']],
    ['upload-stranger', 'No grant, no upload.',
      upload('blob4', a('stranger', { verb: 'upload', hashes: [H('blob4')] })), [403, 'not-granted']],
    ['delete-own', 'The uploader deletes its own claim.',
      del(H('blob1'), a('alicePhone', { verb: 'delete', hashes: [H('blob1')] })), [200, 'ok']],
    ['delete-journal-week', "A delete token may live a week and a second, matching KithMoot's retry journal.",
      del(H('blob1'), a('alicePhone', { verb: 'delete', hashes: [H('blob1')], lifetime: LIMITS.deleteLifetime })),
      [200, 'ok']],
    ['delete-lifetime-too-long', 'One second more than the delete limit.',
      del(H('blob1'), a('alicePhone', { verb: 'delete', hashes: [H('blob1')], lifetime: LIMITS.deleteLifetime + 1 })),
      [401, 'lifetime']],
    ['delete-without-scope', 'A read-only device cannot delete.',
      del(H('blob1'), a('bobLaptop', { verb: 'delete', hashes: [H('blob1')] })), [403, 'not-granted']],
    ['delete-not-own', "Carol's device has `delete` but holds no claim in room A's group.",
      del(H('blob1'), a('carolPhone', { verb: 'delete', hashes: [H('blob1')] })), [404, 'absent']],
    ['purge', "The keeper's coordinator removes the group's claims on a blob another device uploaded.",
      del(H('blob1'), a('coordinatorA', { verb: 'delete', hashes: [H('blob1')] })), [200, 'ok']],
    ['purge-other-group', "Purge reaches only the coordinator's own group.",
      del(H('blob2'), a('coordinatorA', { verb: 'delete', hashes: [H('blob2')] })), [404, 'absent']],
  ];
  return cases.map(([name, note, request, [status, reason]]) => {
    const state = newNode();
    runSteps(state, fixture.steps, 'requestFixture');
    const expect = { status, reason };
    assert.deepEqual(authorise(state, request, now), expect, `requests ${name}`);
    return { name, note, now, request, expect };
  });
}

function sequenceCases() {
  const ok = (state) => ({ status: 201, reason: 'accepted', state });
  const aliceGrant = (options = {}) =>
    grant({ id: 'alice', device: 'alicePhone', scopes: STORE, bytes: GIB, ...options });
  const check = (now, key, scope, value) => ({ now, check: { key: pub(key), scope }, expect: { granted: value } });
  const sequences = [];
  const add = (name, note, steps) => {
    runSteps(newNode(), steps, `sequence ${name}`);
    sequences.push({ name, note, steps });
  };

  const renewed = aliceGrant({ created: T0 + 10 * DAY, expiration: T0 + 40 * DAY });
  const revoked = aliceGrant({ status: 'revoked', created: T0 + 11 * DAY, expiration: T0 + 40 * DAY });
  add('renew-revoke-readmit',
    'Renewal reuses the grant id with a later created_at; revocation is terminal for that id; re-admission uses a new id.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0 + 1, post: aliceGrant(), expect: { status: 200, reason: 'unchanged' } },
      { now: T0 + 10 * DAY, post: renewed, expect: ok('active') },
      { now: T0 + 10 * DAY, post: aliceGrant(), expect: { status: 409, reason: 'stale' } },
      check(T0 + 10 * DAY, 'alicePhone', 'get', true),
      { now: T0 + 11 * DAY, post: revoked, expect: ok('revoked') },
      check(T0 + 11 * DAY, 'alicePhone', 'get', false),
      { now: T0 + 11 * DAY, post: renewed, expect: { status: 409, reason: 'stale' } },
      { now: T0 + 12 * DAY,
        post: aliceGrant({ created: T0 + 12 * DAY, expiration: T0 + 42 * DAY }),
        expect: { status: 409, reason: 'revoked' } },
      { now: T0 + 12 * DAY,
        post: grant({ id: 'alice-2', device: 'alicePhone', scopes: STORE, bytes: GIB,
          created: T0 + 12 * DAY, expiration: T0 + 42 * DAY }),
        expect: ok('active') },
      check(T0 + 12 * DAY, 'alicePhone', 'get', true),
    ]);

  add('revocation-before-grant',
    'A node that was offline gets the revocation (from the keeper or any member) before the device posts its old grant.',
    [
      { now: T0 + DAY, post: aliceGrant({ status: 'revoked', created: T0 + DAY }), expect: ok('revoked') },
      { now: T0 + DAY + 5, post: aliceGrant(), expect: { status: 409, reason: 'stale' } },
      check(T0 + DAY + 5, 'alicePhone', 'get', false),
    ]);

  add('reset-and-regrant',
    'A reset ends every grant of the room at the node that is not newer than it; later grants or renewals land again.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0, post: fixtureGrants.bob(), expect: ok('active') },
      { now: T0 + DAY, post: reset({ created: T0 + DAY }), expect: ok('reset') },
      check(T0 + DAY, 'alicePhone', 'get', false),
      check(T0 + DAY, 'bobLaptop', 'get', false),
      { now: T0 + DAY,
        post: aliceGrant({ created: T0 + DAY, expiration: T0 + 31 * DAY }),
        expect: { status: 409, reason: 'floor' } },
      { now: T0 + DAY + 1,
        post: aliceGrant({ created: T0 + DAY + 1, expiration: T0 + 31 * DAY }),
        expect: ok('active') },
      check(T0 + DAY + 1, 'alicePhone', 'get', true),
      check(T0 + DAY + 1, 'bobLaptop', 'get', false),
      { now: T0 + DAY + 2, post: reset({ created: T0 + 12 * 3600 }), expect: { status: 409, reason: 'stale' } },
    ]);

  add('same-second',
    'Two different events for one grant id in the same second: the second is refused, so the keeper signs again a second later.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0, post: aliceGrant({ bytes: 2 * GIB }), expect: { status: 409, reason: 'stale' } },
      { now: T0 + 1, post: aliceGrant({ bytes: 2 * GIB, created: T0 + 1, expiration: T0 + 1 + MONTH }), expect: ok('active') },
    ]);

  add('one-grant-per-device-and-node',
    "A grant id's scope (room, device, node) never changes, and a device has one active grant per room and node.",
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0 + 1,
        post: grant({ id: 'alice-again', device: 'alicePhone', scopes: ['get'], created: T0 + 1, expiration: T0 + MONTH }),
        expect: { status: 409, reason: 'scope-taken' } },
      { now: T0 + 2,
        post: grant({ id: 'alice', device: 'bobLaptop', scopes: ['get'], created: T0 + 2, expiration: T0 + MONTH }),
        expect: { status: 409, reason: 'scope-changed' } },
    ]);

  add('expiry-boundary', 'A grant is active until the second before its expiration.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      check(T0 + MONTH - 1, 'alicePhone', 'upload', true),
      check(T0 + MONTH, 'alicePhone', 'upload', false),
    ]);

  add('scope-is-per-grant', 'A read-only grant does not allow uploads or deletes.',
    [
      { now: T0, post: fixtureGrants.bob(), expect: ok('active') },
      check(T0, 'bobLaptop', 'get', true),
      check(T0, 'bobLaptop', 'upload', false),
      check(T0, 'bobLaptop', 'delete', false),
    ]);

  add('key-in-two-rooms',
    'A device key belongs to one group at a node. KithMoot device keys are per room, so this only refuses a mistake or an attack.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0,
        post: grant({ signer: 'authorityB', id: 'alice-b', d: ROOM_B, device: 'alicePhone', scopes: ['get'] }),
        expect: { status: 409, reason: 'key-conflict' } },
    ]);

  const t1 = T0 + 3600;
  const d1 = auth('alicePhone', { verb: 'delete', hashes: [H('blob1')], created: t1, lifetime: LIMITS.deleteLifetime });
  const revokedAt = T0 + 2 * DAY;
  add('delete-replay-and-grace',
    'A delete token is spent once; a revoked device keeps only deletion of its own claims, for seven days.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0 + 60,
        request: upload('blob1', auth('alicePhone', { verb: 'upload', hashes: [H('blob1')], created: T0 + 59 }).header),
        expect: { status: 201, reason: 'created' } },
      { now: T0 + 60,
        request: upload('blob4', auth('alicePhone', { verb: 'upload', hashes: [H('blob4')], created: T0 + 59 }).header),
        expect: { status: 201, reason: 'created' } },
      { now: t1 + 1, request: del(H('blob1'), d1.header), expect: { status: 200, reason: 'ok' } },
      { now: t1 + 2, request: del(H('blob1'), d1.header), expect: { status: 404, reason: 'absent' } },
      { now: t1 + 60,
        request: upload('blob1', auth('alicePhone', { verb: 'upload', hashes: [H('blob1')], created: t1 + 59 }).header),
        expect: { status: 201, reason: 'created' } },
      { now: t1 + 61, request: del(H('blob1'), d1.header), expect: { status: 409, reason: 'spent' } },
      { now: revokedAt, post: aliceGrant({ status: 'revoked', created: revokedAt }), expect: ok('revoked') },
      { now: revokedAt + 60,
        request: get(H('blob1'), auth('alicePhone', { verb: 'get', hashes: [H('blob1')], created: revokedAt + 59 }).header),
        expect: { status: 403, reason: 'not-granted' } },
      { now: revokedAt + 60,
        request: upload('blob4', auth('alicePhone', { verb: 'upload', hashes: [H('blob4')], created: revokedAt + 59 }).header),
        expect: { status: 403, reason: 'not-granted' } },
      { now: revokedAt + 120,
        request: del(H('blob1'), auth('alicePhone', { verb: 'delete', hashes: [H('blob1')], created: revokedAt + 119 }).header),
        expect: { status: 200, reason: 'ok' } },
      { now: revokedAt + LIMITS.selfDeleteGrace,
        request: del(H('blob4'), auth('alicePhone', { verb: 'delete', hashes: [H('blob4')],
          created: revokedAt + LIMITS.selfDeleteGrace - 1 }).header),
        expect: { status: 403, reason: 'not-granted' } },
    ]);

  add('removed-device-cannot-read',
    'Group claims stay with the group when the uploader is removed: other members still read, the removed device does not.',
    [
      { now: T0, post: aliceGrant(), expect: ok('active') },
      { now: T0, post: fixtureGrants.bob(), expect: ok('active') },
      { now: T0 + 60,
        request: upload('blob1', auth('alicePhone', { verb: 'upload', hashes: [H('blob1')], created: T0 + 59 }).header),
        expect: { status: 201, reason: 'created' } },
      { now: T0 + DAY, post: aliceGrant({ status: 'revoked', created: T0 + DAY }), expect: ok('revoked') },
      { now: T0 + DAY + 60,
        request: get(H('blob1'), auth('alicePhone', { verb: 'get', hashes: [H('blob1')], created: T0 + DAY + 59 }).header),
        expect: { status: 403, reason: 'not-granted' } },
      { now: T0 + DAY + 60,
        request: get(H('blob1'), auth('bobLaptop', { verb: 'get', hashes: [H('blob1')], created: T0 + DAY + 59 }).header),
        expect: { status: 200, reason: 'ok' } },
    ]);
  return sequences;
}

// ---------------------------------------------------------------------------
// Independent signature check with nostr-tools
// ---------------------------------------------------------------------------

function eventsIn(document) {
  const found = [];
  const fromHeader = (header) => {
    const bytes = decodeBase64(header.slice('Nostr '.length));
    return JSON.parse(bytes.toString('utf8'));
  };
  const fromRequest = (request, expect) => {
    for (const [name, value] of request.headers) {
      if (name.toLowerCase() === 'authorization') found.push({ event: fromHeader(value), expect });
    }
  };
  for (const item of document.grantEvents) found.push({ event: item.event, expect: item.expect });
  for (const step of document.requestFixture.steps) {
    if (step.post) found.push({ event: step.post, expect: step.expect });
    if (step.request) fromRequest(step.request, step.expect);
  }
  for (const item of document.requests) fromRequest(item.request, item.expect);
  for (const sequence of document.sequences) {
    for (const step of sequence.steps) {
      if (step.post) found.push({ event: step.post, expect: step.expect });
      if (step.request) fromRequest(step.request, step.expect);
    }
  }
  return found;
}

function crossCheck(document) {
  let verified = 0;
  for (const { event, expect } of eventsIn(document)) {
    const shapeOnly = Object.fromEntries(
      ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'].map((key) => [key, event[key]]),
    );
    const valid = verifyEvent(clone(shapeOnly));
    assert.equal(valid, expect.reason !== 'signature', `nostr-tools disagrees on ${event.id}`);
    verified += 1;
  }
  return verified;
}

// ---------------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------------

function build() {
  const fixture = requestFixture();
  runSteps(newNode(), fixture.steps, 'requestFixture');
  const document = {
    profile: 'group-grants/1',
    syntheticOnly: true,
    generatedBy:
      `scripts/group-grants/vectors.mjs: @noble/curves ${versions.curves} BIP-340 signatures with 32 zero bytes ` +
      `of auxiliary randomness, node:crypto SHA-256 and HKDF, every outcome checked against a reference model ` +
      `of docs/GROUP-GRANTS.md, every id and signature re-checked with nostr-tools ${versions.nostrTools} verifyEvent`,
    spec: 'docs/GROUP-GRANTS.md',
    kind: KIND,
    limits: LIMITS,
    scopes: SCOPES,
    time: { t0: T0, note: 'Each case carries its own node clock in `now`.' },
    keys,
    rooms,
    node,
    blobs,
    grantEvents: grantEventCases(),
    requestFixture: fixture,
    requests: requestCases(fixture),
    sequences: sequenceCases(),
  };
  return document;
}

const mode = process.argv[2];
if (mode !== '--write' && mode !== '--check') {
  console.error('usage: node vectors.mjs --write | --check');
  process.exit(2);
}
// Two-space JSON, except that an array holding only strings and numbers (a
// tag, a header, a list of scopes) stays on one line.
function format(value, indent = '') {
  const inner = `${indent}  `;
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    if (value.every((item) => typeof item === 'string' || typeof item === 'number')) {
      return `[${value.map((item) => JSON.stringify(item)).join(', ')}]`;
    }
    return `[\n${value.map((item) => inner + format(item, inner)).join(',\n')}\n${indent}]`;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) return '{}';
    return `{\n${entries.map(([key, item]) => `${inner}${JSON.stringify(key)}: ${format(item, inner)}`).join(',\n')}\n${indent}}`;
  }
  return JSON.stringify(value);
}

const document = build();
const text = `${format(document)}\n`;
assert.deepEqual(JSON.parse(text), JSON.parse(JSON.stringify(document)));
const verified = crossCheck(JSON.parse(text));
if (mode === '--write') {
  writeFileSync(output, text);
  console.log(`wrote ${output}: ${document.grantEvents.length} grant events, ${document.requests.length} requests, ` +
    `${document.sequences.length} sequences, ${verified} signed events re-checked with nostr-tools`);
} else {
  const committed = readFileSync(output, 'utf8');
  assert.equal(committed, text, 'vectors/group-grants-v1.json differs from a fresh build');
  crossCheck(JSON.parse(committed));
  console.log(`vectors/group-grants-v1.json matches a fresh build; ${verified} signed events re-checked with nostr-tools`);
}
