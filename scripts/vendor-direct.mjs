// Builds desktop/ui/vendor/wildbloom-direct.js: the web project's direct-send
// TypeScript (DirectPeer, receiveEnvelope and the frames) as one ES module for
// Drop's hidden direct window, so Drop runs the same code as the browser
// instead of a second implementation.
//
//   node scripts/vendor-direct.mjs --checkout ../wildbloom --commit <sha>
//       Builds from that commit of a wildbloom checkout and writes the bundle
//       and its provenance. Sources are read with `git show`, so the
//       checkout's branch and working tree are never touched. The bundler is
//       the checkout's own esbuild (from its node_modules); nothing is added
//       to this repository.
//   node scripts/vendor-direct.mjs --check
//       Checks that the committed bundle's SHA-256 matches its provenance.
//   node scripts/vendor-direct.mjs --check --checkout ../wildbloom
//       Also rebuilds from the provenance's commit and checks that the result
//       is byte for byte the committed bundle.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPOSITORY = 'https://github.com/forgesworn/wildbloom';
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const vendor = join(repo, 'desktop/ui/vendor');
const bundlePath = join(vendor, 'wildbloom-direct.js');
const provenancePath = join(vendor, 'wildbloom-direct.provenance.json');

// Exactly what the hidden window needs, and the frame helpers its tests use.
const ENTRY = [
  'export { DirectPeer, NoRelayError } from "./src/direct/peer.ts";',
  'export { receiveEnvelope, TransferError, SinkStorageError } from "./src/direct/transfer.ts";',
  'export { FRAME_TYPE, FrameError, decodeFrame, encodeAck, encodeData, encodeEnd, encodeKept, encodeStop } from "./src/direct/frames.ts";',
  '',
].join('\n');

// config.ts ends by reading Vite's `import.meta.env` for the page's ICE
// allowlist. Drop never reads that list (Rust chooses the servers), and the
// expression throws outside Vite, so exactly that line is left out.
const CONFIG = 'src/direct/config.ts';
const ENV_LINE = 'export const DIRECT_ICE_ALLOWLIST: readonly string[] = parseIceAllowlist(import.meta.env.VITE_WILDBLOOM_DIRECT_ICE);';

const OPTIONS = Object.freeze({
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  minify: false,
  treeShaking: true,
  sourcemap: false,
  legalComments: 'none',
  charset: 'utf8',
  // DEFAULT_DIRECT_ICE_URLS is frozen at the top level; once nothing reads it, it goes.
  pure: ['Object.freeze'],
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function args(argv) {
  const out = { check: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--check') out.check = true;
    else if (arg === '--checkout') out.checkout = resolve(argv[++i] ?? '');
    else if (arg === '--commit') out.commit = argv[++i];
    else throw new Error(`Unknown argument ${arg}`);
  }
  return out;
}

function git(checkout, ...rest) {
  return execFileSync('git', ['-C', checkout, ...rest], { encoding: 'buffer', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 });
}

/** Builds the bundle from `commit` of the checkout, in memory. */
async function build(checkout, commit) {
  const full = git(checkout, 'rev-parse', '--verify', `${commit}^{commit}`).toString().trim();
  assert.match(full, /^[0-9a-f]{40}$/u);
  const origin = git(checkout, 'remote', 'get-url', 'origin').toString().trim();
  assert.match(origin, /forgesworn\/wildbloom(?:\.git)?$/u, 'The checkout is not forgesworn/wildbloom.');
  const require = createRequire(join(checkout, 'package.json'));
  const esbuild = require('esbuild');
  const sources = new Map();
  const read = (path) => {
    const text = git(checkout, 'show', `${full}:${path}`).toString('utf8');
    sources.set(path, sha256(Buffer.from(text, 'utf8')));
    return text;
  };
  const plugin = {
    name: 'wildbloom-at-commit',
    setup(builder) {
      builder.onResolve({ filter: /^wildbloom-direct-entry$/ }, () => ({ path: 'entry.ts', namespace: 'commit' }));
      builder.onResolve({ filter: /^\.\.?\// }, (args) => {
        assert.equal(args.namespace, 'commit', `An import from outside the commit: ${args.path}`);
        // The sources import `./x.js` for `./x.ts`.
        const path = posix.normalize(posix.join(posix.dirname(args.importer), args.path)).replace(/\.js$/u, '.ts');
        assert.ok(path.startsWith('src/direct/'), `The bundle may only take src/direct, not ${path}`);
        return { path, namespace: 'commit' };
      });
      builder.onResolve({ filter: /.*/ }, (args) => {
        throw new Error(`A bare import the bundle does not allow: ${args.path}`);
      });
      builder.onLoad({ filter: /.*/, namespace: 'commit' }, (args) => {
        if (args.path === 'entry.ts') return { contents: ENTRY, loader: 'ts', resolveDir: '' };
        let contents = read(args.path);
        if (args.path === CONFIG) {
          const parts = contents.split(ENV_LINE);
          assert.equal(parts.length, 2, `${CONFIG} no longer ends with the line this script leaves out; check it by hand.`);
          contents = parts.join('');
        }
        return { contents, loader: 'ts' };
      });
    },
  };
  const banner = `// Generated by scripts/vendor-direct.mjs from ${REPOSITORY} at ${full}.\n// Do not edit: rebuild it. Provenance: wildbloom-direct.provenance.json.`;
  const result = await esbuild.build({
    ...OPTIONS,
    entryPoints: ['wildbloom-direct-entry'],
    write: false,
    outfile: 'wildbloom-direct.js',
    banner: { js: banner },
    plugins: [plugin],
    logLevel: 'silent',
  });
  assert.equal(result.outputFiles.length, 1);
  const bytes = Buffer.from(result.outputFiles[0].contents);
  const text = bytes.toString('utf8');
  for (const absent of ['import.meta', 'kithmoot', 'parseIceAllowlist', 'console.']) {
    assert.ok(!text.includes(absent), `The bundle must not contain ${absent}`);
  }
  for (const name of ['DirectPeer', 'NoRelayError', 'receiveEnvelope', 'TransferError', 'SinkStorageError', 'encodeStop']) {
    assert.match(text, new RegExp(`^export \\{[^}]*\\b${name}\\b`, 'mu'), `The bundle exports ${name}`);
  }
  const provenance = {
    schema: 'wildbloom-node.vendor.v1',
    bundle: 'desktop/ui/vendor/wildbloom-direct.js',
    repository: REPOSITORY,
    commit: full,
    sources: Object.fromEntries([...sources.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([path, hash]) => [path, { sha256: hash }])),
    omitted: { [CONFIG]: 'the last line, the page build-time ICE allowlist read from import.meta.env; Drop never uses it' },
    builder: { name: 'esbuild', version: esbuild.version, options: { ...OPTIONS } },
    sha256: sha256(bytes),
  };
  return { bytes, provenance };
}

function check() {
  assert.ok(existsSync(bundlePath) && existsSync(provenancePath), 'The vendored bundle or its provenance is missing.');
  const provenance = JSON.parse(readFileSync(provenancePath, 'utf8'));
  const bytes = readFileSync(bundlePath);
  assert.equal(sha256(bytes), provenance.sha256, 'The committed bundle does not match its provenance: rebuild it with scripts/vendor-direct.mjs.');
  assert.ok(bytes.toString('utf8').startsWith(`// Generated by scripts/vendor-direct.mjs from ${provenance.repository} at ${provenance.commit}.`), 'The bundle names another commit than its provenance.');
  return { provenance, bytes };
}

const options = args(process.argv.slice(2));
if (options.check) {
  const { provenance, bytes } = check();
  if (options.checkout) {
    const rebuilt = await build(options.checkout, provenance.commit);
    assert.ok(rebuilt.bytes.equals(bytes), 'A rebuild from the provenance commit differs from the committed bundle.');
    assert.deepEqual(rebuilt.provenance, provenance, 'A rebuild records different provenance.');
    console.log(`ok  the bundle rebuilds byte for byte from ${provenance.commit}`);
  }
  console.log(`ok  wildbloom-direct.js matches its provenance (${provenance.sha256})`);
} else {
  assert.ok(options.checkout && options.commit, 'Usage: node scripts/vendor-direct.mjs --checkout <wildbloom checkout> --commit <sha>');
  const { bytes, provenance } = await build(options.checkout, options.commit);
  mkdirSync(vendor, { recursive: true });
  writeFileSync(bundlePath, bytes);
  writeFileSync(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);
  console.log(`wrote desktop/ui/vendor/wildbloom-direct.js (${bytes.length} bytes, ${provenance.sha256}) from ${provenance.commit}`);
}
