import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

assert.ok(['darwin', 'linux', 'win32'].includes(process.platform), 'Unsupported desktop platform');
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const exe = process.platform === 'win32' ? '.exe' : '';
const run = (command, args) => execFileSync(command, args, { cwd: repo, stdio: 'inherit' });
const version = execFileSync('rustc', ['-vV'], { encoding: 'utf8' });
const target = version.match(/^host: (\S+)$/m)?.[1];
assert.ok(target, 'rustc did not report a host target');
run('cargo', ['build', '--locked', '-p', 'wildbloomd', '--bin', 'wildbloomd', '--example', 'acceptance_signer']);
const binaries = join(repo, 'desktop/src-tauri/binaries');
mkdirSync(binaries, { recursive: true });
copyFileSync(join(repo, `target/debug/wildbloomd${exe}`), join(binaries, `wildbloomd-${target}${exe}`));
run('cargo', ['build', '--locked', '--manifest-path', 'desktop/src-tauri/Cargo.toml', '--features', 'native-acceptance']);
run(process.execPath, ['desktop/tests/native-pools.mjs']);
