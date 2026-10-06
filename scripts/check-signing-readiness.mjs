// Read names only. Never fetch, print or export secret values or private keys.
import { execFileSync } from 'node:child_process';
const names = new Set(JSON.parse(execFileSync('gh', ['secret', 'list', '--repo', 'forgesworn/wildbloom-node', '--json', 'name'], { encoding: 'utf8' })).map(({name}) => name));
const groups = {
  updater: ['TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD'],
  macOS: ['APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD', 'APPLE_SIGNING_IDENTITY', 'APPLE_ID', 'APPLE_PASSWORD', 'APPLE_TEAM_ID'],
  Windows: ['WINDOWS_CERTIFICATE', 'WINDOWS_CERTIFICATE_PASSWORD', 'WINDOWS_TIMESTAMP_URL'],
};
let missing = false;
for (const [platform, required] of Object.entries(groups)) {
  const absent = required.filter(name => !names.has(name));
  console.log(`${platform}: ${absent.length ? `missing ${absent.join(', ')}` : 'names configured; credential validity still needs a signed build'}`);
  missing ||= absent.length > 0;
}
process.exitCode = missing ? 1 : 0;
