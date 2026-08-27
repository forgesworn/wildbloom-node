#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <bundle-directory>" >&2
  exit 2
fi

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

bundle_directory="$1"
package_path="$(find "$bundle_directory" -type f -name '*.deb' -print -quit)"
if [ -z "$package_path" ]; then
  echo "the Linux bundle does not contain a deb package" >&2
  exit 1
fi
package_path="$(realpath "$package_path")"

package_name="$(dpkg-deb --field "$package_path" Package)"
runtime_root="$(mktemp -d "$RUNNER_TEMP/wildbloom-linux-runtime.XXXXXX")"
export XDG_DATA_HOME="$runtime_root/data"
export XDG_CONFIG_HOME="$runtime_root/config"
export XDG_CACHE_HOME="$runtime_root/cache"
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

app_pid=""
xvfb_pid=""

cleanup() {
  if [ -n "$app_pid" ] && kill -0 "$app_pid" 2>/dev/null; then
    kill -KILL "$app_pid" 2>/dev/null || true
  fi
  if [ -n "$xvfb_pid" ] && kill -0 "$xvfb_pid" 2>/dev/null; then
    kill -TERM "$xvfb_pid" 2>/dev/null || true
  fi
  if [ -n "${DBUS_SESSION_BUS_PID:-}" ]; then
    kill -TERM "$DBUS_SESSION_BUS_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sudo apt-get install --yes "$package_path"
executable="$(command -v wildbloom-desktop)"
test -x "$executable"
tor_binary="$(dpkg-query --listfiles "$package_name" | awk '/\/tor-runtime\/tor\/tor$/ && !found { print; found = 1 }')"
if [ -z "$tor_binary" ] || [ ! -x "$tor_binary" ]; then
  echo "the installed package manifest does not contain an executable Tor runtime" >&2
  exit 1
fi
tor_library_dir="$(dirname "$tor_binary")"
LD_LIBRARY_PATH="$tor_library_dir" "$tor_binary" --version | grep -Eq '^Tor version [0-9]+\.'
if LD_LIBRARY_PATH="$tor_library_dir" ldd "$tor_binary" | grep -q 'not found'; then
  echo "the packaged Tor runtime has an unresolved shared library" >&2
  LD_LIBRARY_PATH="$tor_library_dir" ldd "$tor_binary" >&2
  exit 1
fi
echo "installed Linux package contains an executable Tor runtime with resolved libraries"

Xvfb :99 -screen 0 1280x800x24 -nolisten tcp >"$runtime_root/xvfb.log" 2>&1 &
xvfb_pid="$!"
export DISPLAY=:99
for _ in $(seq 1 30); do
  test -S /tmp/.X11-unix/X99 && break
  sleep 1
done
test -S /tmp/.X11-unix/X99

eval "$(dbus-launch --sh-syntax)"
"$executable" >"$runtime_root/app.stdout.log" 2>"$runtime_root/app.stderr.log" &
app_pid="$!"

hostname_path=""
database_path=""
node_port=""
ready=0
for _ in $(seq 1 360); do
  if ! kill -0 "$app_pid" 2>/dev/null; then
    echo "the installed desktop process stopped before it became ready" >&2
    sed -n '1,160p' "$runtime_root/app.stderr.log" >&2
    exit 1
  fi

  hostname_path="$(find "$XDG_DATA_HOME" -type f -path '*/tor/onion-service/hostname' -print -quit 2>/dev/null || true)"
  database_path="$(find "$XDG_DATA_HOME" -type f -name wildbloom.sqlite3 -print -quit 2>/dev/null || true)"
  node_port="$(
    ps -eo args= \
      | awk -v root="$runtime_root" \
        'index($0, "wildbloomd") && index($0, root) && !found { print; found = 1 }' \
      | sed -n 's/.*--bind 127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p'
  )"

  if [ -n "$hostname_path" ] && [ -n "$database_path" ] && [ -n "$node_port" ]; then
    onion="$(tr -d '\r\n' < "$hostname_path")"
    if [[ "$onion" =~ ^[a-z2-7]{56}\.onion$ ]] \
      && health="$(curl --fail --silent --max-time 2 "http://127.0.0.1:$node_port/healthz" 2>/dev/null)" \
      && jq -e '.storage.blobs == 0 and .storage.bytes == 0 and .storage.quota_bytes == 10737418240' \
        >/dev/null <<<"$health"; then
      ready=1
      break
    fi
  fi
  sleep 1
done

if [ "$ready" != "1" ]; then
  echo "the installed Linux desktop did not reach Tor and Blossom readiness" >&2
  printf 'hostname-file=%s database-file=%s node-port=%s\n' \
    "$([ -n "$hostname_path" ] && printf present || printf absent)" \
    "$([ -n "$database_path" ] && printf present || printf absent)" \
    "$([ -n "$node_port" ] && printf present || printf absent)" >&2
  sed -n '1,200p' "$runtime_root/app.stdout.log" >&2
  sed -n '1,200p' "$runtime_root/app.stderr.log" >&2
  exit 1
fi
echo "installed Linux desktop reached Tor and Blossom readiness"

if [ "$(stat -c '%a' "$database_path")" != "600" ]; then
  echo "the installed desktop created its database with unsafe permissions" >&2
  exit 1
fi
secret_key="$(find "$XDG_DATA_HOME" -type f -name hs_ed25519_secret_key -print -quit)"
if [ -z "$secret_key" ]; then
  echo "the installed desktop did not create an onion-service secret key" >&2
  exit 1
fi
if [ "$(stat -c '%a' "$secret_key")" != "600" ]; then
  echo "the installed desktop created its onion key with unsafe permissions" >&2
  exit 1
fi
echo "installed Linux desktop kept its database and onion key private"

"$executable" >"$runtime_root/second.stdout.log" 2>"$runtime_root/second.stderr.log" &
second_pid="$!"
for _ in $(seq 1 20); do
  if ! kill -0 "$second_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "$second_pid" 2>/dev/null; then
  echo "a second installed desktop instance remained running" >&2
  kill -TERM "$second_pid" 2>/dev/null || true
  exit 1
fi
wait "$second_pid" || true

if ! kill -0 "$app_pid" 2>/dev/null; then
  echo "the original desktop process stopped during the second launch" >&2
  exit 1
fi
echo "installed Linux desktop enforced one application instance"

kill -KILL "$app_pid"
for _ in $(seq 1 30); do
  if ! kill -0 "$app_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
if kill -0 "$app_pid" 2>/dev/null; then
  echo "the installed desktop process did not stop after SIGKILL" >&2
  exit 1
fi
wait "$app_pid" || true
app_pid=""

for _ in $(seq 1 30); do
  remaining_children="$(ps -eo args= | awk -v root="$runtime_root" 'index($0, root) && (index($0, "wildbloomd") || index($0, "/tor")) { count += 1 } END { print count + 0 }')"
  test "$remaining_children" = "0" && break
  sleep 1
done
if [ "$remaining_children" != "0" ]; then
  echo "a bundled Tor or Wildbloom child remained after the desktop stopped" >&2
  exit 1
fi
echo "installed Linux desktop stopped its bundled children after an abrupt parent death"

sudo apt-get remove --purge --yes "$package_name"
if dpkg-query --show "$package_name" >/dev/null 2>&1; then
  echo "the deb package remained installed after removal" >&2
  exit 1
fi
if command -v wildbloom-desktop >/dev/null 2>&1; then
  echo "the desktop executable remained on PATH after removal" >&2
  exit 1
fi

echo "installed Linux desktop reached Tor and Blossom readiness, enforced one instance, survived an abrupt parent death and uninstalled"
