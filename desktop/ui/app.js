const invoke = window.__TAURI__.core.invoke;

const elements = {
  phase: document.querySelector("#phase"),
  detail: document.querySelector("#detail"),
  dot: document.querySelector("#status-dot"),
  onion: document.querySelector("#onion"),
  blobs: document.querySelector("#blob-count"),
  used: document.querySelector("#used-space"),
  free: document.querySelector("#free-space"),
  pubkey: document.querySelector("#pubkey"),
  writeStatus: document.querySelector("#write-status"),
  quota: document.querySelector("#quota"),
  autostart: document.querySelector("#autostart"),
  form: document.querySelector("#settings-form"),
  restart: document.querySelector("#restart"),
  checkUpdate: document.querySelector("#check-update"),
  updateStatus: document.querySelector("#update-status"),
  saveStatus: document.querySelector("#save-status"),
};

let settingsLoaded = false;
let updateAvailable = false;

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** exponent)).toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

async function refresh() {
  try {
    const status = await invoke("node_status");
    elements.phase.textContent = status.phaseLabel;
    elements.detail.textContent = status.detail;
    elements.dot.className = status.phase === "ready" ? "ready" : status.phase === "error" ? "error" : "";
    elements.onion.textContent = status.onionUrl || "Waiting for Tor…";
    elements.blobs.textContent = String(status.storage?.blobs ?? 0);
    elements.used.textContent = formatBytes(status.storage?.bytes ?? 0);
    const free = Math.max(0, (status.storage?.quotaBytes ?? 0) - (status.storage?.bytes ?? 0));
    elements.free.textContent = formatBytes(free);
    elements.writeStatus.textContent = status.settings.allowedPubkey
      ? "Only this public key may upload, mirror or delete blobs."
      : "The node is read-only until you add a public key.";
    if (!settingsLoaded) {
      elements.pubkey.value = status.settings.allowedPubkey || "";
      elements.quota.value = String(status.settings.quotaGib);
      elements.autostart.checked = status.settings.startAtLogin;
      settingsLoaded = true;
    }
  } catch (error) {
    elements.phase.textContent = "Unavailable";
    elements.detail.textContent = String(error);
    elements.dot.className = "error";
  }
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = elements.form.querySelector("button[type=submit]");
  submit.disabled = true;
  elements.saveStatus.textContent = "Saving…";
  try {
    await invoke("save_settings", {
      settings: {
        allowedPubkey: elements.pubkey.value.trim() || null,
        quotaGib: Number(elements.quota.value),
        startAtLogin: elements.autostart.checked,
      },
    });
    elements.saveStatus.textContent = "Saved.  Restarting the node.";
    settingsLoaded = false;
    await refresh();
  } catch (error) {
    elements.saveStatus.textContent = String(error);
  } finally {
    submit.disabled = false;
  }
});

elements.restart.addEventListener("click", async () => {
  elements.restart.disabled = true;
  try {
    await invoke("restart_node");
  } catch (error) {
    elements.detail.textContent = String(error);
    elements.dot.className = "error";
  } finally {
    elements.restart.disabled = false;
    await refresh();
  }
});

elements.checkUpdate.addEventListener("click", async () => {
  elements.checkUpdate.disabled = true;
  elements.updateStatus.textContent = updateAvailable
    ? "Downloading and verifying the update…"
    : "Checking the signed release feed…";
  try {
    if (updateAvailable) {
      await invoke("install_update");
      return;
    }
    const update = await invoke("check_for_update");
    if (!update.available) {
      elements.updateStatus.textContent = "Wildbloom Node is up to date.";
      return;
    }
    elements.updateStatus.textContent = `Version ${update.version} is signed and available.`;
    updateAvailable = true;
    elements.checkUpdate.textContent = "Install and restart";
  } catch (error) {
    elements.updateStatus.textContent = String(error);
  } finally {
    elements.checkUpdate.disabled = false;
  }
});

refresh();
setInterval(refresh, 2000);
