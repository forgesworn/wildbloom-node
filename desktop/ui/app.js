const invoke = window.__TAURI__.core.invoke;

const elements = {
  phase: document.querySelector("#phase"),
  detail: document.querySelector("#detail"),
  dot: document.querySelector("#status-dot"),
  address: document.querySelector("#node-address"),
  addressHint: document.querySelector("#address-hint"),
  blobs: document.querySelector("#blob-count"),
  used: document.querySelector("#used-space"),
  free: document.querySelector("#free-space"),
  pubkey: document.querySelector("#pubkey"),
  friendGrants: document.querySelector("#friend-grants"),
  openShelter: document.querySelector("#open-shelter"),
  writeStatus: document.querySelector("#write-status"),
  quota: document.querySelector("#quota"),
  autostart: document.querySelector("#autostart"),
  transport: document.querySelector("#transport"),
  directFields: document.querySelector("#direct-fields"),
  directPort: document.querySelector("#direct-port"),
  directPublicUrl: document.querySelector("#direct-public-url"),
  form: document.querySelector("#settings-form"),
  restart: document.querySelector("#restart"),
  checkUpdate: document.querySelector("#check-update"),
  updateStatus: document.querySelector("#update-status"),
  saveStatus: document.querySelector("#save-status"),
};

let settingsLoaded = false;
let updateAvailable = false;

function updateTransportFields() {
  const direct = elements.transport.value === "direct";
  elements.directFields.hidden = !direct;
  elements.addressHint.textContent = direct
    ? "Local-only unless you provide an HTTPS reverse proxy.  Direct clients and origins can see ordinary network metadata."
    : "Tor provides reachability without a router rule and keeps the home IP out of the Blossom address.";
}

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
    elements.restart.disabled = status.phase === "setup";
    elements.address.textContent = status.publicUrl || "Starting…";
    elements.blobs.textContent = String(status.storage?.blobs ?? 0);
    elements.used.textContent = formatBytes(status.storage?.bytes ?? 0);
    const free = Math.max(0, (status.storage?.quotaBytes ?? 0) - (status.storage?.bytes ?? 0));
    elements.free.textContent = formatBytes(free);
    const friends = status.settings.friendGrants?.length ?? 0;
    elements.writeStatus.textContent = status.settings.openShelter
      ? `${friends} friend grant${friends === 1 ? "" : "s"}; spare capacity is open to signed guest mirrors.`
      : status.settings.allowedPubkey || friends > 0
        ? `${friends} friend grant${friends === 1 ? "" : "s"}; unknown writers are denied.`
        : "The node is read-only until you add an owner, a friend grant or open shelter.";
    if (!settingsLoaded) {
      elements.pubkey.value = status.settings.allowedPubkey || "";
      elements.friendGrants.value = (status.settings.friendGrants || []).join("\n");
      elements.openShelter.checked = Boolean(status.settings.openShelter);
      elements.quota.value = String(status.settings.quotaGib);
      elements.autostart.checked = status.settings.startAtLogin;
      elements.transport.value = status.settings.transport;
      elements.directPort.value = String(status.settings.directPort);
      elements.directPublicUrl.value = status.settings.directPublicUrl || "";
      updateTransportFields();
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
        friendGrants: elements.friendGrants.value
          .split(/\r?\n/)
          .map((grant) => grant.trim())
          .filter(Boolean),
        openShelter: elements.openShelter.checked,
        quotaGib: Number(elements.quota.value),
        startAtLogin: elements.autostart.checked,
        transport: elements.transport.value,
        directPort: Number(elements.directPort.value),
        directPublicUrl: elements.directPublicUrl.value.trim() || null,
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

elements.transport.addEventListener("change", updateTransportFields);

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

// Wildbloom Drop settings (section 9.5). Changes apply immediately and are not
// part of "Save and restart". All state lives in Rust; this is a view over it.
(() => {
  const Drop = window.WildbloomDrop;
  const $ = (id) => document.getElementById(id);
  const ui = {
    nodeUrl: $("drop-node-url"), nodeStatus: $("drop-node-status"), nodeChange: $("drop-node-change"),
    npub: $("drop-device-npub"), approval: $("drop-approval-text"), copy: $("drop-device-copy"), copyStatus: $("drop-device-status"), renew: $("drop-renew"),
    folder: $("drop-folder"), folderHint: $("drop-folder-hint"), folderShow: $("drop-folder-show"),
    recovery: $("drop-recovery-text"), recoveryButton: $("drop-recovery"), error: $("drop-settings-error"),
  };
  let snapshot = null;
  let copyTimer = null;

  function showError(text) {
    ui.error.textContent = text || "";
    ui.error.hidden = !text;
  }

  function render() {
    const online = snapshot?.online;
    const approval = snapshot?.approval || { state: "none" };
    const configured = Boolean(online?.configured);
    ui.nodeUrl.textContent = configured ? online.url : "";
    ui.nodeUrl.hidden = !configured;
    const unreachable = configured && (online.reachable === false || (online.failedChecks || 0) > 0);
    ui.nodeStatus.textContent = !snapshot ? "Not available yet."
      : !configured ? "Not set up"
      : unreachable ? "Can't reach it right now"
      : `Connected · ${Drop.formatBytes(online.usedBytes)} of ${Drop.formatBytes(online.limitBytes)} used`;
    ui.nodeStatus.classList.toggle("warn", unreachable);
    ui.nodeChange.textContent = configured ? "Change…" : "Add online node…";
    ui.nodeChange.disabled = !snapshot;

    ui.npub.textContent = approval.deviceNpub ? Drop.shortNpub(approval.deviceNpub) : "";
    ui.copy.hidden = !approval.deviceNpub;
    const soon = approval.state === "active" && approval.until && approval.until - Date.now() / 1000 < 30 * 86400;
    ui.approval.textContent = approval.state === "active" ? `Approved by ${Drop.shortNpub(approval.byNpub)} until ${Drop.fullDate(approval.until)}`
      : approval.state === "expired" ? `Approval ended on ${Drop.fullDate(approval.until)}`
      : configured ? "Not approved yet" : "Add your online node first.";
    ui.approval.classList.toggle("warn", approval.state === "expired" || Boolean(soon));
    ui.renew.disabled = !snapshot || !configured;
    ui.renew.classList.toggle("emphasis", approval.state === "expired" || Boolean(soon));

    const folder = snapshot?.watchFolder || {};
    ui.folder.checked = Boolean(folder.enabled);
    ui.folder.disabled = !snapshot;
    const folderPath = folder.path || "~/Wildbloom";
    const trash = Drop.platform.os === "windows" ? "Recycle Bin" : "Trash";
    ui.folderHint.textContent = folder.enabled
      ? `${folderPath}. Deleting a file here removes it on all your computers. Their copies go to the ${trash}.`
      : `${folderPath}.`;
    ui.folderShow.disabled = !folder.enabled;

    const recovery = snapshot?.recovery || {};
    ui.recovery.textContent = recovery.savedAt ? `Saved ${Drop.fullDate(recovery.savedAt)}` : "Not saved yet";
    ui.recoveryButton.disabled = !snapshot;
  }

  async function refreshDrop() {
    try {
      snapshot = await Drop.call("drop_status");
    } catch {
      snapshot = null;
    }
    render();
  }

  async function runFlow(options, opener) {
    const finished = await Drop.openFlowSheet({ ...options, refresh: async () => { await refreshDrop(); return snapshot; } }, opener);
    await refreshDrop();
    return finished;
  }

  // Changing node ends every live share first (its shared copy is deleted on
  // the old node), so say so before the owner continues.
  function sharingWarning(status) {
    const shared = (status?.files || []).filter((row) => row.state === "shared").length;
    if (shared === 0) return [];
    const host = Drop.hostOf(status.online.url);
    return [shared === 1
      ? `You're sharing 1 file. Its shared copy on ${host} is deleted now, so its link stops working.`
      : `You're sharing ${shared} files. Their shared copies on ${host} are deleted now, so their links stop working.`];
  }

  ui.nodeChange.addEventListener("click", async (event) => {
    const opener = event.currentTarget;
    if (snapshot?.online?.configured) {
      const yes = await Drop.confirmDialog({
        title: "Use a different online node?",
        paragraphs: [
          `Your files will be copied to the new node. Copies on ${Drop.hostOf(snapshot.online.url)} aren't deleted.`,
          ...sharingWarning(snapshot),
        ],
        confirmLabel: "Continue", destructive: false, opener,
      });
      if (!yes) return;
    }
    runFlow({ sequence: ["node", "approve"], browserApproval: Boolean(snapshot?.browserApproval), label: "Online node" }, opener);
  });
  ui.renew.addEventListener("click", (event) => {
    runFlow({ sequence: ["approve"], renew: true, browserApproval: Boolean(snapshot?.browserApproval), label: "Renew approval" }, event.currentTarget);
  });
  ui.recoveryButton.addEventListener("click", async () => {
    // The recovery key is shown only in the Drop window.
    showError("");
    try {
      await Drop.call("open_drop_flow", { flow: "recovery" });
    } catch (error) {
      showError(error.message || "Couldn't open Wildbloom Drop.");
    }
  });
  ui.copy.addEventListener("click", async () => {
    const npub = snapshot?.approval?.deviceNpub;
    if (!npub) return;
    ui.copyStatus.textContent = (await Drop.writeClipboard(npub)) ? "Copied." : "Couldn't copy.";
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => { ui.copyStatus.textContent = ""; }, 2000);
  });
  ui.folder.addEventListener("change", async () => {
    showError("");
    try {
      if (ui.folder.checked && !(await Drop.confirmFolderOn(ui.folder))) {
        ui.folder.checked = false;
        return;
      }
      await Drop.call("set_watch_folder", { enabled: ui.folder.checked });
    } catch (error) {
      showError(error.message || "Couldn't change the Wildbloom folder.");
    }
    await refreshDrop();
  });
  ui.folderShow.addEventListener("click", async () => {
    try {
      await Drop.call("open_watch_folder");
    } catch (error) {
      showError(error.message || "Couldn't open the Wildbloom folder.");
    }
  });

  Drop.listen("drop://status", (payload) => {
    if (!payload) return;
    snapshot = { ...(snapshot || {}), ...payload };
    render();
  });
  render();
  refreshDrop();
})();

refresh();
setInterval(refresh, 2000);
