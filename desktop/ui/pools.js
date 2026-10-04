// Local UI only. Remote storage/signing is owned by the bounded native command.
(() => {
  const invoke = window.__TAURI__.core.invoke;
  const el = (id) => document.getElementById(`pool-${id}`);
  let pools = [];
  let busy = false;
  let refreshing = false;
  let revision = 0;
  const selected = () => pools.find((p) => p.inspection.receipt_id === el('select').value);
  const running = (pool) => ['checking', 'repairing'].includes(pool?.phase);
  const active = () => pools.some(running);
  const message = (text) => { el('action-status').textContent = text; };
  const date = new Date(Date.now() + 24 * 60 * 60 * 1000);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  el('expiry').value = date.toISOString().slice(0, 16);

  function revoke() { revision++; el('consent').checked = false; el('remove-consent').checked = false; controls(); }
  function controls() {
    el('import').disabled = busy;
    el('check').disabled = busy || active() || !selected();
    el('start').disabled = busy || active() || !selected() || !el('consent').checked;
    el('stop').disabled = busy || !active();
    el('remove').disabled = busy || running(selected()) || !el('remove-consent').checked;
    el('select').disabled = busy;
  }
  function fact(label, value) {
    const term = document.createElement('dt'); term.textContent = label;
    const definition = document.createElement('dd'); definition.textContent = value;
    el('facts').append(term, definition);
  }
  function render() {
    const pool = selected(); el('details').hidden = !pool;
    if (!pool) { controls(); return; }
    const { inspection, report } = pool;
    const manifest = inspection.manifest;
    el('facts').replaceChildren();
    fact('Receipt', inspection.receipt_id);
    fact('Owner', inspection.owner);
    fact('Layout', manifest.mode === 'erasure' ? `${manifest.required} of ${manifest.total} parts` : `${manifest.copies} complete encrypted copies`);
    fact('Transport', manifest.profile === 'tor' ? 'Tor only' : 'Direct HTTPS');
    fact('Encrypted size', `${manifest.payload.size.toLocaleString()} bytes`);
    el('proxy-field').hidden = manifest.profile !== 'tor';
    el('work-dir').textContent = pool.work_dir;
    el('process').textContent = `${pool.detail}${pool.expires_at ? ` Authority ends ${new Date(pool.expires_at * 1000).toLocaleString()}.` : ''}`;
    el('health').textContent = !report ? 'Storage not yet verified in this session.' : report.protected ? 'Requested protection verified at the last check.' : report.recoverable ? 'Needs repair: the file was recoverable, but redundancy was below the requested level.' : 'Recovery threshold not met. Some parts may be offline; restore access or use an independent backup.';
    el('health').className = report && !report.protected ? 'pool-warning' : 'pool-health';
    el('observed').textContent = report ? `Last completed observation: ${new Date(report.observed_at * 1000).toLocaleString()}. ${report.uploads_attempted} upload attempt(s); ${report.reconstructed ? 'missing parts reconstructed' : 'no reconstruction'}.` : 'A signed receipt describes intended placement. It does not prove the nodes currently hold the parts.';
    el('parts').replaceChildren();
    for (const part of manifest.parts) {
      const row = document.createElement('li');
      const heading = document.createElement('strong');
      heading.textContent = `Part ${part.index + 1} · ${report ? `${report.verified_groups[part.index]} / ${manifest.copies} verified failure groups` : 'not checked'}`;
      row.append(heading);
      for (const target of part.targets) {
        const text = document.createElement('p');
        const observation = report?.nodes.find((node) => node.id === target.id && node.part_index === part.index);
        const state = { verified: 'verified', unavailable: 'unavailable or failed verification', not_checked: 'not checked (may be a spare)' }[observation?.state] ?? 'not checked';
        text.textContent = `${target.origin} · ${target.failure_group} · ${state}`;
        row.append(text);
      }
      el('parts').append(row);
    }
    controls();
  }
  async function refresh() {
    if (refreshing) return;
    refreshing = true;
    try {
      const result = await invoke('pool_status');
      const previous = el('select').value;
      pools = result.pools;
      el('load-error').hidden = !result.error;
      el('load-error').textContent = result.error || '';
      const ids = pools.map((p) => p.inspection.receipt_id);
      if ([...el('select').options].map((o) => o.value).join() !== ids.join()) {
        el('select').replaceChildren();
        for (const pool of pools) {
          const option = document.createElement('option');
          option.value = pool.inspection.receipt_id;
          option.textContent = `${pool.inspection.manifest.mode === 'erasure' ? 'Split' : 'Replicated'} · ${pool.inspection.receipt_id.slice(0, 16)}…`;
          el('select').append(option);
        }
        if (!pools.length) { const option = document.createElement('option'); option.value = ''; option.textContent = 'No receipts imported'; el('select').append(option); }
        if (ids.includes(previous)) el('select').value = previous;
        else revoke();
      }
      render();
    } catch { message('Could not read pool status. Check the desktop process before relying on an earlier observation.'); }
    finally { refreshing = false; }
  }
  async function action(fn) {
    if (busy) return;
    busy = true; controls();
    try { await fn(); }
    catch (error) { message(String(error)); }
    finally { busy = false; await refresh(); controls(); }
  }
  el('import-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const file = el('receipt').files[0];
    const owner = el('owner').value.trim();
    const current = revision;
    action(async () => {
      if (!file || file.size > 128 * 1024) throw new Error('Choose a signed receipt no larger than 128 KiB.');
      const receipt = await file.text();
      if (current !== revision) throw new Error('Receipt selection changed. Import again.');
      const result = await invoke('import_pool', { receipt, owner });
      message(`Verified and saved receipt ${result.receipt_id.slice(0, 16)}…. No nodes were contacted.`);
      revoke();
      await refresh(); el('select').value = result.receipt_id; render();
    });
  });
  function settings(checkOnly) {
    if (!el('run-form').reportValidity()) throw new Error('Complete the required settings.');
    const pool = selected(); if (!pool) throw new Error('Select a receipt.');
    return {
      receiptId: pool.inspection.receipt_id, checkOnly,
      allowReconstruction: !checkOnly && el('consent').checked,
      signer: checkOnly ? '' : el('signer').value.trim(),
      signerArguments: checkOnly ? [] : el('signer-arguments').value.split(/\r?\n/).filter((v) => v.length),
      proxy: pool.inspection.manifest.profile === 'tor' ? el('proxy').value.trim() || null : null,
      expiresAt: Math.floor(new Date(el('expiry').value).getTime() / 1000),
      interval: Number(el('interval').value),
      transferBudgetBytes: Number(el('transfer').value) * 1024 ** 3,
      maxWorkBytes: Number(el('disk').value) * 1024 ** 3,
    };
  }
  el('run-form').addEventListener('submit', (event) => {
    event.preventDefault();
    action(async () => {
      const config = settings(false);
      if (!config.allowReconstruction) throw new Error('Approve reconstruction and scoped signing first.');
      await invoke('start_pool', { settings: config });
      revoke(); message('Automatic repair started for the selected receipt.');
    });
  });
  el('check').addEventListener('click', () => action(async () => {
    await invoke('start_pool', { settings: settings(true) }); revoke(); message('Read-only check started. No signer or uploads will be used.');
  }));
  el('stop').addEventListener('click', () => action(async () => {
    await invoke('stop_pool'); revoke(); message('Pool process stopped.');
  }));
  el('remove').addEventListener('click', () => action(async () => {
    if (!el('remove-consent').checked || !selected()) throw new Error('Confirm your receipt backup first.');
    await invoke('remove_pool', { receiptId: selected().inspection.receipt_id }); revoke(); message('Local receipt removed. Remote parts and work folders were preserved.');
  }));
  el('browser').addEventListener('click', () => action(async () => { await invoke('open_pool_client'); }));
  el('select').addEventListener('change', () => { revoke(); render(); });
  for (const name of ['receipt','owner','proxy','interval','expiry','transfer','disk','signer','signer-arguments']) el(name).addEventListener('input', revoke);
  el('consent').addEventListener('change', controls);
  el('remove-consent').addEventListener('change', controls);
  refresh(); setInterval(refresh, 2000);
})();
