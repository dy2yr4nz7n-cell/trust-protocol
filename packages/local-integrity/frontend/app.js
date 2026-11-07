'use strict';
const $ = id => document.getElementById(id);
let current = null, controller = null, busy = false;
const labels = { NOT_PROVIDED: 'Kein Referenzwert angegeben', MATCH: 'Referenz-Hash stimmt überein', MISMATCH: 'Referenz-Hash stimmt NICHT überein' };

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'X-Trust-Protocol': '1', ...options.headers } });
  if (response.status === 204) return null;
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function resetResult() {
  current = null;
  $('result-title').textContent = 'Noch kein Ergebnis';
  $('result-desc').textContent = 'Keine aktuelle Prüfung ausgeführt. Herkunft und Echtheit sind nicht bewertet.';
  $('hash').textContent = '—'; $('comparison').textContent = 'Nicht ausgeführt';
  $('json-output').textContent = 'Noch keine Live-Analyse ausgeführt.';
  $('download').disabled = true; $('delete').disabled = true;
}
function setBusy(value) {
  busy = value;
  for (const id of ['run', 'file', 'expected']) $(id).disabled = value;
  $('cancel').hidden = !value;
  $('download').disabled = value || !current;
  $('delete').disabled = value || !current;
}
function showResult(data) {
  current = data;
  const comparison = data.integrity.comparison;
  $('result-title').textContent = comparison === 'MATCH' ? 'Dateiintegrität: Referenz stimmt überein' : comparison === 'MISMATCH' ? 'Dateiintegrität: Abweichung erkannt' : 'Fingerabdruck berechnet · nicht verifiziert';
  $('result-desc').textContent = comparison === 'MISMATCH' ? 'Die Dateibytes passen nicht zum angegebenen Referenzwert. Das ist kein automatischer Beweis für eine Fälschung.' : 'Der Befund betrifft Dateibytes, nicht Herkunft, Signaturen oder den Wahrheitsgehalt.';
  $('hash').textContent = data.integrity.sha256;
  $('comparison').textContent = labels[comparison];
  $('json-output').textContent = JSON.stringify(data, null, 2);
  $('download').disabled = false; $('delete').disabled = false;
}
async function deletePrevious() {
  if (!current) return;
  try { await api(`/v1/jobs/${current.job_id}`, { method: 'DELETE' }); }
  catch (error) { if (!error.message.includes('abgelaufen')) throw error; }
  resetResult();
}

$('file').addEventListener('change', () => {
  const file = $('file').files[0];
  $('file-info').textContent = file ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB` : 'Noch keine Datei ausgewählt.';
  if (current) $('progress').textContent = 'Dateiauswahl geändert. Der bisherige Befund gehört weiterhin zur vorherigen Datei, siehe JSON.';
});
$('analyze-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  const file = $('file').files[0];
  const expected = $('expected').value.trim().toLowerCase();
  if (!file || !file.size) { $('progress').textContent = 'Bitte eine nicht leere Datei auswählen.'; return; }
  if (file.size > 15 * 1024 * 1024) { $('progress').textContent = 'Maximal 15 MiB pro Datei.'; return; }
  if (expected && !/^[a-f0-9]{64}$/.test(expected)) { $('progress').textContent = 'Referenz-Hash benötigt 64 Hex-Zeichen.'; return; }
  controller = new AbortController(); setBusy(true);
  const timeout = setTimeout(() => controller?.abort(), 45000);
  let jobId = null;
  try {
    await deletePrevious();
    $('progress').textContent = 'Datei wird lokal übertragen und gehasht …';
    const query = new URLSearchParams({ filename: file.name.slice(0, 180), expected_sha256: expected });
    const job = await api(`/v1/analyze?${query}`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file, signal: controller.signal });
    jobId = job.job_id;
    const result = await api(job.status_url, { signal: controller.signal });
    showResult(result);
    $('progress').textContent = `Abgeschlossen · ${result.size_bytes} Bytes · ${result.processing_time_ms} ms Hash-Lesezeit. Keine Herkunftsprüfung.`;
  } catch (error) {
    if (jobId && !current) api(`/v1/jobs/${jobId}`, { method: 'DELETE' }).catch(() => {});
    $('progress').textContent = error.name === 'AbortError' ? 'Abgebrochen oder Zeitlimit erreicht. Kein aktuelles Ergebnis.' : `Fehler: ${error.message}`;
  } finally { clearTimeout(timeout); controller = null; setBusy(false); }
});
$('cancel').addEventListener('click', () => controller?.abort());
$('delete').addEventListener('click', async () => {
  if (busy) return;
  setBusy(true);
  try { await deletePrevious(); $('progress').textContent = 'Ergebnis aus Arbeitsspeicher und Ansicht gelöscht. Bereits exportierte Dateien bleiben bei dir.'; }
  catch (error) { $('progress').textContent = `Löschen fehlgeschlagen: ${error.message}`; }
  finally { setBusy(false); }
});
$('download').addEventListener('click', () => {
  if (!current) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(current, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = `trust-result-${current.job_id}.json`;
  document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
for (const mode of ['live', 'demo']) $('tab-' + mode).addEventListener('click', () => {
  for (const name of ['live', 'demo']) {
    $(name).hidden = name !== mode;
    $('tab-' + name).classList.toggle('selected', name === mode);
    $('tab-' + name).setAttribute('aria-pressed', String(name === mode));
  }
});
$('run-demo').addEventListener('click', async () => {
  $('run-demo').disabled = true;
  try {
    const result = await api('/v1/demo/' + $('scenario').value);
    $('demo-status').textContent = 'SIMULATION · ' + result.title;
    $('demo-json').textContent = JSON.stringify(result, null, 2);
  } catch (error) { $('demo-status').textContent = 'Fehler: ' + error.message; }
  finally { $('run-demo').disabled = false; }
});
api('/v1/health').then(() => { $('health').textContent = 'Lokal verbunden · nur Integrität'; }).catch(() => { $('health').textContent = 'Backend nicht erreichbar · npm start ausführen'; });
