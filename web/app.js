const $ = id => document.getElementById(id);
let report = null, sequence = 0;
function compare() {
  const expected = $('expected').value.trim().toLowerCase();
  $('comparison').textContent = !expected ? 'Kein Referenzwert angegeben' : !/^[a-f0-9]{64}$/.test(expected) ? 'Referenz ungültig: genau 64 Hex-Zeichen erforderlich' : !report ? 'Zuerst eine Datei auswählen' : expected === report.sha256 ? 'Übereinstimmung: identische Bytes zur Referenz' : 'Keine Übereinstimmung: andere Bytes als die Referenz';
  if (report) { report.expectedSha256 = expected || null; report.matches = /^[a-f0-9]{64}$/.test(expected) ? expected === report.sha256 : null; }
}
function clear() {
  sequence++; report = null;
  $('export').disabled = true;
  $('filename').textContent = 'Nicht ausgewählt'; $('size').textContent = 'Nicht berechnet'; $('hash').textContent = 'Noch kein Fingerabdruck';
  $('badge').textContent = 'BEREIT'; $('result-title').textContent = 'Noch keine Datei ausgewählt';
  $('status').textContent = 'Wähle eine Datei, um ihren eindeutigen Fingerabdruck zu berechnen.';
  compare();
}
$('file').addEventListener('change', async () => {
  clear(); const current = sequence, file = $('file').files[0]; if (!file) return;
  $('filename').textContent = file.name; $('size').textContent = `${file.size.toLocaleString('de-DE')} Bytes`;
  if (file.size > 64 * 1024 * 1024) { $('badge').textContent = 'LIMIT'; $('status').textContent = 'Maximal 64 MiB erlaubt. Bitte kleinere Datei wählen.'; return; }
  $('badge').textContent = 'LÄUFT'; $('result-title').textContent = 'Fingerabdruck wird berechnet';
  try {
    const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
    if (current !== sequence) return;
    const sha256 = Array.from(new Uint8Array(digest), n => n.toString(16).padStart(2, '0')).join('');
    report = { schemaVersion: 'trust-local-hash/1', filename: file.name, bytes: file.size, sha256, checkedAt: new Date().toISOString(), uploaded: false, provenance: 'not_checked', aiDetection: 'not_performed' };
    $('hash').textContent = sha256; $('badge').textContent = 'BERECHNET'; $('result-title').textContent = 'Fingerabdruck berechnet';
    $('status').textContent = 'Lokal abgeschlossen. Herkunft und KI-Erstellung wurden nicht geprüft.'; $('export').disabled = false; compare();
  } catch { if (current === sequence) { $('badge').textContent = 'FEHLER'; $('result-title').textContent = 'Berechnung fehlgeschlagen'; $('status').textContent = 'Datei nicht lesbar oder Web Crypto nicht verfügbar. Bitte über HTTPS oder localhost öffnen.'; } }
});
$('expected').addEventListener('input', compare);
$('reset').addEventListener('click', () => { $('file').value = ''; $('expected').value = ''; clear(); });
$('export').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = 'trust-integrity-report.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
