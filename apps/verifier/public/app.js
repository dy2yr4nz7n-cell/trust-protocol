const $ = id => document.getElementById(id);
const titles = { verified_offline: 'Herkunftsnachweis offline gegen konfigurierte Vertrauensanker geprüft', valid_untrusted: 'Signatur und Dateibindung gültig; Aussteller nicht bestätigt', invalid: 'Prüfprobleme im Herkunftsnachweis; kein automatischer Fake-Beweis', absent: 'Kein eingebetteter Herkunftsnachweis gefunden', unknown: 'Nicht eindeutig prüfbar' };
$('form').addEventListener('submit', async event => {
  event.preventDefault(); $('result').hidden = true;
  const file = $('file').files[0];
  if (!file || !$('consent').checked) return;
  if (!file.size || file.size > 8 * 1024 * 1024) { $('status').textContent = 'Dateigröße ungültig (maximal 8 MiB).'; return; }
  $('submit').disabled = true; $('clear').disabled = true; $('status').textContent = 'Datei wird übertragen und geprüft …';
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
  try {
    const body = new FormData(); body.append('file', file);
    const response = await fetch('/api/verify', { method: 'POST', headers: { Authorization: `Bearer ${$('token').value.trim()}` }, body, signal: controller.signal });
    const report = await response.json();
    if (!response.ok) throw new Error(report.error || `HTTP ${response.status}`);
    $('heading').textContent = titles[report.provenance] || titles.unknown;
    $('ai').textContent = report.generation.aiDeclared ? (report.generation.status === 'ai_declared_trusted' ? 'Der geprüfte Herkunftsnachweis deklariert KI-Erstellung oder KI-Anteile.' : 'Das Manifest enthält eine KI-Angabe, deren Vertrauenswürdigkeit nicht bestätigt ist.') : 'Keine eindeutige KI-Angabe. Das beweist keine menschliche Erstellung.';
    $('limits').replaceChildren(...report.limits.map(text => { const li = document.createElement('li'); li.textContent = text; return li; }));
    $('json').textContent = JSON.stringify(report, null, 2); $('result').hidden = false; $('status').textContent = 'Prüfung abgeschlossen.';
  } catch (error) { $('status').textContent = error.name === 'AbortError' ? 'Zeitlimit erreicht. Keine Einordnung möglich.' : `Keine Einordnung: ${error.message}`; }
  finally { clearTimeout(timer); $('submit').disabled = false; $('clear').disabled = false; }
});
$('clear').addEventListener('click', () => { $('form').reset(); $('result').hidden = true; $('json').textContent = ''; $('status').textContent = ''; });
$('file').addEventListener('change', () => { $('result').hidden = true; $('json').textContent = ''; });
