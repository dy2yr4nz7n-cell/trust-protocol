# Zusammengeführtes TRUST-Projekt

## Verwendete Eingaben

- GitHub-Repository `dy2yr4nz7n-cell/trust-protocol`: Protokoll-Engine, Policies, Verifier und bestehende Tests.
- Railway-ZIP und beide identischen Demo-HTMLs: als Original erhalten und als ausdrücklich gekennzeichnete Simulation integriert.
- Zusätzlicher v12-Dateisatz: Medienprüfung, EXIF, SQLite-Verlauf und JSON-Berichte übernommen. Der ungeschützte Originalserver wird nicht gestartet.
- Clean-ZIP: localhost-beschränkte Minimalanwendung sowie Verschlüsselungsbibliothek unter `packages/local-integrity/`. Gesprächs-/Referenzexporte sind bewusst nicht Teil des öffentlichen Repositories oder der ausgelieferten Website.

## Sicherheits- und Integrationsentscheidungen

- Ein Hauptserver, ein Root-Dockerfile, ein Root-Lockfile. Kein CommonJS/ESM-Konflikt.
- Tokenprüfung vor Upload und vor Zugriff auf Audit-Berichte. Audit-Zeilen sind pro Token-Identität getrennt.
- SQL-Abfragen sind parametrisiert. Neue Tabelle `inspection_audits`; keine bestehenden Tabellen werden gelöscht oder verändert.
- Originalmedien werden temporär verarbeitet und nicht in SQLite gespeichert. Dateiname, Hash, ausgewählte EXIF-Felder und Prüfbericht werden nur nach Einwilligung gespeichert.
- Die v12-Suche nach Wörtern wie „valid“ im gesamten C2PA-JSON wurde nicht übernommen. Stattdessen werden die vorhandenen strukturierten C2PA-Prüfergebnisse ausgewertet.
- Fehlende Vertrauensanker führen nicht zu „vertrauenswürdig“. Eine gültige, selbst signierte Testdatei liefert `VALID_UNTRUSTED`.
- Keine KI-Erkennung. Simulationen, lokale Hashes und kryptografische Herkunftsnachweise bleiben getrennt.
- Lokale Setup-Secrets und Zugriffstokens sind Git- und Docker-ignoriert. Öffentlich ausgeliefert wird ausschließlich `dist/public`.
- SQLite ist nicht automatisch verschlüsselt oder manipulationssicher. Das separat übernommene Verschlüsselungsmodul ist keine Verschlüsselung der Audit-Datenbank.
- Railway benötigt für dauerhaften Verlauf ein Volume. Ohne Volume wird keine dauerhafte Speicherung über Redeployments zugesichert.

## Verifikation

`npm ci` und `npm run test:ci` wurden mit Node 20.20 erfolgreich ausgeführt. Der Gesamtlauf enthält:

- Konformität, Ableitung, Signaturen und Fingerprints der ursprünglichen Engine.
- X.509-Parser, C2PA-Transport und zusätzliche Policy-/C2PA-Tests.
- 21 Verifier-Tests.
- 39 importierte Tests der Clean-ZIP, einschließlich Verschlüsselungsmodul.
- HTTP-Start, Healthcheck, private Dateipfade, fehlende Konfiguration und Tokenprüfung.
- SQLite-Speicherung, Wiederladen nach Serverneustart, Export, fehlende Einwilligung, falscher Dateityp und Trennung zweier Token-Identitäten.
- Mit offizieller CLI `c2patool 0.28.6`: unsigned PNG → `absent`, neu signiertes JPEG ohne vertrauenswürdigen Aussteller → `valid_untrusted`.

Zusätzlich wurde der Browser bei Desktopbreite und 375 Pixeln geprüft: lokaler Hash, Referenzvergleich, ungültige Referenz, JSON-Export, Reset, Simulationsszenarien, Protokoll-Presets, Upload/Einwilligung, echte C2PA-Ausgabe, EXIF aus einer selbst erzeugten Testdatei, Verlauf öffnen, Methodik-Tab, Export und Abmelden.

`npm audit --omit=dev` meldete beim Abschluss keine bekannten Abhängigkeitsprobleme. Das ist kein vollständiges Sicherheitsgutachten.

Der Workflow `.github/workflows/workspace.yml` prüft zusätzlich den Docker-Build, die ausgelieferte Oberfläche und die enthaltene C2PA-CLI.
