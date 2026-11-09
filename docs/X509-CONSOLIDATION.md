# X.509-Konsolidierung

Am 9. November 2026 wurde der separate X.509-Reparatur-Snapshot mit dem
aktuellen Hauptprojekt abgeglichen. Die Zusammenführung erfolgt selektiv:
Der Snapshot besitzt eine eigenständige Git-Historie und enthält einen älteren
Anwendungsstand. Ein vollständiges Überschreiben wäre ein Rückschritt.

## Verglichene Stände

| Stand | Commit |
|---|---|
| Hauptprojekt vor der Konsolidierung | `b413a9276a589116898a3516689334edf5afe82b` |
| Ursprüngliche Basis des Reparatur-Snapshots | `4b80995b626d956955ddc67d08107a32d6609a3a` |
| Reparatur-Snapshot, Standardbranch | `991bd5395060cf05e228054b6449ed0a0a0583d4` |
| Zusätzlicher Reparaturbranch | `0fd1af69e336cb62f504afd1bd402cc7425db93f` |

Vollständige Git-Bundles beider Repositories wurden vor Änderungen erstellt und
mit `git bundle verify` geprüft. Diese Sicherungen gehören nicht in das öffentliche
Repository; insbesondere wird die private Snapshot-Historie nicht veröffentlicht.

## Übernommene und bereits vorhandene Korrekturen

| Änderung des Snapshots | Ergebnis im Hauptprojekt |
|---|---|
| RDNs als DER-SET lesen | Bereits korrekt vorhanden; auf den wiederverwendbaren `readSet()`-Helper umgestellt und Ablehnung eines SEQUENCE-RDN zusätzlich getestet |
| P-256-OID `1.2.840.10045.3.1.7` | Parser bereits korrekt; verbliebene falsche OID im Transport-Testhelper korrigiert und mit dem tatsächlich erzeugten SPKI verglichen |
| Navigation vom Subject zum SubjectPublicKeyInfo | Bereits im produktiven Transport vorhanden und durch Kettenprüfungen abgedeckt |
| Unverändertes WebCrypto-SPKI in Testzertifikaten | Bereits vorhanden; nicht mehr benötigte lokale Algorithmusvariablen entfernt |
| Digest-Testhelper an den produktiven Verifier angleichen | Statt einer weiteren Kopie wird `findDigest` direkt aus dem produktiven Modul importiert; bestehendes Produktverhalten bleibt unverändert |
| Ungültige Top-Level-Returns aus Tests entfernen | Bereits erledigt; vorhandene Fehler-Exitcodes bleiben erhalten |
| Alle Protokoll-Suites über `npm test` ausführen | Übernommen; `test:ci` ergänzt weiterhin Verifier-, lokale Integritäts-, Build- und Laufzeitprüfungen, ohne Protokoll-Suites doppelt auszuführen |
| Diagnose für nicht selbstsigniertes Kettenende | Übernommen; zusätzliche Tests mit und ohne Vertrauensliste sichern die Ablehnung einer fehlenden Root-Signatur ab |

## Bewusst nicht übernommen

- **Anwendung und Laufzeit:** Workspace, Authentifizierung, Docker-Konfiguration,
  Deployment-Dateien und lokale Integritätswerkzeuge bleiben erhalten.
- **Neuere Schutzmaßnahmen:** Ableitungs-Zyklusbegrenzung, begrenzte öffentliche
  Build-Assets, geschützte Dateierstellung und Fehler-Exitcodes bleiben erhalten.
- **Ältere Testfixtures:** Ungültige Datumswerte und der ältere Trust-List-Test
  ersetzen nicht die korrigierten Hauptprojekt-Fixtures.
- **Veröffentlichungs-Workflows:** npm-Publishing-Workflows werden nicht in die
  als `private` markierte Anwendung kopiert.
- **Zusätzlicher Branch:** Dessen einzige Änderung gegenüber dem gemeinsamen
  Snapshot ist eine generische Webpack-CI. Das Projekt baut über
  `scripts/build.mjs`; ein zusätzlicher `npx webpack`-Ablauf wird nicht eingeführt.
- **Snapshot-Metadaten:** Private Historie, `.write-probe` und die Snapshot-README
  ersetzen weder Dokumentation noch Dateien des Hauptprojekts.

## Verifikation

```sh
npm ci
npm test
npm run test:ci
```

Gezielt lassen sich die betroffenen Bereiche zusätzlich prüfen:

```sh
node x509-parser.test.mjs
node c2pa-transport.test.mjs
node c2pa-verifier.test.mjs
```

Die Laufzeitprüfung mit echter C2PA-CLI kann ohne installierte CLI übersprungen
werden. Ein grüner lokaler Testlauf allein belegt deshalb keinen erfolgreichen
Container-Build und kein erfolgreiches Produktionsdeployment.
