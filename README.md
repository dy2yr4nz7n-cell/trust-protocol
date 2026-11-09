# TRUST Protocol: lauffähiger Prüf-Workspace

## Start

```sh
npm ci
npm run build
npm run setup
npm start
```

Öffne http://localhost:3000. Node.js ab 20.19 wird benötigt.
`PORT` wird automatisch übernommen; der Server bindet standardmäßig an `0.0.0.0`.
Für die geschützten Bereiche nach `npm run setup` ausdrücklich http://127.0.0.1:3000 verwenden.
Das Setup erzeugt lokal `.env` und ein einstündiges Token in `access-token.txt`. Diese Dateien niemals veröffentlichen.
Das Token in „Medienprüfung & Verlauf“ eingeben; Datei auswählen, Einwilligung setzen und prüfen.
Bei Ablauf mit `npm run setup` ein neues Token für dieselbe lokale Identität erzeugen. Vorhandene Secrets werden nicht überschrieben.

## Enthaltene Werkzeuge

- `/`: echte lokale SHA-256-Berechnung, Referenzvergleich und JSON-Export. Keine Dateiübertragung, keine Speicherung.
- `/protocol/`: ursprüngliche TRUST-Engine mit Record-Ableitung, Policies und Demo-Nachweisen.
- `/simulator/`: hochgeladene Architektur-Demo, ausdrücklich als Simulation markiert. Keine echte KI-Erkennung oder Hardware-Attestierung.
- `/verifier/`: vorhandener geschützter C2PA-Client. Nur mit konfigurierter API nutzbar.
- `/inspection/`: Medienprüfung aus dem zusätzlichen v12-Upload mit Dateityperkennung, EXIF, 25-MiB-Limit, echter C2PA-Auswertung, SQLite-Prüfverlauf und JSON-Export. Token und Einwilligung erforderlich.
- `/health`: öffentlicher Healthcheck, ohne Geheimnisse.
- `uploads/original/`: alle vier Original-Uploads unverändert; nicht öffentlich ausgeliefert.
- `uploads/inspection-original/`: zweiter Upload-Satz unverändert, als Referenz. Nicht ausführen: die lauffähige Integration liegt unter `apps/verifier/inspection.js`.
- `packages/local-integrity/`: eigenständig startbare, localhost-beschränkte Minimalversion und validierendes Verschlüsselungsmodul aus `trust-protocol-clean.zip`. Deren Gesprächs-/Referenzexporte werden nicht in das öffentliche Repository übernommen.

## Railway

Repository mit Branch `main` verbinden, Root Directory `/` verwenden und deployen.
Das Root-Dockerfile baut das Projekt; `railway.json` konfiguriert `/health`.
Unter Networking eine Domain erzeugen. Keine Secrets für lokale Hash-Prüfung, Protokoll und Simulator erforderlich.
Für geschützte Medienprüfung und Verlauf in Railway `JWT_SECRET` mit mindestens 32 zufälligen Bytes und `PUBLIC_ORIGIN=https://DEINE-DOMAIN` setzen.
Für dauerhaften Verlauf ein Railway-Volume unter `/app/data` einhängen und `DATA_DIR=/app/data` setzen.
Ohne Volume kann der Verlauf bei Redeployment verloren gehen. Kein externer Datenbankdienst ist erforderlich.
Ein persönliches API-Token über Railway CLI/Shell mit `npm run token -- DEINE_USER_ID` erzeugen; niemals das Secret ins Frontend schreiben.
Die SQLite-Reports sind pro Token-Identität getrennt. Originalmedien werden nicht gespeichert.

```sh
docker build -t trust-protocol .
docker run --rm -p 3000:3000 trust-protocol
```

Mit geschützter API und dauerhaftem Volume:

```sh
# .env vorher lokal mit npm run setup erzeugen
docker run --rm --env-file .env -p 3000:3000 -v trust-data:/app/data trust-protocol
```

## Minimalversion aus der Clean-ZIP

```sh
npm run test:local
npm run start:local
```

Diese Alternative bindet ausschließlich an `127.0.0.1`, nutzt Port 3000 und darf nicht parallel zur Hauptanwendung auf demselben Port laufen.
Sie bietet Streaming-Hashing, Referenzvergleich, kurzlebige Ergebnisse und deren Löschung, jedoch bewusst keine C2PA-Prüfung.
Das Verschlüsselungsmodul unter `packages/local-integrity/lib/encrypt.js` ist eine separat getestete Bibliothek und nicht automatisch mit SQLite verbunden.
Es verschlüsselt ausgewählte Record-Felder; unverschlüsselte Metadaten bleiben veränderbar. Kein Herkunftsbeweis und kein standardisiertes JWE.

## Optionale echte C2PA-Prüfung

Das Root-Dockerfile enthält die offizielle Linux-amd64-Version von `c2patool` exakt in Version `0.28.6`, mit fest gepinntem SHA-256 des Archivs.
Das Image unterstützt Linux amd64. Auf ARM kann mit `docker build --platform linux/amd64` gebaut werden; lokal muss die CLI ansonsten separat installiert und erreichbar sein.
Ohne CLI bleibt die Oberfläche lauffähig und meldet keine erfundenen Prüfergebnisse.
Zusätzlich `JWT_SECRET` (mindestens 32 zufällige Bytes) und `PUBLIC_ORIGIN` (exakte HTTPS-Origin ohne abschließenden Slash) setzen; lokal übernimmt `npm run setup` die Startkonfiguration.
Optional `C2PA_TRUST_ANCHORS` mit einem PEM-Vertrauensanker konfigurieren.
Ohne konfigurierte Vertrauensanker wird ein gültiger Aussteller nicht als vertrauenswürdig bestätigt.
Ein persönliches, kurzlebiges Token erzeugt `npm run token --workspace apps/verifier -- USER_ID` mit derselben Server-Umgebung.
Kein JWT-Secret im Browser eingeben. Tokens sind keine vollständige Benutzerverwaltung.

Die C2PA-API verarbeitet JPEG, PNG und WebP bis 8 MiB temporär. Upload erst nach Einwilligung.
Keine allgemeine KI-Erkennung und keine Live-Widerrufsprüfung. Nur der zusätzliche Medienprüfbereich speichert Reports dauerhaft in SQLite; die einfache C2PA-Prüfung bleibt temporär.

## Tests

```sh
npm test
npm run test:all
npm run test:verifier
npm run build
npm run test:runtime
```

`npm test` führt sämtliche Protokoll-Suites einschließlich X.509, C2PA und Policies aus.
`npm run test:ci` ergänzt Verifier-, lokale Integritäts-, Build- und Laufzeitprüfungen.
Der Abgleich des X.509-Reparatur-Snapshots ist unter [X.509-Konsolidierung](docs/X509-CONSOLIDATION.md) dokumentiert.

## Ursprüngliches Produktkonzept

[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://app.codspeed.io/dy2yr4nz7n-cell/trust-protocol?utm_source=badge)

## 1. Produktvision

TRUST:// ist ein offener Standard für nachweisbare Herkunft im Netz. Das Produkt zielt darauf ab, digitale Inhalte nicht nur als Dateien, sondern als überprüfbare Herkunftseinheiten zu behandeln: Woher kommen sie, wer hat sie signiert, welche Metadaten wurden behauptet, und wurden sie seitdem verändert?

Die Kernidee ist einfach und zugleich bahnbrechend:
- Herkunft und Integrität werden getrennt von Behauptungen über Erzeugung betrachtet.
- Ein System entscheidet nicht über „Glauben
