# Trust Protocol · lokale, konsolidierte Version

Hinweis zur Integration: Diese README beschreibt den eigenständigen lokalen Teil aus der hochgeladenen Clean-ZIP. Für das zusammengeführte Projekt, Railway, C2PA und den SQLite-Verlauf gilt die README im Repository-Hauptverzeichnis. Historische Testangaben unten sind nicht der aktuelle Integrationsnachweis.

Ein lokal startbarer Prototyp zur **echten SHA-256-Dateiprüfung**. Berechnet einen Dateifingerabdruck und vergleicht ihn auf Wunsch mit einer Referenz. Die ursprünglichen vier Präsentationsszenarien sind separat und ausdrücklich als Simulation vorhanden.

**Kein vollständiges Trust-/C2PA-/Forensikprodukt.** Keine echte Herkunfts-, Zertifikats-, Hardware- oder KI-Prüfung. Keine erfundenen Wahrscheinlichkeiten oder Trust-Scores. Ein passender Hash bedeutet nur, dass die Datei zum angegebenen Hash passt; der Hash muss aus einer unabhängig vertrauenswürdigen Quelle stammen.

## Sofort starten

Voraussetzung: Node.js ab Version 20. Für reguläre Nutzung eine aktuell unterstützte Node-LTS-Version wählen. Getestet wurde hier mit Node 20.20.1 auf Linux; Android/Termux wurde nicht direkt getestet.

1. ZIP entpacken.
2. Im Terminal in den entpackten Ordner `trust-protocol` wechseln, in dem `package.json` liegt.
3. `npm test` ausführen.
4. `npm start` ausführen.
5. Im Browser **http://127.0.0.1:3000** öffnen.
6. Mit `Strg+C` stoppen.

**Kein `npm install` erforderlich:** Das Projekt hat keine externen Laufzeit- oder Testabhängigkeiten. Die HTML-Datei nicht per Doppelklick öffnen: Der lokale Server muss laufen.

Wenn Port 3000 belegt ist: `PORT=3001 npm start`, anschließend http://127.0.0.1:3001 öffnen.

## Auf Android mit Termux

Node.js lässt sich laut Termux-Dokumentation mit `pkg install nodejs-lts` installieren; ZIP-Unterstützung mit `pkg install unzip`. Anleitung: https://wiki.termux.com/index.php?title=Node.js

```sh
pkg update
pkg install nodejs-lts unzip
termux-setup-storage
mkdir -p ~/projekte
unzip ~/storage/downloads/trust-protocol-clean.zip -d ~/projekte
cd ~/projekte/trust-protocol
npm test
npm start
```

Wenn der Browser den Download anders benennt, den tatsächlichen Dateinamen einsetzen. Nach `termux-setup-storage` den Android-Speicherzugriff erlauben. Entwickle unter `~/projekte` und nicht direkt im gemeinsam genutzten Android-Speicher. Ob `nodejs-lts` auf deinem konkreten Gerät verfügbar ist, hängt von der Termux-Installation ab; alternativ gibt es `pkg install nodejs`.

## Benutzung

- Unter **Echte Dateianalyse** eine Datei bis 15 MiB auswählen.
- Optional einen vertrauenswürdig erhaltenen SHA-256-Referenzwert mit 64 Hex-Zeichen eingeben.
- **Datei analysieren** starten. Ohne Referenz bleibt das Ergebnis `UNVERIFIED`.
- `INTEGRITY_MATCH` bedeutet Übereinstimmung mit der Referenz, nicht „authentisches Foto“.
- `INTEGRITY_MISMATCH` bedeutet Abweichung, nicht automatisch „Fälschung“.
- JSON exportieren oder das Ergebnis aus Server und Ansicht löschen.
- Unter **Simulation · fiktiv** die vier ursprünglichen Szenarien ansehen. Sie prüfen keine Datei.

## Projektstruktur

```text
server.js                 Lokaler HTTP-Server, Upload, begrenzter Ergebnisspeicher
engine.js                 SHA-256, Referenzvergleich, Dateityp-Hinweise, Demos
frontend/index.html       Einzige aktive Oberfläche
frontend/styles.css       Lokales Styling, keine CDN-Abhängigkeit
frontend/app.js           Upload, Ergebnisanzeige, Export, Löschung
lib/encrypt-legacy.js      Unveränderte Verschlüsselung aus dem Gesprächsexport
lib/encrypt.js             Validierende Schnittstelle für das Legacy-Envelope
test/                     39 Node-Tests
docs/                     Prüfung, Sicherheitsgrenzen und Testnachweise
reference/                Unveränderte Ausgangsdateien, nicht vom Server erreichbar
```

Das Verschlüsselungsmodul ist eine eigenständige Bibliothek und **nicht** an den Upload oder die Oberfläche angeschlossen. Es verschlüsselt ausgewählte Record-Felder, aber authentifiziert keine Herkunft und signiert keine Records. Unverschlüsselte Metadaten können verändert werden; ein Test dokumentiert genau diese Grenze. Siehe `docs/SECURITY.md`.

## API

Alle Routen sind ausschließlich lokal erreichbar. Für mutierende Anfragen ist `X-Trust-Protocol: 1` erforderlich. Fremde Origins und nicht lokale Host-Header werden abgelehnt. Es gibt keine CORS-Freigabe und keine öffentliche Authentifizierung.

| Route | Funktion |
|---|---|
| `GET /v1/health` | Fähigkeiten und Grenzen |
| `POST /v1/analyze?filename=DATEI&expected_sha256=HASH` | Binäre Datei hashen, maximal 15 MiB |
| `GET /v1/jobs/ID` | Befund auslesen |
| `DELETE /v1/jobs/ID` | Befund löschen |
| `GET /v1/demo/authentic` | Ausdrücklich fiktives Szenario |
| `GET /v1/demo/ai_manipulated` | Ausdrücklich fiktive KI-Warnung |
| `GET /v1/demo/revoked_cert` | Ausdrücklich fiktiver Widerruf |
| `GET /v1/demo/corrupted_manifest` | Ausdrücklich fiktiver Manifest-Fehler |

**Bewusste API-Änderung gegenüber alten Entwürfen:** Der Upload erwartet einen rohen binären Body mit `Content-Type: application/octet-stream`, kein Multipart/FormData. Der Hash wird beim Einlesen berechnet. Die Antwort ist `202` mit bereits abgeschlossenem Job und abrufbarer Ergebnis-URL; es gibt keine simulierte Hintergrundwarteschlange und kein endloses Polling.

## Nachweise und Grenzen

- 39/39 automatisierte Node-Tests im beigefügten Testlauf erfolgreich.
- 11 erfolgreiche Browserprüfungen in Chromium, einschließlich Upload, Vergleich, JSON-Export, Löschung und Mobilbreite 390 px.
- Testprotokolle unter `docs/`; Node-Tests mit `npm test` reproduzierbar. Browserlauf nicht Teil des abhängigkeitfreien npm-Testskripts; der Playwright-Test liegt unter `docs/browser_check.py` und benötigt separat Python/Playwright/Chromium.
- Keine Aussage über Produktionssicherheit, C2PA-Konformität oder getestete Android-Kompatibilität.
- Kein GitHub-Repository geändert. Nur die bereitgestellten Anhänge wurden verwendet; Behauptungen alter Chatantworten über entfernte CI-Läufe sind nicht als aktueller Nachweis übernommen.
- Die komplette Chat-JSON wird aus Datenschutzgründen nicht mitverteilt. Wiederhergestellte Quelltexte und ein SHA-256-Eingangsmanifest sind enthalten. Der doppelte Demo-Anhang und seine ZIP-Kopie wurden nicht mehrfach aufgenommen.
