# TRUST verifier: separater Entwicklungsstand

Diese optionale App ergänzt das bestehende Repository, ohne dessen Kernmodule,
Root-Abhängigkeiten, Demo oder Record-Format zu ersetzen. Noch keine Freigabe
für öffentlichen Produktivbetrieb und kein vollständiger Security-Audit.

## Start

Voraussetzung: Node.js >=20.19 und die separat installierte offizielle
c2patool-CLI 0.28.6. Nicht das unbestätigte npm-API toolsList verwenden.
CLI-Dokumentation: https://github.com/contentauth/c2patool/blob/main/docs/usage.md

Im Ordner apps/verifier:

```sh
npm install
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Den erzeugten Wert über eine sichere Umgebungsvariable JWT_SECRET an den
Prozess übergeben. Nicht in Git committen oder in das Browserformular kopieren.
C2PATOOL_PATH kann auf die ausführbare Datei zeigen. Optional nimmt
C2PA_TRUST_ANCHORS einen lokalen PEM-Dateipfad mit bewusst ausgewählten
Vertrauensankern entgegen. Testzertifikate nicht als Produktionsanker verwenden.

```sh
npm run token -- mein-benutzer
npm start
```

Token-Erzeugung und Server müssen dasselbe JWT_SECRET verwenden. Das erzeugte
Token (nicht das Secret) im Browser unter http://127.0.0.1:3000 eingeben.
Es gilt eine Stunde. Es gibt keinen öffentlichen Login-/Token-Ausgabe-Endpunkt.

PUBLIC_ORIGIN muss bei anderer URL exakt auf deren Ursprung gesetzt werden.
PORT ist optional; HOST ist standardmäßig 127.0.0.1. Die App wird nicht auf
GitHub Pages betrieben: Dateiprüfung und Schlüssel bleiben im Node-Backend.

## Verhalten und Grenzen

POST /api/verify erwartet ein Bearer-Token sowie multipart/form-data mit dem
Feld file (JPEG, PNG, WebP; maximal 8 MiB). Optional enthält metadata einen
JSON-String wie {"tools":[{"toolId":"editor","toolName":"Example"}]}.
Solche Clientangaben sind niemals verifizierte Herstellernachweise.
GET /api/capabilities benötigt ebenfalls ein Token.

Die CLI wird ohne Shell mit Zeit- und Ausgabelimit gestartet. Temporäre
Dateien werden im normalen Erfolgs-/Fehlerpfad entfernt. Bei Prozessabsturz
oder erzwungenem Stop können Dateien zurückbleiben; keine sichere Löschgarantie.
Maximal zwei Prüfungen laufen gleichzeitig. Fremde Browser-Ursprünge werden
abgewiesen; keine pauschale CORS-Freigabe. Vor Einsatz im Internet sind HTTPS,
Prozess-/Speicherisolation, Netzwerk-Egress-Sperren, Nutzerverwaltung,
Datenschutzkonzept, Dependency-Lockfile und weitere Laufzeittests erforderlich.
Die CLI-Einstellungen deaktivieren entfernte Manifeste und OCSP; eine
betriebssystemseitige Netzwerksperre ist zusätzlich nötig.

KI-Erstellung wird nur als Manifestdeklaration angezeigt. Nicht gekennzeichnete
KI-Bilder werden nicht aus Pixeln erkannt. Herkunft ist kein Wahrheitsbeweis.
verified_offline ist ausdrücklich keine aktuelle Online-Widerrufsauskunft.
Keine Browser-Kompatibilitätsgarantie: reale Browser-/Gerätetests stehen aus.

## Tatsächlich ausgeführte Prüfungen dieses Änderungsstands

Node.js 20.20.1: 13 Tests des echten c2pa.js-Moduls mit kontrolliertem
CLI-Testdouble bestanden, außerdem 8 JavaScript-Dateien mit node --check
syntaktisch geprüft. Wiederholen mit npm test oder ohne npm-Installation mit
node --test test/c2pa.test.js.

Nicht ausgeführt: echte c2patool-Binärintegration, JWT-/Express-/Joi-Laufzeittests,
Browsertests, Installation/Audit der npm-Abhängigkeiten und der bestehende
Repository-Gesamttest. Die alte Unterhaltung enthält andere Testzahlen; diese
werden für diesen neu erstellten Stand ausdrücklich nicht übernommen.
Ein package-lock.json wurde mangels Dependency-Installation noch nicht erzeugt.
