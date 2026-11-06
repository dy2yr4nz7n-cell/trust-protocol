# Serverseitige JWT-Authentifizierung

## Einordnung

`src/auth.js` vervollständigt den bereitgestellten JWT-Baustein. Das Repository verwendet ES-Module, deshalb werden `import` und benannte `export`-Funktionen statt `require` und `module.exports` verwendet. Das optionale Servermodul hat eine eigene `src/package.json` und Lockdatei. Die bestehenden Browsermodule, Protokollfunktionen und die Abhängigkeiten im Root bleiben unverändert.

Dieses Modul ist noch keine Login-Anwendung und schützt ohne Einbindung keine bestehende Route. Es gehört ausschließlich auf den Server, nicht in `index.html`, den Service Worker oder ein Browser-Bundle. Es implementiert keine KI-Erkennung oder Medien-Herkunftsprüfung.

## Installation und Test

Im Repository-Stamm:

```sh
npm ci --prefix src --ignore-scripts
npm run test:auth
```

Zum Ausführen der vorhandenen Protokolltests zusätzlich `npm ci` und `npm test` verwenden. Der neue Auth-CI-Job ist von den vorhandenen Protokolltests getrennt und läuft in der bestehenden Versionsmatrix Node 18, 20 und 22.

## Secret konfigurieren

Zufälligen Wert erzeugen:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Den ausgegebenen Wert im Secret-Manager oder in der Laufzeitumgebung als `JWT_SECRET` setzen, bevor `src/auth.js` importiert wird. Keine Secrets committen oder an den Browser senden. `.env`-Dateien sind zusätzlich in `.gitignore` ausgeschlossen; das Modul lädt solche Dateien nicht automatisch. Ein Secret mit mindestens 32 Byte ist vorgeschrieben, aber Länge allein garantiert keine Zufälligkeit. Kein Secret-Wert ist in dieser Anleitung oder im Quellcode eingebaut.

## Einbindung

In einer bereits vorhandenen serverseitigen Express-Anwendung:

```js
import { createAccessToken, verifyToken } from './src/auth.js';

// Ausschließlich NACH erfolgreicher Anmeldung aufrufen:
const accessToken = createAccessToken(authenticatedUser);
// Über die vorhandene Login-Route zurückgeben.

app.get('/api/me', verifyToken, (req, res) => {
  res.json({ id: req.user.id });
});
```

`app` und `authenticatedUser` werden von der jeweiligen Anwendung bereitgestellt. Dieses Repository enthält keine Express-Laufzeit und dieser Ausschnitt ist kein eigenständig startbarer Server. Eine Express-Abhängigkeit wird daher nicht hinzugefügt.

Requests an geschützte Routen benötigen den Header `Authorization: Bearer <access-token>`. Nach erfolgreicher Prüfung enthält `req.user` nur `id`, `sub`, `iat` und `exp`. Benutzer-IDs können nichtleere Strings oder nichtnegative sichere Ganzzahlen sein. Zusätzliche Rollen- oder Kontoprüfungen muss die Anwendung selbst ausführen.

## Prüfregeln

- Tokens werden mit HS256 und einer Lebensdauer von einer Stunde ausgestellt.
- Verifikation akzeptiert nur HS256, gültige Signatur und zulässige Zeitangaben.
- Benutzer-ID und `sub` müssen zueinander passen; `iat` und `exp` sind verpflichtend.
- Tokens ohne Ablaufzeit, mit zukünftiger Ausstellung oder einer Lebensdauer über einer Stunde werden abgelehnt.
- Ungültige, abgelaufene, noch nicht aktive oder manipulierte Tokens ergeben HTTP 401 mit generischer Fehlermeldung, `WWW-Authenticate: Bearer` und `Cache-Control: no-store`.
- Unerwartete interne Fehler gehen an `next(error)`; Fehler nachfolgender Middleware werden nicht als Authentifizierungsfehler abgefangen.
- Fehlendes oder zu kurzes `JWT_SECRET` führt bereits beim Import zu einem Fehler.

## Betriebsgrenzen

Nur HTTPS verwenden. Tokenbesitz ersetzt keine Benutzerkontoprüfung oder Autorisierung. JWT-Payloads sind nicht verschlüsselt; keine vertraulichen Daten hineinlegen. Kein Refresh-Token-Verfahren, keine Widerrufsliste, keine automatische Kontosperrenprüfung und kein Rate-Limiting sind enthalten. Alle Serverinstanzen derselben Anwendung benötigen denselben Schlüssel. Ein Schlüsselwechsel macht vorhandene Tokens ungültig. Beim Umstieg von der fehlerhaften Vorversion müssen sich Benutzer erneut anmelden.

Für mehrere Anwendungen oder Tokenarten getrennte Schlüssel verwenden oder explizite Issuer-/Audience-Bindungen ergänzen. Tokenwerte und Schlüssel nicht loggen. Passwörter und Anmeldedaten müssen vor `createAccessToken` durch die Anwendung verifiziert worden sein.

## Lokaler Testnachweis

Basis: main-Commit `a4dda132a135dc2d5bd443d6342cd399c0627a45`. Die Auth-Suite umfasst 45 Tests und wurde lokal mit Node 18, 20 und 22 erfolgreich ausgeführt. Sie nutzt echte jsonwebtoken-Signaturen mit kleinen Express-kompatiblen Request-/Response-Testobjekten, nicht einen vollständigen HTTP-Integrationstest. Ein `npm audit --prefix src --omit=dev` meldete zum Testzeitpunkt keine bekannten Schwachstellen; das ist kein Sicherheitsaudit.

Die vorhandene Gesamtsuite ist bereits im unveränderten Basisstand nicht grün: `fingerprint.test.mjs:196` enthält ein Top-Level-`return` und erzeugt einen Syntaxfehler. Außerdem schlägt `c2pa-transport.test.mjs` im Basisstand fehl (38/49, Invariante zur abgelaufenen Zertifikatskette verletzt). Diese bestehenden Fehler wurden separat auf einem unveränderten Export von main reproduziert und in diesem Auth-Patch nicht verändert. Die Protokoll-Gesamtsuite wird ausdrücklich nicht als erfolgreich ausgewiesen.
