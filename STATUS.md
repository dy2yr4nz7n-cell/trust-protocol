# STATUS — gemessener Stand, 9. Oktober 2026

Diese Datei ersetzt die Zahlen in `TRUST.md` und `README.md`, wo sie abweichen.
Dort stehen Angaben aus früheren Ständen: „138 Testfälle“, „37 von 48“, und die
Zusage, `createVerifiedTransport` liefere den echten Nachweis. Für den
ausgelieferten Code stimmte das nicht.

---

## Neu: `c2pa-integration.test.mjs`

Die übrigen Suiten prüfen **Nachbauten** der Module innerhalb ihrer eigenen
Datei. Das zeigt die Logik, nicht die ausgelieferte Datei. Der Integrationstest
lädt die echten `c2pa-tsr.js` und `c2pa-transport.js` und schickt echte,
signierte Token hindurch.

Aufruf: `node c2pa-integration.test.mjs` — braucht Node 20 oder neuer.
Ergebnis nach den Korrekturen: **25/25, 5 Invarianten**.

---

## Drei Fehler, die er gefunden hat

Alle drei lagen im ausgelieferten Code und waren in keiner anderen Suite
sichtbar, weil diese Nachbauten prüfen. Er lief zunächst 14 von 23.

**1. `createVerifiedTransport` hat nie etwas geprüft.** Der Transport ruft
`verifyToken` mit **einem Objekt** auf; `verifyTimestampResponse` erwartet die
Token-Bytes als **erstes Argument**. Die Funktion wurde direkt weitergereicht
und bekam das ganze Objekt als „den Token“ — jeder Aufruf endete bei
`step: "parse"`. Jetzt übersetzt ein Adapter und bindet den Token über den
Digest an die Signaturbytes.

**2. Ein Token ohne übergebenen Digest galt als `trusted`.** Der
Imprint-Vergleich wurde übersprungen, wenn kein Digest vorlag. Jetzt endet die
Prüfung bei `step: "imprint"`. Ohne Bindung an die Bytes ist ein Token kein
Beleg.

**3. Ein im Token eingebettetes Zertifikat durfte für das Token bürgen.** Jeder
kann ein Schlüsselpaar erzeugen, ein Token damit signieren und das passende
Zertifikat beilegen. Der Schlüssel kommt jetzt ausschließlich vom Aufrufer.
Wer auf ein bestimmtes TSA-Zertifikat festlegen will:
`spkiFromCertificate(trustedCertDer)`.

Nebenbei: mehrere „wird abgelehnt“-Assertions waren zunächst nur grün, weil jede
Prüfung vorher an `parse` scheiterte. Erst die Assertions auf den **benannten
Schritt** haben das aufgedeckt.

---

## Grenzen — gemessen, nicht vermutet

- **Nie gegen einen echten Dienst gelaufen.** Kein echtes Zertifikat, kein echter
  Zeitstempel, keine reale CRL.
- **Wahrscheinliche erste Fehlerquelle bei einem echten Token:** Viele
  Zeitstempel tragen als Signaturalgorithmus `rsaEncryption`
  (1.2.840.113549.1.1.1) statt `sha256WithRSAEncryption`. Diese OID ist nicht
  abgebildet; das Ergebnis wäre `step: "algorithm"`. Erwartung, keine Messung.
- ECDSA-Schlüssel werden nur als P-256 importiert. Ein TSA auf einer anderen
  Kurve endet bei `step: "tsa-key"`.
- **Die übrigen Suiten prüfen Nachbauten**, nicht die ausgelieferten Dateien.
  `c2pa-transport.test.mjs` hält noch das Verhalten von `@0.2` fest.
- **Kein Datenhash über das Ausschlussverfahren.** `c2pa-verifier.js` hasht die
  ganze Datei oder einen vom Aufrufer genannten Bereich. Ein echtes C2PA-JPEG
  schließt die APP11-Segmente aus der Hash-Rechnung aus; ohne dieses Verfahren
  würde der Digest bei echten Dateien vermutlich nicht passen. Erwartung aus dem
  Code, nicht gemessen.
- **Keine Hash-Bindung der Assertions** an den Claim.
- Keine CRL-Signaturprüfung, keine Zertifikatssignaturprüfung, kein `net.js`.
- Eine Implementierung. Stufe 7 braucht eine zweite.

---

## Herkunft der Dateien in diesem Repository

An diesem Repository haben **mehrere Systeme geschrieben**, nicht nur eines.
Andere Commits stammen aus anderen Quellen und sind nicht gegen den
Integrationstest gelaufen.

Für einen Standard, dessen Gegenstand „nachweisbare Herkunft“ ist, ist das eine
Schwachstelle in der eigenen Ablage: **welche Zeile woher kommt, ist nicht für
jede Datei belegbar.** Wer das Repository prüft, sollte die Commit-Historie je
Datei ansehen, nicht nur den HEAD.

Empfehlung, bis das geklärt ist:

1. ein schreibender Beitragender je Datei,
2. `node c2pa-integration.test.mjs` nach jedem Commit,
3. lesende Systeme dürfen prüfen und vorschlagen, nicht schreiben.

---

## Widerspruch zwischen Dokumenten und Code

`TRUST.md` und `README.md` nennen Zahlen und Zusagen aus früheren Ständen.
Diese Datei ersetzt sie, bis die beiden Dokumente nachgezogen sind.
