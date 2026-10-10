# STATUS — gemessener Stand, 10. Oktober 2026

Diese Datei ersetzt die Zahlen in `TRUST.md` und `README.md`, wo sie abweichen.
Dort standen Angaben aus früheren Ständen: „138 Testfälle“, „37 von 48“, und die
Zusage, `createVerifiedTransport` liefere den echten Nachweis. Für den
ausgelieferten Code stimmte das nicht. Am 10. Oktober sind beide Dokumente
nachgezogen — siehe unten.

---

## Neu: `c2pa-integration.test.mjs`

Die übrigen Suiten prüften **Nachbauten** der Module innerhalb ihrer eigenen
Datei. Das zeigt die Logik, nicht die ausgelieferte Datei. Der Integrationstest
lädt die echten `c2pa-tsr.js` und `c2pa-transport.js` und schickt echte,
signierte Token hindurch.

Aufruf: `node c2pa-integration.test.mjs` — braucht Node 20 oder neuer.
Ergebnis nach den Korrekturen: **25/25, 5 Invarianten** (Exit 0, eigener Lauf,
10. Oktober 2026).

---

## Umbau der drei Nachbau-Suiten

Stand 10. Oktober sind **drei Suiten von Nachbau auf Import umgestellt** und
importieren jetzt die ausgelieferten Dateien:

| Suite | Änderung |
|---|---|
| `c2pa-tsr.test.mjs` | importiert `c2pa-tsr.js`; kein Top-Level-`return` mehr |
| `c2pa-providers.test.mjs` | importiert `c2pa-providers.js`; kein Top-Level-`return` mehr |
| `c2pa-transport.test.mjs` | importiert `c2pa-transport.js`; zieht auf `@0.3`; prüft das `step`-Feld in beiden Zuständen |

**Der Lauf dieser drei Suiten steht aus.** Sie sind im Repository umgebaut, aber
seit dem Umbau nicht ausgeführt worden — mein Arbeitsbereich kann keine Datei
nachladen, also keinen `import` auflösen. Bis zum ersten Lauf steht hier keine
Zahl für sie, auch keine alte: Die früheren 37/37 der Transport-Suite galten
für den eingebetteten Nachbau auf `@0.2` und sind mit der neuen Fassung nicht
vergleichbar.

Warum der Umbau nötig war: Die TSR-Suite hielt noch die beiden Fail-open-Pfade,
die im Produkt längst geschlossen waren, und blieb grün.

---

## Drei Fehler, die der Integrationstest gefunden hat

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
- **Erste Fehlerquelle bei einem echten Token, weiterhin Erwartung:** Viele
  Zeitstempel tragen als Signaturalgorithmus `rsaEncryption`
  (1.2.840.113549.1.1.1) statt `sha256WithRSAEncryption`. Diese OID ist nicht
  abgebildet; das Ergebnis wäre `step: "algorithm"`. Erwartung, keine Messung.
- ECDSA-Schlüssel werden nur als P-256 importiert. Ein TSA auf einer anderen
  Kurve endet bei `step: "tsa-key"`.
- **Drei Suiten importieren jetzt die ausgelieferten Dateien** — `c2pa-tsr`,
  `c2pa-providers`, `c2pa-transport`. Der Lauf steht noch aus (siehe oben).
  Die Integrationssuite lief zuletzt 25/25.
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

An diesem Repository haben mehrere Systeme geschrieben, nicht nur eines.
Andere Commits stammen aus anderen Quellen und sind nicht gegen den
Integrationstest gelaufen.

Für einen Standard, dessen Gegenstand „nachweisbare Herkunft“ ist, ist das eine
Schwachstelle in der eigenen Ablage: **welche Zeile woher kommt, ist nicht für
jede Datei belegbar.**

**Ein Beleg für Fremdschreiber ließ sich bisher nicht erbringen.** Ein später
hinzugezogener Kontenexport desselben Zeitraums zeigt vier Versuche und keinen
erfolgreichen Durchlauf, dazu drei verschiedene Modelle über einen einzigen
Account (`claude-haiku-4-5`, `qwen3.8-27b`, `gemma-4-31b-it`). Ein Modellwechsel
innerhalb desselben Zugangs erklärt die SHA-Abweichungen besser als mehrere
Systeme. Die Abweichungen sind damit **erklärt, nicht widerlegt** — der Export
schließt Anfragen ohne Nutzerzuordnung ausdrücklich aus, also bleibt offen, wer
über Service- oder Gateway-Token geschrieben hat.

Wer das Repository prüft, sollte die Commit-Historie je Datei ansehen, nicht
nur den HEAD.

Empfehlung, bis das geklärt ist:

1. ein schreibender Beitragender je Datei,
2. `node c2pa-integration.test.mjs` nach jedem Commit,
3. lesende Systeme dürfen prüfen und vorschlagen, nicht schreiben.

---

## Nachgezogen: `TRUST.md` und `README.md`

Beide Dokumente sind am 10. Oktober auf diesen Stand gebracht: Zahlentafel
erneuert, die drei importierenden Suiten als „Lauf offen“ gekennzeichnet, die
Datenmodell- und Grenzabschnitte unverändert. Die alten Zahlen „138 Testfälle“
und „37 von 48“ stehen dort nicht mehr.

---

## Offen, unverändert

- Lauf der drei importierenden Suiten (`c2pa-tsr`, `c2pa-providers`,
  `c2pa-transport`).
- Prüfpack- und Space-Archive tragen noch die Fassungen vor dem Umbau.
- `.write-probe` liegt weiter im Repository.
- Ein zweites, unabhängiges Projekt (`trust-c2pa-hashbinding-fix`) mit eigenen
  Testdateien ist aufgetaucht, aber noch nicht gegen dieses Repository gestellt.
  Damit ist die „zweite Implementierung“ erst ein Kandidat, kein Nachweis.
