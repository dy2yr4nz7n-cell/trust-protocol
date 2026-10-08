# TRUST:// — Record Format 0.2

**Ein offener Standard für nachweisbare Herkunft im Netz.**

TRUST:// beantwortet eine Frage, die heute niemand plattformübergreifend
beantworten kann: *Woher kommt ein Inhalt, und hat ihn seitdem jemand
angefasst?* — und es beantwortet sie, ohne dass ein Anbieter entscheiden muss,
wem man glaubt.

Die vollständige Motivation, das Datenmodell, die Entwurfsprinzipien und die
Abgrenzung stehen in **[TRUST.md](TRUST.md)**. Dieses Readme ist die Landkarte
für den Code.

---

## Drei Achsen, ein berechneter Status

```
origin:     verified | claimed | none
integrity:  intact | modified | broken
generation: attested_by_signer | asserted | none
```

Das sind die einzigen Werte, die je gespeichert werden. Der Status, den ein
Nutzer sieht — VERIFIED, AUTHENTICATED, CLAIMED, MODIFIED, INVALID, UNKNOWN —
wird aus `origin` und `integrity` **berechnet** und niemals persistiert.

| Achse | Frage | Charakter |
|---|---|---|
| `origin` | Kann die Bindung bewiesen werden? | Beobachtung |
| `integrity` | Stimmt der Inhalt noch mit der Signatur? | Beobachtung |
| `generation` | Was wurde über die Erzeugung behauptet? | **Behauptung**, kein Messwert |

Die dritte Achse erkennt nicht, ob etwas KI ist — das kann kein System. Sie
verortet die Behauptung: *signiert* (`attested_by_signer`) oder *frei stehend*
(`asserted`). `none` heißt „niemand hat etwas behauptet", **nicht** „von einem
Menschen gemacht".

---

## Das Gitter

```
             verified          claimed        none
 intact      VERIFIED          CLAIMED        UNKNOWN
 modified    MODIFIED          CLAIMED        UNKNOWN
 broken      INVALID           INVALID        UNKNOWN
```

- **`MODIFIED` ist ein Zustand, keine Warnung.** Eine legitime Bearbeitung nach
  der Signatur erzeugt genau diesen Wert.
- **`UNKNOWN` ist ein Messergebnis, kein Verdacht.**
- **`AUTHENTICATED`** ist `VERIFIED` plus separater Identitätsnachweis.

---

## Dateien

| Datei | Zweck |
|---|---|
| `TRUST.md` | Die Idee, das Datenmodell, die Grenze, die Roadmap |
| `engine.js` | Referenzimplementierung — browser-sicher, keine Abhängigkeiten |
| `record-0.2.schema.json` | JSON Schema (2020-12). `verdict` fehlt darin absichtlich |
| `vectors.js` | Testvektoren, einer pro Status plus Erzeugungsachse |
| `conformance.mjs` | Konformitätsliste, in sich geschlossen |
| `index.html` | Bedienbare Demo |
| `sprechnotizen.md` | Sprechnotizen zum 15-Folien-Deck |

---

## Ausführen

**Konformitätsliste** — braucht nichts außer WebCrypto (Node 18+ oder Browser):

```bash
node conformance.mjs
```

**Demo** — als Ordner über HTTP ausliefern, ES-Module laden nicht von `file://`:

```bash
python3 -m http.server 8000
# http://localhost:8000
```

Alles läuft im Browser. Eine geladene Datei wird lokal gehasht und verlässt die
Seite nicht.

---

## Referenzimplementierung

```js
import { check, recordJson } from "./engine.js";

const { record, derivation } = await check({
  subject: { kind: "url", id: "https://example.org/gallery/hero-77" },
  evidence: [
    { kind: "attestation", label: "C2PA manifest", state: "valid", chain: "intact",
      content_hash: "<sha256 der geladenen Bytes>",
      generation: { kind: "trainedAlgorithmicMedia" } }
  ],
  content_hash: "<sha256 der geladenen Bytes>",
  issuer: "did:web:example.org",
});

derivation.status;            // "VERIFIED"
record.generation;            // "attested_by_signer"
recordJson(record);           // enthält KEIN verdict
```

Die Engine prüft **nicht** die Signatur. Sie konsumiert das Ergebnis einer
Prüfung (`state`, `chain`) und passt damit auf jeden Verifier. Das ist Absicht:
Signaturprüfung braucht Vertrauensliste, Chain-Building und Zeitstempel-Autorität
— also Netzwerk und Infrastruktur, nicht ein paar Zeilen Bibliothek.

---

## Konformität

```
passed 14/14

inv  verdict is never persisted                     holds
inv  unsigned claim never forges provenance         holds
inv  generation never moves origin/integrity        holds
inv  unsigned claim never downgrades a signed subject holds
```

Die vier Invarianten sind der Unterschied zwischen einem Standard und einer
Bibliothek. Jede von ihnen lässt sich in einer Zeile brechen — und dann liest ein
Prüfer eine Herkunft, die niemand belegt hat.

---

## Was fehlt

- **Signaturprüfung** — der nächste echte Bauabschnitt.
- **API (Stufe 5) und Browser-Integration (Stufe 4)** — Roadmap, nicht Code.
- **Kein Patent auf das Datenformat.** Eine Entscheidung, keine Lücke: Ein Patent
  auf den Record tötet die offene Standardisierung.

---

## Abgrenzung

Kein Wahrheitsurteil. Keine Signaturpflicht. Keine Zertifizierungsstelle. Keine
Aussage darüber, ob ein Inhalt von einer Maschine erzeugt ist. Keine
Unterstellung einer Absicht bei fehlendem Nachweis.

**Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.**
