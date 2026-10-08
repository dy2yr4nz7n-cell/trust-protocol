# TRUST:// — Record Format 0.2

**Ein offener Standard für nachweisbare Herkunft im Netz.**

TRUST:// beantwortet eine Frage, die heute niemand plattformübergreifend
beantworten kann: *Woher kommt ein Inhalt, und hat ihn seitdem jemand
angefasst?* — und es beantwortet sie, ohne dass ein Anbieter entscheiden muss,
wem man glaubt.

Vollständige Motivation, Datenmodell, Entwurfsprinzipien und Abgrenzung stehen
in **[TRUST.md](TRUST.md)**. Dieses Readme ist die Landkarte für den Code.

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

## Vier Module, vier Fragen

Der Code ist entlang von Fragen geschnitten, nicht entlang von Schichten. Jedes
Modul besitzt genau eine, und keine beantwortet die einer anderen.

| Modul | Frage | Braucht Netz? |
|---|---|---|
| `signature.js` | **Dürfen wir diese Attestierung „verifiziert" nennen?** | nein (Policy) |
| `verifier-bridge.js` | Kann der Record die Antwort der Prüfung lesen? | nein |
| `engine.js` | Gegeben geprüfte Fakten — was ist der Record? | nein |
| `derivation.js` | Ist ein verändertes Byte ein Transform oder eine Manipulation? | nein |

---

## Signaturen: die Grenze, die man nicht überschreiten kann

Volle C2PA-Validierung heißt: CBOR/COSE-Struktur parsen, X.509-Kette zu einem
Trust Anchor bauen, Revocation prüfen (CRL/OCSP über Netz), RFC-3161-Zeitstempel
verifizieren. **Das braucht ein Netzwerk und eine Vertrauensliste.** Wer behauptet,
das offline zu tun, lügt.

Die Arbeit ist deshalb entlang einer Linie geteilt, die sich ehrlich ziehen lässt:

```
VERIFIER (braucht Netz)           POLICY (signature.js, braucht nichts)
------------------------------    --------------------------------------
Kette zu einem Trust Anchor       Ist der Anchor einer, dem WIR trauen?
Revocation (CRL / OCSP)           Ist der Chain-Zustand für uns akzeptabel?
RFC 3161 Zeitstempel              Behandeln wir "unbekannt" als Fehler?
Kryptografische Signaturprüfung   Wieviel Uhr-Abweichung erlauben wir?
```

Der Verifier ist eine **injizierte Schnittstelle**, keine fehlende Funktion. Die
Policy-Schicht ist vollständig gebaut und getestet.

```js
import { createStubVerifier, withPolicy, createTrustList, annotateEvidence } from "./verifier-bridge.js";
import { deriveRecord } from "./engine.js";

const verifier = createStubVerifier({ "urn:c2pa:9f2c": { state: "verified", chain: "intact", anchor: "Example Root CA" } });

const policy = withPolicy({
  trustList: createTrustList(["Example Root CA"]),
  allowExpiredChain: false,
  requireTrustedTimestamp: false,
});

// Die Attestierung wird NICHT ungeprüft übernommen: annotateEvidence ersetzt
// `state` und `chain` durch das, was der Verifier festgestellt hat.
const evidence = await annotateEvidence(rawEvidence, verifier, policy);
const { record, derivation } = deriveRecord({ subject, evidence, content_hash, issuer });
```

**Die Regel, die alles trägt:** Ein fehlgeschlagener *oder* unbestimmter Check
erzeugt **nie** `verified`. Unbestimmtes Verhalten schlägt geschlossen fehl — eine
unauflösbare Kette, ein abgelaufenes Zertifikat und ein Verifier, der schlicht
eine Exception wirft, landen bei höchstens `claimed`.

Und: **`unknown` und `invalid` sind verschiedene Aussagen.** Sie zu verschmelzen
würde aus „wir konnten nicht prüfen" ein „wir haben geprüft, es ist gefälscht"
machen — die schädlichste Lüge, die ein Verifikationssystem erzählen kann.

---

## Ableitungen: MODIFIED auflösbar machen

Ein gescanntes Kartenbild ist nicht das Foto. Zwischen Aufnahme und Anzeige
liegen Geraderücken, Zuschnitt, Farbkorrektur, Skalierung. **Die meisten Records
in der echten Welt sind so** — das Geprüfte ist ein bearbeitetes Derivat von
etwas, das signiert war.

Der Record löst das mit einem Feld am Subjekt:

```json
"subject": {
  "kind": "card",
  "id": "card:pokemon:base-set:4/102",
  "derived_from": ["<sha256 der Kamera-Aufnahme>"]
}
```

> **Eine Ableitung bewegt nur `integrity`, niemals `origin`.**
> Man kann keine Herkunft erben, die man nicht beweisen kann.

Ein fremdes Bild, das einfach dieselbe Abstammung *behauptet*, erbt nichts:
`origin` bleibt `none`, der Status bleibt UNKNOWN. Ein Edit ohne auflösbaren
Verweis bleibt `modified` **ohne** `resolvable`-Markierung.

---

## Dateien

| Datei | Zweck |
|---|---|
| `TRUST.md` | Die Idee, das Datenmodell, die Grenze, die Roadmap |
| `engine.js` | Record-Ableitung aus geprüften Fakten |
| `derivation.js` | Ableitungs-Pipeline mit Herkunftskette |
| `signature.js` | Signatur-**Policy** + Verifier-Schnittstelle |
| `verifier-bridge.js` | Brücke: Verifier-Antwort → Record-Evidence |
| `record-0.2.schema.json` | JSON Schema (2020-12). `verdict` fehlt darin absichtlich |
| `vectors.js` | Testvektoren, einer pro Status plus Erzeugungsachse |
| `conformance.mjs` | Konformitätsliste, in sich geschlossen |
| `derivation.test.mjs` | Ableitungs-Suite: Scan-Szenario, Ende zu Ende |
| `signature.test.mjs` | Signatur-Policy-Suite: fail closed |
| `index.html` | Bedienbare Demo |
| `sw.js`, `manifest.webmanifest`, `.nojekyll` | Offline-Shell, installierbar, GitHub Pages |
| `sprechnotizen.md` | Sprechnotizen zum 15-Folien-Deck |

---

## Ausführen

Alle Suiten sind in sich geschlossen — sie brauchen nichts außer WebCrypto:

```bash
node conformance.mjs
node derivation.test.mjs
node signature.test.mjs
```

**Demo** — über HTTP ausliefern, ES-Module laden nicht von `file://`:

```bash
python3 -m http.server 8000
# http://localhost:8000
```

---

## Prüfergebnisse

```
conformance.mjs      passed 14/14
derivation.test.mjs  passed 16/16
signature.test.mjs   passed 18/18

inv  verdict is never persisted                        holds
inv  unsigned claim never forges provenance            holds
inv  generation never moves origin/integrity           holds
inv  unsigned claim never downgrades a signed subject  holds
inv  derivation moves only integrity                   holds
inv  derivation never grants origin                    holds
inv  unresolvable edit stays MODIFIED                  holds
inv  nothing non-verified is reported as verified      holds
inv  unknown stays distinct from invalid               holds
inv  a throwing verifier never verifies                holds
inv  an untrusted anchor never verifies                holds
inv  an expired chain never verifies by default        holds
```

Zwölf Invarianten. Jede lässt sich in einer Zeile brechen — und dann liest ein
Prüfer eine Herkunft, die niemand belegt hat.

---

## Was fehlt

- **Ein konkreter C2PA-Verifier.** Die Schnittstelle ist definiert und getestet,
  ein echter Verifier (Netz, Revocation, Zeitstempel) ist der nächste Bauabschnitt.
- **Derivation über Record-Grenzen.** Heute löst ein Verifier gegen seinen
  eigenen Store auf. Für plattformübergreifende Ketten braucht es eine
  Abfrage-Semantik, nicht nur einen Map-Zugriff.
- **API (Stufe 5) und Browser-Integration (Stufe 4)** — Roadmap, nicht Code.
- **Kein Patent auf das Datenformat.** Eine Entscheidung, keine Lücke.

---

## Lizenz

Apache-2.0. Siehe [LICENSE](LICENSE).

Abschnitt 3 enthält eine **Patentlizenz** auf Beiträge. Für ein Format, das
offen bleiben soll, ist das die passende Wahl — es verhindert, dass ein
Beitragender später Patentansprüche gegen Implementierungen geltend macht.
Patente auf den Record selbst gibt es nicht.

---

## Abgrenzung

Kein Wahrheitsurteil. Keine Signaturpflicht. Keine Zertifizierungsstelle. Keine
Aussage darüber, ob ein Inhalt von einer Maschine erzeugt ist. Keine
Unterstellung einer Absicht bei fehlendem Nachweis.

**Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.**
