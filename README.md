# TRUST:// — Record Format 0.2

**Ein offener Standard für nachweisbare Herkunft im Netz.**

TRUST:// beantwortet eine Frage, die heute niemand plattformübergreifend
beantworten kann: *Woher kommt ein Inhalt, und hat ihn seitdem jemand
angefasst?* — und es beantwortet sie, ohne dass ein Anbieter entscheiden muss,
wem man glaubt.

Vollständige Motivation, Datenmodell, Entwurfsprinzipien und Abgrenzung stehen
in **[TRUST.md](TRUST.md)**. Dieses Readme ist die Landkarte für den Code.

---

## Zwei Achsen im Gitter, eine daneben

```
origin:     verified | claimed | none
integrity:  intact | modified | broken
generation: attested_by_signer | asserted | none
```

Das Gitter ist **unverändert seit 0.1**. Sechs Status, zwei Achsen, dieselbe
Zuordnung. Daneben steht eine dritte Prüfung, die den Status nie berührt:

```
fingerprint: match | mismatch | multiple | none
```

| | Frage | Charakter |
|---|---|---|
| `origin` | Kann die Bindung bewiesen werden? | Beobachtung |
| `integrity` | Stimmt der Inhalt noch mit der Signatur? | Beobachtung |
| `generation` | Was wurde über die Erzeugung behauptet? | **Behauptung** |
| `fingerprint` | Ist der Inhalt der Inhalt, der er zu sein behauptet? | **Eigenschaft des Inhalts** |

---

## Der Fingerabdruck

**Alles hat einen Fingerabdruck.** Ein Hash ist keine Meinung eines Prüfers über
einen Inhalt — er ist eine Eigenschaft des Inhalts selbst. Deshalb braucht diese
Prüfung **keinen Verifier, keine Trust-Liste, kein Netzwerk**: Sie vergleicht den
deklarierten Fingerabdruck mit dem Fingerabdruck der vorliegenden Bytes.

| Ergebnis | Bedeutung |
|---|---|
| `match` | Der deklarierte Fingerabdruck ist der dieser Bytes |
| `mismatch` | Der deklarierte Fingerabdruck gehört zu anderen Bytes |
| `multiple` | Die Belege deklarieren mehr als einen Fingerabdruck |
| `none` | Nichts wurde deklariert, also nichts zu vergleichen |

**Warum er neben dem Gitter steht und nicht darin:**

- Das Gitter sagt: *in welchem Zustand ist dieser Record.*
- Der Fingerabdruck sagt: *ist der Inhalt der Inhalt, der er zu sein behauptet.*

Verschiedene Fragen, verschiedene Haltbarkeitsdauern. Der **Status** ändert sich,
wenn neue Belege eintreffen — aus CLAIMED kann später VERIFIED werden. Der
**Fingerabdruck** ist einfach; er wurde über Bytes gerechnet und ist in hundert
Jahren dieselbe Tatsache.

Der wichtigste Fall, den das sichtbar macht:

```
Status:        CLAIMED      (Signatur nicht bestätigt)
Fingerabdruck: mismatch     (die Bytes sind andere)
```

Vorher wäre dieser Befund spurlos im Status verschwunden. Jetzt steht er da.
Und: **Der Fingerabdruck kann einen Status nie anheben.**

---

## Das Gitter

```
             verified          claimed        none
 intact      VERIFIED          CLAIMED        UNKNOWN
 modified    MODIFIED          CLAIMED        UNKNOWN
 broken      INVALID           INVALID        UNKNOWN
```

- **`MODIFIED` ist ein Zustand, keine Warnung.**
- **`UNKNOWN` ist ein Messergebnis, kein Verdacht.**
- **`AUTHENTICATED`** ist `VERIFIED` plus separater Identitätsnachweis.

---

## Module, und die Frage, die jedes beantwortet

| Modul | Frage |
|---|---|
| `signature.js` | **Dürfen wir diese Attestierung „verifiziert" nennen?** |
| `verifier-bridge.js` | Kann der Record die Antwort der Prüfung lesen? |
| `engine.js` | Gegeben geprüfte Fakten — was ist der Record? |
| `derivation.js` | Ist ein verändertes Byte ein Transform oder eine Manipulation? |
| `fingerprint.js` | Ist der Inhalt der Inhalt, der er zu sein behauptet? |
| `c2pa-verifier.js` | Was sagt das Manifest über Signatur und Erzeugung? |
| `c2pa-providers.js` | Signatur, Kette, Zeitstempel — drei Provider |
| `c2pa-transport.js` | Wie kommt die Netz-Antwort in den Record? |
| `c2pa-tsr.js` | **Ist der Zeitstempel bewiesen oder nur behauptet?** |

---

## Signaturen: die Grenze, die man nicht überschreiten kann

Volle C2PA-Validierung braucht Netzwerk und Vertrauensliste. Die Arbeit ist
deshalb entlang einer Linie geteilt:

```
VERIFIER (braucht Netz)           POLICY (signature.js, braucht nichts)
------------------------------    --------------------------------------
Kette zu einem Trust Anchor       Ist der Anchor einer, dem WIR trauen?
Revocation (CRL / OCSP)           Ist der Chain-Zustand für uns akzeptabel?
RFC 3161 Zeitstempel              Behandeln wir "unbekannt" als Fehler?
Kryptografische Signaturprüfung   Wieviel Uhr-Abweichung erlauben wir?
```

Der Verifier ist eine **injizierte Schnittstelle**. Die Policy-Schicht ist
vollständig gebaut und getestet.

```js
import { createDemoVerifier, DEMO_VERIFICATIONS, DEMO_POLICIES } from "./demo-verifier.js";
import { createTrustList, withPolicy, annotateEvidence } from "./verifier-bridge.js";
import { deriveRecord } from "./engine.js";
import { attachChecks } from "./fingerprint.js";

const verifier = createDemoVerifier(DEMO_VERIFICATIONS);
const policy = withPolicy(DEMO_POLICIES.strict.config(createTrustList));

// annotateEvidence ERSETZT state und chain durch das, was der Verifier
// festgestellt hat. Ein Aufrufer kann kein state: "valid" einschmuggeln.
const evidence = await annotateEvidence(rawEvidence, verifier, policy);
const input = { subject, evidence, content_hash, issuer };

const out = deriveRecord(input);
const withChecks = attachChecks(out.record, input, trustStore);
```

**Die Regel, die alles trägt:** Ein fehlgeschlagener *oder* unbestimmter Check
erzeugt **nie** `verified`. `unknown` und `invalid` sind verschiedene Aussagen.

---

## Der Zeitstempel: zwei Schritte, die man nicht verschmelzen darf

Ein RFC-3161-Zeitstempel sieht wie ein Ergebnis aus und ist zwei Dinge:

```
1. STATUS      Die Autorität hat "granted" geantwortet.
2. TSA-PROOF   Die CMS-Signatur hält gegen den TSA-Schlüssel, über
               Attribute, die die TSTInfo decken, deren messageImprint
               die Signaturbytes deckt, die man bekommen hat.
```

Schritt 1 allein ist eine **Behauptung eines Dritten**. Erst Schritt 2 ist ein
**Nachweis**. `c2pa-tsr.js` trennt beide und prüft der Reihe nach:

| Prüfung | Scheitert bei |
|---|---|
| `status` | Antwort ohne `granted` |
| `token` | `granted` ohne Token |
| `imprint` | Imprint deckt nicht die Signaturbytes |
| `contentdigest` | signiertes message-digest passt nicht zur TSTInfo |
| `tsa-key` | kein TSA-Schlüssel, also nichts geprüft |
| `cms-signature` | Signatur hält nicht über die signierten Attribute |
| `verified` | **nur** wenn alles oben gehalten hat |

```js
import { createVerifiedTransport } from "./c2pa-transport.js";

// Ohne verifyToken bleibt es beim ehrlichen Nein, mit step: "tsa-signature".
// Mit dem Verifier wird aus dem Status ein Nachweis.
const transport = createVerifiedTransport({
  http: myFetch,
  trustAnchors: ["Example Root CA"],
  tsaPublicKey: spkiBytes,
});
```

**Ein Ergebnis, das seinen Schritt nennt, ist mehr wert als ein `false`.** Wer
`step: "contentdigest"` bekommt, weiß, dass die Signatur stand und die Bindung
zwischen Signatur und Token nicht — das sind zwei verschiedene Reparaturen.

---

## Ableitungen: MODIFIED auflösbar machen

Ein gescanntes Kartenbild ist nicht das Foto — zwischen Aufnahme und Anzeige
liegen Geraderücken, Zuschnitt, Farbkorrektur. `subject.derived_from` verlinkt
die aktuellen Bytes zurück zur signierten Quelle:

> **Eine Ableitung bewegt nur `integrity`, niemals `origin`.**
> Man kann keine Herkunft erben, die man nicht beweisen kann.

---

## Dateien

| Datei | Zweck |
|---|---|
| `TRUST.md` | Die Idee, das Datenmodell, die Grenze, die Roadmap |
| `engine.js` | Record-Ableitung aus geprüften Fakten |
| `derivation.js` | Ableitungs-Pipeline mit Herkunftskette |
| `signature.js` | Signatur-**Policy** + Verifier-Schnittstelle |
| `verifier-bridge.js` | Brücke: Verifier-Antwort → Record-Evidence |
| `fingerprint.js` | Fingerabdruck-Prüfung und Ableitungs-Verweis |
| `c2pa-verifier.js` | Manifest-, Signatur- und Erzeugungsschicht über Bytes |
| `c2pa-providers.js` | Signatur-, Ketten- und Zeitstempel-Provider |
| `c2pa-transport.js` | Netz-Schicht: Kette, CRL, Zeitstempel-Status |
| `c2pa-tsr.js` | **Zweiter Zertifizierungsschritt: TSA-Signaturnachweis** |
| `demo-verifier.js` | Demo-Verifier und die vier Policies |
| `record-0.2.schema.json` | JSON Schema (2020-12). `verdict` fehlt darin absichtlich |
| `vectors.js` | Testvektoren |
| `conformance.mjs` · `derivation.test.mjs` · `signature.test.mjs` · `fingerprint.test.mjs` | Die vier in sich geschlossenen Suiten |
| `c2pa-transport.test.mjs` · `c2pa-providers.test.mjs` · `c2pa-tsr.test.mjs` | Die drei c2pa-Suiten — sie **importieren** die ausgelieferten Module |
| `c2pa-integration.test.mjs` | Integrationstest gegen die ausgelieferten Module |
| `index.html` | Bedienbare Demo mit Policy-Umschaltung und Fingerabdruck-Panel |
| `sw.js` · `manifest.webmanifest` · `.nojekyll` | Offline-Shell, installierbar, GitHub Pages |
| `sprechnotizen.md` | Sprechnotizen zum 15-Folien-Deck |

---

## Ausführen

Die vier ersten Suiten sind in sich geschlossen — sie brauchen nichts außer
WebCrypto. Die drei c2pa-Suiten und der Integrationstest **importieren** die
ausgelieferten Module und müssen im selben Verzeichnis laufen:

```bash
node conformance.mjs
node derivation.test.mjs
node signature.test.mjs
node fingerprint.test.mjs
node c2pa-tsr.test.mjs
node c2pa-providers.test.mjs
node c2pa-transport.test.mjs
node c2pa-integration.test.mjs
```

**Demo** — über HTTP ausliefern, ES-Module laden nicht von `file://`:

```bash
python3 -m http.server 8000
# http://localhost:8000
```

---

## Prüfergebnisse

```
conformance.mjs          passed 14/14
derivation.test.mjs      passed 16/16
signature.test.mjs       passed 18/18
fingerprint.test.mjs     passed 20/20
c2pa-integration.test.mjs  passed 25/25   (ausgelieferte Module)
c2pa-tsr.test.mjs        importiert c2pa-tsr.js         Lauf offen
c2pa-providers.test.mjs  importiert c2pa-providers.js   Lauf offen
c2pa-transport.test.mjs  importiert c2pa-transport.js   Lauf offen

Gemessen: 93 Assertions in vier Suiten plus 25 im Integrationstest,
zwanzig Invarianten. Die drei importierenden Suiten sind umgebaut, aber seit
dem Umbau nicht gelaufen; ihre alten Zahlen gelten für den eingebetteten
Nachbau und stehen deshalb nicht mehr hier. Eine gerundete Gesamtzahl gibt es
nicht.

inv  verdict is never persisted                          holds
inv  unsigned claim never forges provenance              holds
inv  generation never moves origin/integrity             holds
inv  unsigned claim never downgrades a signed subject    holds
inv  derivation moves only integrity                     holds
inv  derivation never grants origin                      holds
inv  unresolvable edit stays MODIFIED                    holds
inv  nothing non-verified is reported as verified        holds
inv  unknown stays distinct from invalid                 holds
inv  a throwing verifier never verifies                  holds
inv  an untrusted anchor never verifies                  holds
inv  an expired chain never verifies by default          holds
inv  the grid is unchanged: nine mappings                holds
inv  the fingerprint is reported when the status hides it holds
inv  the fingerprint never lifts a status                holds
inv  a root off the trust list is never accepted         holds
inv  a CRL match is by value, not by position            holds
inv  no http function means no revocation was checked    holds
inv  a timestamp is never trusted without a TSA proof    holds
inv  every refusal names the step that blocked           holds
```

---

## Was fehlt

- **Ein echtes Netz-I/O.** Alle Provider und der TSA-Nachweis sind gebaut und
  geprüft, aber die `http`-Funktion wird von außen übergeben. Der Bauabschnitt ist
  eine `fetch`-Implementierung mit Rate-Limit und Frist, kein Algorithmus.
- **CRL-Signaturprüfung.** Die Kettenordnung und die Wertsuche laufen; die
  Signatur über die CRL selbst nicht.
- **Zwei interoperable Implementierungen.** Ein Standard mit einer Umsetzung ist
  eine Beschreibung. Stufe 7 braucht eine zweite. Ein Kandidat mit eigener
  Testdatei (`trust-c2pa-hashbinding-fix`) ist aufgetaucht, aber noch nicht
  gegen dieses Repository gestellt — ein Kandidat ist kein Nachweis.
- **Derivation über Record-Grenzen.** Heute löst ein Verifier gegen seinen
  eigenen Store auf.
- **API (Stufe 5) und Browser-Integration (Stufe 4)** — Roadmap, nicht Code.
- **Kein Patent auf das Datenformat.** Eine Entscheidung, keine Lücke.

---

## Lizenz

Apache-2.0. Siehe [LICENSE](LICENSE).

---

## Abgrenzung

Kein Wahrheitsurteil. Keine Signaturpflicht. Keine Zertifizierungsstelle. Keine
Aussage darüber, ob ein Inhalt von einer Maschine erzeugt ist.

**Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.**
