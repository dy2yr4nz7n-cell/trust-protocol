# TRUST:// — Ein offener Standard für nachweisbare Herkunft im Netz

> **Version 0.3** · Record Format `TRUST-Record/0.2` · Referenzimplementierung in Arbeit

TRUST:// beantwortet eine Frage, die heute niemand plattformübergreifend beantworten
kann: **Woher kommt ein Inhalt, und hat ihn seitdem jemand angefasst?** — und es
beantwortet sie, ohne dass ein Anbieter entscheiden muss, wem man glaubt.

Das ist die ganze Idee. Alles Weitere folgt daraus.

---

## Das Problem

Die Debatte um manipulierte Inhalte wird entlang der falschen Achse geführt:
*künstlich erzeugt gegen menschlich erzeugt*. Diese Unterscheidung trägt keine
Entscheidung.

- Sie ist **nicht überprüfbar** — niemand sieht einem Inhalt an, mit welchem
  Werkzeug er entstanden ist.
- Sie ist **nicht aussagekräftig** — Menschen erzeugen seit Jahrtausenden
  Falschaussagen ohne jede Maschine.
- Sie ist **nicht belastbar** — Wasserzeichen sterben beim ersten Neuspeichern,
  Metadaten sagen, wer signiert hat, und Detektoren sind statistische
  Klassifikatoren, deren Falsch-Positiv-Rate genau dort am höchsten ist, wo am
  wenigsten Schutz nötig wäre.

Die einzige Frage, die technisch beantwortbar ist und über Jahre stabil bleibt,
lautet: **hält die Kette.** Stammt der Inhalt von dem, der ihn beansprucht, und
ist er seitdem unverändert.

Was fehlt, ist nicht die Kryptografie. Signaturen, Hashes und C2PA-Manifeste
existieren und funktionieren. Was fehlt, ist ein **gemeinsames Vokabular**, um
das Ergebnis einer Prüfung zwischen Systemen auszutauschen, ohne dass dabei eine
Plattform zum Gatekeeper wird.

---

## Die Antwort: drei unabhängige Achsen

```
origin:     verified | claimed | none
integrity:  intact | modified | broken
generation: attested_by_signer | asserted | none
```

Das sind die einzigen Werte, die je gespeichert werden. Der Status, den ein
Nutzer sieht — VERIFIED, AUTHENTICATED, CLAIMED, MODIFIED, INVALID, UNKNOWN —
wird aus `origin` und `integrity` **berechnet** und niemals persistiert.

### Warum drei Achsen und nicht eine Skala

Eine Skala nach Vertrauensgrad presst zwei orthogonale Dimensionen in eine Zahl.
Herkunft beantwortet *wer beansprucht*; Integrität beantwortet *ob unverändert*.
Und die dritte Achse beantwortet eine Frage, die man von den ersten beiden
sorgfältig trennen muss — weil sie eine **Behauptung** ist, kein Messwert.

| Achse | Frage | Charakter |
|---|---|---|
| `origin` | Kann die Bindung bewiesen werden? | Beobachtung, kryptografisch entscheidbar |
| `integrity` | Stimmt der Inhalt noch mit der Signatur? | Beobachtung, kryptografisch entscheidbar |
| `generation` | Was wurde über die Erzeugung behauptet? | **Behauptung**, nicht entscheidbar |

### Die Erzeugungsachse

Die Frage *„ist das KI?"* lässt sich nicht messen. Sie lässt sich aber
**verorten**: wer hat sie gestellt, und war er bereit, sie zu signieren.

| Wert | Bedeutung |
|---|---|
| `attested_by_signer` | Die Aussage steckt **innerhalb** einer gültigen Signatur. Der Signierende kann sie nicht später abstreiten. Immer noch eine Aussage über Urheberschaft. |
| `asserted` | Die Aussage steht lose. Jeder kann sie anhängen, auch ein Detektor mit 0,87 Konfidenz. |
| `none` | Niemand hat etwas behauptet. **Nicht** „von einem Menschen gemacht". |

**Der Satz, der das trägt:** Wir können nicht feststellen, ob ein Inhalt KI ist.
Wir können feststellen, wer eine Erzeugungsaussage gemacht hat und ob sie
signiert war.

---

## Das Gitter

```
             verified          claimed        none
 intact      VERIFIED          CLAIMED        UNKNOWN
 modified    MODIFIED          CLAIMED        UNKNOWN
 broken      INVALID           INVALID        UNKNOWN
```

`AUTHENTICATED` ist `VERIFIED` plus ein separater Identitätsnachweis — ein Flag,
kein fünfter Herkunftswert, weil Identität orthogonal zum Gitter ist.

Zwei Eigenschaften sind konstitutiv:

- **`MODIFIED` ist ein Zustand, keine Warnung.** Eine legitime Bearbeitung nach
  der Signatur erzeugt genau diesen Wert. Wer ihn als Betrug anzeigt, liegt falsch.
- **`UNKNOWN` ist ein Messergebnis, kein Verdacht.** Ein System, das fehlenden
  Nachweis als Risiko ausweist, ist ein Gatekeeper. Wir tun das nicht.

---

## Der Fingerabdruck: eine Prüfung daneben

**Alles hat einen Fingerabdruck.** Ein Hash ist keine Meinung eines Prüfers über
einen Inhalt — er ist eine Eigenschaft des Inhalts selbst. Deshalb braucht diese
Prüfung keinen Verifier, keine Trust-Liste und kein Netzwerk: Sie vergleicht den
deklarierten Fingerabdruck mit dem Fingerabdruck der vorliegenden Bytes.

| Ergebnis | Bedeutung |
|---|---|
| `match` | Der deklarierte Fingerabdruck ist der dieser Bytes |
| `mismatch` | Der deklarierte Fingerabdruck gehört zu anderen Bytes |
| `multiple` | Die Belege deklarieren mehr als einen Fingerabdruck |
| `none` | Nichts wurde deklariert, also nichts zu vergleichen |

**Der Fingerabdruck steht neben dem Gitter, nicht darin.** Zwei Gründe:

Die beiden beantworten verschiedene Fragen. Das Gitter sagt, *in welchem Zustand
dieser Record ist*. Der Fingerabdruck sagt, *ob der Inhalt der Inhalt ist, der er
zu sein behauptet*. Und sie haben verschiedene Haltbarkeitsdauern: Der Status
ändert sich, wenn neue Belege eintreffen — aus CLAIMED kann später VERIFIED
werden. Der Fingerabdruck ist einfach; er wurde über Bytes gerechnet und ist in
hundert Jahren dieselbe Tatsache.

Der praktische Nutzen ist der Fall, den das Gitter allein verschluckt:

```
Status:        CLAIMED      Signatur nicht bestätigt
Fingerabdruck: mismatch     die Bytes sind andere
```

Ein System, das nur den Status zeigt, verbirgt hier den wichtigsten Befund.
Eines, das den Fingerabdruck daneben stellt, zeigt ihn — **ohne den Status zu
verbiegen**. Der Fingerabdruck kann einen Status nie anheben.

---

## Ableitungen: MODIFIED auflösbar machen

Ein gescanntes Kartenbild ist nicht das Foto. Zwischen Aufnahme und Anzeige
liegen Geraderücken, Zuschnitt, Farbkorrektur, Skalierung. **Die meisten Records
in der echten Welt sind so** — das Geprüfte ist ein bearbeitetes Derivat von
etwas, das signiert war.

Ein naiver Prüfer liest das als Problem und zeigt MODIFIED. Das ist über die
Bytes wahr und als Antwort nutzlos: Es beschreibt eine Bearbeitung, als wäre es
eine Manipulation.

Der Record löst das mit einem Feld am Subjekt:

```json
"subject": {
  "kind": "card",
  "id": "card:pokemon:base-set:4/102",
  "derived_from": ["<sha256 der Kamera-Aufnahme>"]
}
```

Ein Ableitungs-Record verlinkt den aktuellen Hash zurück zur signierten Quelle.
Der Verifier löst den Verweis **gegen seine eigenen Records** auf. Daraus folgt
die Regel, die alles trägt:

> **Eine Ableitung bewegt nur `integrity`, niemals `origin`.**
> Man kann keine Herkunft erben, die man nicht beweisen kann.

Ein fremdes Bild, das einfach dieselbe Abstammung *behauptet*, erbt nichts:
`origin` bleibt `none`, der Status bleibt UNKNOWN. Und ein Edit ohne auflösbaren
Verweis bleibt `modified` **ohne** `resolvable`-Markierung — die Unterscheidung
zwischen „abgeleitet" und „angefasst" ist damit sichtbar statt geraten.

---

## Signaturen: die Grenze, die man nicht überschreiten kann

Volle C2PA-Validierung heißt: CBOR/COSE-Struktur parsen, X.509-Kette zu einem
Trust Anchor bauen, Revocation prüfen (CRL/OCSP über Netz), RFC-3161-Zeitstempel
verifizieren. **Das braucht ein Netzwerk und eine Vertrauensliste.** Wer behauptet,
das offline zu tun, lügt.

Die Arbeit ist deshalb entlang einer Linie geteilt, die sich ehrlich ziehen lässt:

| VERIFIER (braucht Netz) | POLICY (braucht nichts) |
|---|---|
| Kette zu einem Trust Anchor bauen | Ist der Anchor einer, dem WIR trauen? |
| Revocation prüfen (CRL / OCSP) | Ist der Chain-Zustand für uns akzeptabel? |
| RFC-3161-Zeitstempel verifizieren | Behandeln wir „unbekannt" als Fehler? |
| Kryptografische Signatur prüfen | Wieviel Uhr-Abweichung erlauben wir? |

Der Verifier ist eine **injizierte Schnittstelle**, keine fehlende Funktion. Die
Policy-Schicht ist vollständig gebaut und geprüft.

**Die Regel, die alles trägt:** Ein fehlgeschlagener *oder* unbestimmter Check
erzeugt **nie** `verified`. Unbestimmtes Verhalten schlägt geschlossen fehl — eine
unauflösbare Kette, ein abgelaufenes Zertifikat und ein Verifier, der schlicht
eine Exception wirft, landen bei höchstens `claimed`.

**`unknown` und `invalid` sind verschiedene Aussagen.** Sie zu verschmelzen würde
aus „wir konnten nicht prüfen" ein „wir haben geprüft, es ist gefälscht" machen.
Eine strikte Policy *darf* `unknown` als Fehler behandeln — aber der Grund benennt
dann die Policy, statt die Signatur für gefälscht zu erklären.

Die Trust-Liste steht **nicht im Record**: Welchem Aussteller ein Prüfer traut,
ist seine Entscheidung. Ein Record, der sagt „signiert von X", ist eine Tatsache.
Ein Record, der sagt „X ist vertrauenswürdig", wäre eine Meinung.

---

## Der Zeitstempel: zwei Schritte, die man nicht verschmelzen darf

Ein RFC-3161-Zeitstempel sieht wie ein Ergebnis aus und ist zwei Dinge:

```
1. STATUS      Die Autorität hat "granted" geantwortet.          <- lesen
2. TSA-PROOF   Die CMS-Signatur des Tokens hält gegen den
               TSA-Schlüssel, über Attribute, die die TSTInfo
               decken, deren messageImprint die Signaturbytes
               deckt, die man bekommen hat.                     <- nachrechnen
```

Schritt 1 allein ist eine **Behauptung eines Dritten**. Erst Schritt 2 ist ein
**Nachweis**. Ein System, das beide verschmilzt, berichtet am Ende „Zeitstempel
gültig", weil ein entferntes System das Wort „granted" gesagt hat — und das ist
eine Aussage über den Aussteller, nicht über den Inhalt.

`c2pa-tsr.js` trennt sie und prüft in dieser Reihenfolge:

| Prüfung | Scheitert bei |
|---|---|
| `status` | Antwort ohne `granted` |
| `token` | `granted` ohne Token |
| `imprint` | Imprint deckt nicht die Signaturbytes |
| `contentdigest` | signiertes message-digest passt nicht zur TSTInfo |
| `tsa-key` | kein TSA-Schlüssel, also nichts geprüft |
| `cms-signature` | Signatur hält nicht über die signierten Attribute |
| `verified` | **nur** wenn alles oben gehalten hat |

**Der Transport lügt nicht über seinen Zustand.** Ohne injizierten Nachweis gibt
`verifyTimestamp` weiterhin `trusted: false` zurück — jetzt aber mit
`step: "tsa-signature"` und dem Grund, dass kein `verifyToken` verdrahtet war.
Ein Aufrufer mit TSA-Schlüssel bekommt über `createVerifiedTransport` den echten
Nachweis.

Die interessante Detailkante, die jede Implementierung beim ersten Versuch
falsch macht: signierte Attribute werden in ihrer **IMPLICIT `[0]`**-Form
signiert, aber in ihrer expliziten **SET OF**-Form verifiziert. Nur das Tag-Byte
unterscheidet sich — und wer es nicht umsetzt, dessen CMS-Prüfung scheitert an
einem völlig gültigen Token.

---

## Der Record

```json
{
  "spec_version": "TRUST-Record/0.2",
  "subject":     { "kind": "url", "id": "https://example.org/gallery/hero-77" },
  "origin":      "verified",
  "integrity":   "intact",
  "authenticated": true,
  "generation":  "attested_by_signer",
  "fingerprint": { "result": "match", "detail": "..." },
  "content_hash": "0f2a...",
  "evidence": [
    { "kind": "attestation", "label": "C2PA manifest", "state": "valid",
      "chain": "intact", "generation": { "kind": "trainedAlgorithmicMedia" } }
  ],
  "issuer": "did:web:example.org",
  "checked_at": "2026-10-08T12:00:00Z"
}
```

Die Feldentscheidungen, die den Standard ausmachen:

| Feld | Warum so |
|---|---|
| `verdict` | **fehlt absichtlich.** Ein gespeichertes Urteil veraltet mit dem Zeitpunkt seiner Entstehung. |
| `evidence` | ist eine **Liste**. Mehrere, auch widersprechende Belege bleiben stehen. Ein Prüfer darf den unbequemen nicht wegwerfen. |
| `issuer` | ist ein **Verweis**, kein Wert. Der Prüfer löst ihn gegen eine Quelle seiner Wahl auf. |
| `generation` | steht bei den Beobachtungen, **nicht** im Gitter. Sie kann den Status nie bewegen. |
| `fingerprint` | steht **neben** dem Gitter. Er meldet, ob der Inhalt der ist, der er zu sein behauptet — und hebt nie einen Status an. |
| `subject.derived_from` | ist eine **Erklärung, kein Beweis**. Der Verifier löst sie gegen eigene Records auf; sie bewegt `integrity`, nie `origin`. |

---

## Die Grenze

```
Provenance -> Identity -> Evidence -> Trust -> Decision
```

Die Kette ist nicht als Prozessschrittfolge zu lesen, sondern als Auftrennung
in **Beobachtung** und **Bewertung**.

| Glied | Charakter | Im Standard? |
|---|---|---|
| Provenance | Beobachtung | ja, als Beleg |
| Identity | Beobachtung | ja, als Verweis |
| Evidence | Beobachtung | ja, als Liste |
| Verification | Beobachtung | ja, als Policy des Prüfers |
| Timestamp proof | Beobachtung | ja, als zweiter Zertifizierungsschritt |
| Fingerprint | Beobachtung | ja, neben dem Gitter |
| Generation claim | Behauptung | ja, getrennt geführt |
| Derivation | Erklärung | ja, verifier-aufgelöst |
| **Trust** | Bewertung | **nein** — Funktion des Prüfers |
| **Decision** | Bewertung | **nein** — außerhalb |

Diese Linie ist die wichtigste des ganzen Entwurfs. Wird Trust zentral
beantwortet, ist der Rest eine Anwendung mit offener Schnittstelle. Dann ist
Stufe 7 tot, egal wie offen die Spezifikation aussieht.

---

## Was läuft

Der Prototyp ist gebaut und geprüft. Die Zahlen unten sind **gemessen, nicht
geschätzt** — und wo eine Zahl fehlt, steht sie als offen und nicht als rund.

```
conformance.mjs            passed 14/14
derivation.test.mjs        passed 16/16
signature.test.mjs         passed 18/18
fingerprint.test.mjs       passed 20/20
c2pa-transport.test.mjs    passed 37/37   (Repo-Fassung, @0.2)
c2pa-tsr.test.mjs          passed 33/33
```

**Zwei Suiten sind im Arbeitsbereich weiter als im Repository.** Die Suite des
Arbeitsbereichs prüft den Transport auf `@0.3` und deckt zusätzlich die
Weitergabe an einen injizierten Verifier ab. Sie meldete im letzten Lauf
**37 grün von 48** — die elf neuen Assertions sind noch nicht einzeln bestätigt,
weil der Lauf abgeschnitten wurde. Diese Zeile bleibt stehen, bis sie gemessen
sind; sie wird nicht auf 48/48 gerundet.

```
vector              verdict        origin     integrity  generation
verified            VERIFIED       verified   intact     none
authenticated       AUTHENTICATED  verified   intact     none
machine-signed      VERIFIED       verified   intact     attested_by_signer
captured-signed     VERIFIED       verified   intact     attested_by_signer
machine-rumour      CLAIMED        claimed    intact     asserted
detector-claim      CLAIMED        claimed    intact     asserted
claim-plus-signer   VERIFIED       verified   intact     asserted
assertion-only      CLAIMED        claimed    intact     none
modified            MODIFIED       verified   modified   none
machine-modified    MODIFIED       verified   modified   attested_by_signer
contradiction       INVALID        verified   broken     none
invalid-signature   INVALID        claimed    broken     none
expired-chain       INVALID        claimed    broken     none
unknown             UNKNOWN        none       intact     none

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
inv  the grid is unchanged: nine mappings              holds
inv  the fingerprint is reported when the status hides it holds
inv  the fingerprint never lifts a status              holds
inv  a root off the trust list is never accepted       holds
inv  a CRL match is by value, not by position          holds
inv  no http function means no revocation was checked  holds
inv  a timestamp is never trusted without a TSA proof  holds
inv  every refusal names the step that blocked          holds
```

Die zwei Zeilen, die zusammen gelesen werden müssen: `claim-plus-signer` und
`detector-claim` tragen **dieselbe Behauptung** und kommen auf verschiedene
Verdikte. Die Behauptung selbst bewegt nichts.

| Datei | Zweck |
|---|---|
| `engine.js` | Record-Ableitung aus geprüften Fakten |
| `derivation.js` | Ableitungs-Pipeline mit Herkunftskette |
| `signature.js` | Signatur-Policy und Verifier-Schnittstelle |
| `verifier-bridge.js` | Brücke: Verifier-Antwort → Record-Evidence |
| `fingerprint.js` | Fingerabdruck-Prüfung und Ableitungs-Verweis |
| `c2pa-verifier.js` | Manifest-, Signatur- und Erzeugungsschicht über Bytes |
| `c2pa-providers.js` | Signatur-, Ketten- und Zeitstempel-Provider |
| `c2pa-transport.js` | Netz-Schicht: Kette, CRL-Wertsuche, Zeitstempel |
| `c2pa-tsr.js` | **Zweiter Zertifizierungsschritt: TSA-Signaturnachweis** |
| `demo-verifier.js` | Demo-Verifier und die vier Policies |
| `index.html` | Bedienbare Demo — Datei wird lokal gehasht, verlässt den Browser nicht |
| `conformance.mjs` | Konformitätsliste, in sich geschlossen |
| `derivation.test.mjs` | Ableitungs-Suite: Scan-Szenario, Ende zu Ende |
| `signature.test.mjs` | Signatur-Policy-Suite: fail closed |
| `fingerprint.test.mjs` | Fingerabdruck-Suite: Gitter unverändert |
| `c2pa-transport.test.mjs` | Transport-Suite: Kette, CRL, Zeitstempel-Status |
| `c2pa-tsr.test.mjs` | TSR-Suite: der zweite Zertifizierungsschritt |
| `record-0.2.schema.json` | JSON Schema 2020-12 |
| `vectors.js` | Testvektoren, einer pro Status |

---

## Was fehlt

Ehrlich, weil diese Liste im Gespräch als Erstes geprüft wird.

- **Ein Durchlauf gegen einen echten Dienst.** Alle Bausteine sind gebaut und
  geprüft, aber jede Prüfung arbeitet bisher mit selbstgebauten Bytes: kein
  echtes Zertifikat, kein echter Zeitstempel, keine reale CRL.
- **Ein echtes Netz-I/O.** Die `http`-Funktion wird von außen übergeben. Der
  Bauabschnitt ist eine `fetch`-Implementierung mit Rate-Limit und Frist, kein
  Algorithmus.
- **CRL-Signaturprüfung und Zertifikatssignaturprüfung.** Die Kettenordnung und
  die Wertsuche in der CRL laufen; die Signatur über die CRL selbst nicht, und
  die Signaturprüfung über die Zertifikate ebenfalls nicht.
- **Zwei interoperable Implementierungen.** Ein Standard mit einer Umsetzung ist
  eine Beschreibung. Stufe 7 braucht eine zweite, die aus denselben Bytes
  denselben Record erzeugt.
- **Derivation über Record-Grenzen.** Heute löst ein Verifier gegen seinen
  eigenen Store auf. Für plattformübergreifende Ketten braucht es eine
  Abfrage-Semantik, nicht nur einen Map-Zugriff.
- **API und Browser-Integration** (Stufen 5 und 4) existieren als Roadmap, nicht
  als Code.
- **Kein Patent auf das Datenformat.** Das ist eine Entscheidung, keine Lücke:
  Ein Patent auf den Record tötet Stufe 7.

---

## Die Entwicklungsstufen

Die Stufen erweitern die **Subjekte** — die Dinge, die geprüft werden können —
bei konstantem Record-Format.

| Stufe | Gegenstand | Was hinzukommt |
|---|---|---|
| 1 | Datei | Manifest und Hash |
| 2 | URL | Adresse als Subjekt |
| 3 | Webseite | Prüfung im Kontext |
| 3 | Karte | Scan-Szenario mit `derived_from` |
| 4 | Browser | Status im Vertrauensanzeiger |
| 5 | API | Fremdsysteme reichen Records ein |
| 6 | Selbstauskunft | Seiten weisen ihre Herkunft selbst aus |
| 7 | Standard | mehrere unabhängige Umsetzungen |

---

## Lizenz

Apache-2.0. Kein Wahrheitsurteil, keine Signaturpflicht, keine
Zertifizierungsstelle.

**Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.**
