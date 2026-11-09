# STATUS — gemessener Stand, 9. November 2026

Diese Datei ersetzt abweichende Zahlen in `TRUST.md` und `README.md`.

## Umgesetzt am 9. November 2026

### 1. C2PA-Hash-Exclusions — Commit `d6884d3`

`c2pa-verifier.js` liest jetzt `exclusions` aus dem dekodierten Claim,
normalisiert überlappende oder angrenzende Bereiche und hasht nur die
verbleibenden Asset-Bytes.

- `collectExclusionRanges`, `mergeRanges`, `subtractRanges` und `concatSlices`
  wurden ergänzt.
- Ein explizit übergebener `assetRange` bleibt unterstützt.
- Wenn Exclusions vorhanden sind, aber den gesamten Asset-Bereich entfernen,
  ist das Ergebnis `unknown`, nicht `mismatch`.
- APP11/JUMBF wird ausschließlich über deklarierte Exclusion-Bereiche
  ausgeschlossen; es gibt keine implizite Whole-Container-Ausnahme.

**Grenze:** Die Implementierung ist gegen die im Repository vorhandenen Tests
und synthetische Strukturen gerichtet. Ein Abgleich mit einem echten,
in der Praxis erzeugten C2PA-Asset steht noch aus.

### 2. Assertion-Bindings — Commit `e3d095c`

`engine.js` unterstützt jetzt eine optionale SHA-256-Bindung für
`assertion`-Evidence.

- `canonicalAssertionPayload` kanonisiert `id`, `label`, `source`,
  `issued_at` und `data`.
- `verifyAssertionBinding` prüft den deklarierten Digest.
- `check()` berechnet die Bindung vor der Record-Ableitung und übergibt das
  Ergebnis an `deriveRecord`.
- Der Record führt `binding.algorithm`, `binding.digest` und
  `binding.verified`.

**Wichtig:** Eine verifizierte Assertion-Bindung beweist nur, dass der
Assertion-Payload unverändert ist. Sie macht die Assertion nicht zu einer
Attestation und beweist weder Autor noch Wahrheit der Behauptung.

### 3. TSR-Algorithmen — Commit `4ee0b7c`

`c2pa-tsr.js` behandelt `rsaEncryption`
(`1.2.840.113549.1.1.1`) jetzt explizit:

- Es ist ein Schlüssel- und kein Signaturalgorithmus.
- Ein Token mit dieser OID endet bei `step: "algorithm"` und wird nicht als
  vertrauenswürdig behandelt.
- ECDSA-TSA-Schlüssel werden für P-256, P-384 und P-521 importiert.
- Alle anderen nicht unterstützten Algorithmen bleiben fail-closed.

**Grenze:** Die Unterstützung wurde nicht gegen einen echten RFC-3161-Dienst
oder echte TSA-Zertifikate validiert.

### 4. CRL-Signaturprüfung — Commit `83d01c5`

`c2pa-transport.js` verifiziert jetzt die Signatur einer CRL gegen den
öffentlich konfigurierten Issuer-Schlüssel.

- `verifyCrlSignature` prüft `tbsCertList`, Signaturalgorithmus und
  Signaturwert.
- `createTransport` akzeptiert `crlIssuerCertificates` als Map von
  Issuer-Hex zu Issuer-Zertifikat.
- `revocationStatus` meldet `signatureVerified`.
- Eine CRL ohne verifizierbare Signatur kann Revocation nicht begründen.

**Grenze:** CRL-Distribution-Points werden weiterhin nur über die konfigurierte
`crlUrls`-Map gefunden. Name-, Policy- und Path-Length-Constraints bleiben
unimplementiert.

## Weiterhin offen

- Die drei auf Import umgestellten Suiten (`c2pa-tsr`, `c2pa-providers`,
  `c2pa-transport`) müssen nach diesen Änderungen erneut ausgeführt werden.
- `c2pa-integration.test.mjs` muss nach jedem Commit ausgeführt werden.
- Es fehlt weiterhin ein Abgleich gegen echte C2PA-Dateien, echte
  Zeitstempel, echte Zertifikate und reale CRLs.
- Die Assertion-Bindung ist Integrität, keine Signatur: Sie ersetzt keine
  kryptografische Herkunftsattestation.
- Prüfpack- und Space-Archive können noch ältere Fassungen enthalten.
- Eine zweite unabhängige Implementierung bleibt erforderlich, um die
  Interoperabilität des Protokolls zu belegen.

## Herkunft der Dateien

An diesem Repository haben mehrere Systeme geschrieben. Für einen Standard
mit dem Gegenstand „nachweisbare Herkunft“ bleibt die lückenlose Zuordnung
jeder Zeile zu ihrem Ursprung eine offene Schwäche.

Empfehlung:

1. ein schreibender Beitragender je Datei,
2. `node c2pa-integration.test.mjs` nach jedem Commit,
3. lesende Systeme dürfen prüfen und vorschlagen, nicht schreiben.
