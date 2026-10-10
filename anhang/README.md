# Anhang — Nicht-Myra-Bestand aus der Sitzung vom 10. Oktober 2026

Dieser Ordner sammelt, was zur TRUST://-Arbeit gehört, aber nicht Teil des
Standards selbst ist. Der Myra-Kontenexport liegt hier bewusst **nicht** — er
enthält Adress- und Gerätedaten einer dritten Person und gehört nicht in ein
öffentliches Repository.

## Inhalt

| Datei | Herkunft | Bezug zu TRUST:// |
|---|---|---|
| `hashbinding-package.json` | eigenes Testprojekt `trust-c2pa-hashbinding-fix` | Kandidat für die zweite Implementierung: JUMBF-Regression, detachtes COSE, Signatur-Provider, Binding |
| `karten-app-README.md` | Grade-Check Vault (Karten-Scanner) | Anwendungsfall für `subject.derived_from`: Kamera-Aufnahme als belegbare Quelle |
| `index-neu.html` | neuere Fassung der Karten-App (121 KB) | enthält `sha256`, `crypto.subtle`, Manifest-Bezug |
| `index-alt.html` | frühere Fassung der Karten-App (41 KB) | Preis- und Binder-Ansicht, ohne Krypto-Bezug |
| `binder-scan.md` | Anzeigetext des Scan-Bereichs | Oberflächentext, kein Code |

## Schlüsselsätze aus der Karten-App (neuere Fassung)

```
sha256 / crypto.subtle:
  async function sha256(str){
  const buf=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(str))
  crypto.subtle.importKey / generateKey (AES-GCM) für den lokalen Vault

manifest:
  <link rel="manifest" href="manifest.webmanifest">

origin:
  let serverUrl = store.get('gcv_server') || window.location.origin

Capture:
  <input id="ai-cam" type="file" accept="image/*" capture="environment" hidden onchange="scanFile(...)">

Grading:
  Grading-Rechner (PSA) · ROI-Panel
```

## Unterschied der beiden HTML-Fassungen

| | neuere (`index-neu.html`) | frühere (`index-alt.html`) |
|---|---|---|
| Umfang | 121 KB | 41 KB |
| `sha256` | ja | nein |
| `crypto.subtle` | ja | nein |
| Manifest-Bezug | ja | nein |
| Preisquellen | TCGdex, Scryfall, YGOPRODeck | dieselben |
| Grading-ROI | ja, eigener Rechner | nur Ansicht |

Die neuere Fassung ist die, die an TRUST:// andockt.

## Was nicht in diesem Ordner liegt

- `myra-ai-datenexport-2026-10-09.json` — Kontenexport mit 68 Requests,
  Kostentafel (2,9739 USD über drei Modelle, 1.303.974 Input- und 144.145
  Output-Tokens), Protokolladressen und Gerätedaten. Nicht Teil dieses
  Repositories.
- `6ac860238dac8faa97cf7706-saaaay.json` — Trace einer Unterhaltung mit vier
  fehlgeschlagenen Runden (Status 402, kein Guthaben). Kein Inhalt.

---

**Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.**
