# TRUST:// — Produkt‑Poster (One‑Pager)

Kurz: Offener Standard für nachweisbare Herkunft digitaler Inhalte — verifizierbar, interoperabel, auditierbar.

Problem
- Niemand kann plattformübergreifend beweisen, woher Inhalte stammen und ob sie unverändert sind.
- Heutige Ansätze mischen Beobachtung und Bewertung und sind schwer interoperabel.

Lösung
- Ein schlankes Record‑Format (TRUST‑Record/0.2), das Herkunft (origin), Integrität (integrity) und Erzeugungsbehauptung (generation) getrennt abbildet.
- Fingerabdruckprüfung neben dem Status (match/mismatch) — hebt nie einen Status an, macht aber sichtbare Fakten.
- Klare Trennung: Verifier (Netzwerkabhängig) vs Policy (lokal, deterministisch).

Kernfunktionen (MVP)
- Record‑Ableitung aus Belegen (engine.js)
- Signature‑Policy und Verifier‑Bridge (signature.js, verifier-bridge.js)
- Fingerabdruckprüfung und derived_from‑Ableitung (fingerprint.js, derivation.js)
- JSON‑Schema + Testvektoren (record-0.2.schema.json, vectors.js)
- Demo/Integrationstest + Browser‑Demo (index.html, conformance.mjs)

Zielgruppen
- Entwickler und Plattformen (APIs, Verifier‑Integrationen)
- Medienorganisationen, Archive, Plattform‑Integratoren
- Forscher/Standards‑Communities (Interoperabilitätstests)

Erfolgsmetriken (90 Tage)
- Erstes echtes Netz‑Verifizierungs‑Durchlauf mit TSA/CRL: 1
- Konformes Record erzeugt & geprüft: 100+ Testvektoren
- Zwei unabhängige Implementierungen (Idee/Kandidat vorhanden)
- Dokumentation + Demo einsatzbereit

Roadmap (Kurz)
- Woche 0–2: Netzwerk‑I/O (fetch), CRL/TSA‑Pipelines
- Woche 3–6: Integration mit echtem Zertifikat + Timestamp Service
- Woche 6–12: Interop‑Test mit zweiter Implementierung, Release

Call to Action / Ask
- Review & Feedback aus Community
- Ein Integrationstest mit einem realen TSA/CRL‑Service
- Mitwirkende für Interop‑Implementierung

Lizenz: Apache‑2.0

Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.
