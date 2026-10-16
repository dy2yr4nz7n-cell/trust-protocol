# DECISION: Local App Integrations are optional

Status: Accepted
Date: 2026-10-16
Decision ID: DECISION-local-apps

## Kontext

TRUST:// ist ein offener Standard und eine Referenzimplementierung für nachweisbare Herkunft digitaler Inhalte. Der Kern des Projekts ist die Spezifikation des Record‑Formats, die Trennung von Herkunft (origin), Integrität (integrity) und Erzeugungsbehauptung (generation), sowie die Regeln zur Ableitung eines Records aus geprüften Fakten und Belegen.

Es existiert ein TypeScript‑Modul (LOCAL_APPS), das lokale Laufzeit‑Integrationen (llama.cpp, vLLM, LocalAI, Ollama, Docker Model Runner u. a.) sowie Snippets und Deeplinks für Developer‑Workflows erzeugt. Solche Integrationen sind nützlich für Demos, lokale Tests und Developer Experience, tangieren aber nicht die semantische Definition des Standards.

## Entscheidung

Lokale App‑Integrationen werden als optionales, developer‑orientiertes Layer behandelt und nicht als Teil des TRUST:// Kerns oder als Voraussetzung für Konformität:

- Sie dürfen im Repository gehalten werden, jedoch in einem klar getrennten Bereich (z. B. `tools/`, `examples/` oder `docs/`), getrennt von der Spezifikation und Referenzimplementierung der Verifikationslogik.
- Sie sind ausdrücklich „Developer Experience“-Artefakte: Zweck ist Onboarding, Demo, lokale Verifikation und Interop‑Experimentation.
- Die Existenz solcher Integrationen ist kein Kriterium für die Konformität mit dem TRUST‑Record‑Format.

## Begründung

- Der primäre Wert des Projekts liegt in verifizierbaren Tatsachen (Provenance, Integrity, Evidence). Runtime‑Integrationen sind Hilfsmittel, keine semantische Ergänzung des Standards.
- Die Trennung reduziert Risiko: Plattform‑/OS‑spezifische Befehle und Snippets würden die Spezifikation unnötig verkomplizieren und zusätzlichen Wartungsaufwand erzeugen.
- Gleichzeitig erhöhen lokal auszuführende Demos die Adoptions‑ und Testrate: Entwickler können schneller prüfen, reproduzieren und interagieren.

## Konsequenzen

Positive
- Besseres Onboarding und leichtere lokale Reproduzierbarkeit.
- Mehr und einfachere Interop‑Tests.

Negative
- Zusätzlicher Pflegeaufwand für Snippets, Deeplinks und OS‑spezifische Anleitungen.
- Potenziell unsichere Beispielbefehle, wenn sie nicht korrekt dokumentiert werden.

Minderungsmaßnahmen
- Die lokale App‑Schicht wird als optional und community‑getrieben markiert.
- Sicherheits‑Hinweise werden verpflichtend in die zugehörige Dokumentation aufgenommen (keine Secrets in Beispielen, Platzhalter für Tokens, Hinweise zu Risiken beim Ausführen von Dritt‑Installationsskripten).
- Unit‑Tests für Parselogik (z. B. Quant‑Tag‑Erkennung) und CI‑Checks für statische Integrität (keine Downloads in CI) werden empfohlen.

## Kompatibilität

Diese Entscheidung ändert nichts an den semantischen Definitionen von origin, integrity oder generation und ist vollständig kompatibel mit dem existierenden Repository‑Inhalt und der Roadmap. Sie erweitert die Nutzbarkeit (Developer UX), ohne die Spezifikation zu verwässern.

## Empfehlung zur Ablage und Sichtbarkeit

- Ablage: `tools/local-apps/` oder `examples/local-apps/` mit `README.md` und `LOCAL_APPS.md` (Dokumentation). In diesem Repository wurde bereits `LOCAL_APPS.md` hinzugefügt.
- Sichtbarkeit: Ein Link im Haupt‑README auf die Decision‑Datei und auf die Local‑Apps‑Dokumentation.
- Verantwortung: Markiere diese Artefakte als community‑gewartet / optional und nicht als Release‑Blocker für Spec‑Releases.

---

Autoren: Repository‑Maintainer
