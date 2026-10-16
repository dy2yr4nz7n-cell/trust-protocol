# Optional: Lokale Apps und Run‑Local‑Integrationen

Dieses Dokument beschreibt eine optionale Erweiterung für das Projekt: ein kleines, produktnahes „Local Apps“-Layer, der Entwicklern Copy‑Paste‑Anleitungen für lokale Laufzeitumgebungen liefert.

Wichtig: Diese Funktion ist bewusst nicht Teil des Kern‑Standards von TRUST://. Sie ist ein optionales Developer-/Demo‑Tool und kein Pflichtbestandteil des Protokolls.

## Warum das sinnvoll ist

Ein Standard wie TRUST:// wird viel leichter angenommen, wenn die Entwickler:innen sofort sehen können:
- wie sie einen Verifier lokal ausführen,
- wie sie Testvektoren mit einer lokalen Runtime prüfen,
- wie sie Demos und Interop‑Tests ohne Spezialumgebung starten,
- wie sie die Produktidee in einer echten Umgebung demonstrieren.

Das reduziert die Einstiegshürde und macht das Projekt für Tests, Demos und Community‑Feedback deutlich zugänglicher.

## Was dieses Paket leisten kann

Es kann für lokale Laufzeiten wie z. B. folgende Integrationen bereitstellen:
- llama.cpp
- Ollama
- vLLM
- LocalAI
- Docker Model Runner
- SGLang
- MLX LM
- Lemonade
- weitere Laufzeitumgebungen nach Bedarf

Typischerweise würde es folgendes anbieten:
- Installationshinweise
- Startbefehle für lokale Server
- OpenAI‑kompatible Beispielaufrufe
- Deeplinks für Apps mit direktem OS‑Integration
- Modell‑spezifische Snippets mit Quant‑Tag‑Erkennung

## Warum das nicht im Kern des Produkts liegen sollte

Das Protokoll selbst sollte sich auf die tatsächlichen Fragen konzentrieren:
- Herkunft
- Integrität
- Erzeugungsbehauptung
- Nachweisbarkeit

Die lokale App‑Integration ist ein Komfort-/Produktwerkzeug. Sie gehört in den Bereich „Developer Experience“ und nicht in die logische Kernschicht der Trust‑Verifikation.

## Sicherheits-Hinweise

Da diese Laufzeitumgebungen häufig Befehle mit `curl`, Docker, HF‑Token oder Modellpfaden ausführen, gilt:
- keine geheimen Tokens fest in Beispielbefehlen einbauen
- alle sensiblen Werte als Umgebungsvariablen oder Platzhalter nutzen
- Docker‑ und Shell‑Kommandos als Beispieldurchlauf kennzeichnen
- auffällige Flags immer kommentieren

Empfohlener Stil:
- `HF_TOKEN=<secret>`
- `{{GGUF_FILE}}`
- `{{QUANT_TAG}}`

## Empfohlener Produktansatz

Die beste Einbindung ist als optionales, separates Modul:
- nicht im Kern des Protokolls
- nicht als Voraussetzung für Release oder Standardisierung
- sondern als Entwickler‑ / Demo‑Utility mit klarer Trennung von Spezifikation und Laufzeit

Praktisch heißt das:
- ein Ordner wie `tools/local-apps/` oder `examples/local-apps/`
- ein `README` mit Warnhinweisen und der Zweckbeschreibung
- kleine Test‑Suiten für Typen, Tag‑Erkennung und Snippet‑Erzeugung

## Einfache Produktlogik

Die Idee ist einfach:
- Ein Modell wird geprüft
- Die passende App wird für das Modell bestimmt
- Ein passender Start-/Run‑Snippet wird erzeugt

Dafür braucht es nur:
- Modellmetadaten
- eine kleine App‑Map
- ein Snippet‑Generator pro Laufzeitumgebung

Damit erhält man eine selbsterklärende UX ohne die Trust‑Logik zu vermischen.

## Fazit

Ja, das lohnt sich — aber nur als optionales, gut getrenntes Produktsegment.

Es bringt:
- bessere Onboarding‑Erfahrung
- schnellere Demos
- niedrigere Einstiegshürde bei Integratoren
- weniger Reibung bei Tests und Community‑Feedback

Es hat aber auch klare Grenzen:
- keine Kernfunktion des Standards
- Wartungsaufwand durch viele Laufzeitumgebungen
- Notwendigkeit klarer Sicherheits‑ und Pflege‑Regeln

Empfehlung: als optionales Developer-Tool einbauen, nicht als Teil der Standard‑Architektur.

---

Für die Produktseite: siehe auch
- [PRODUCT_POSTER.md](PRODUCT_POSTER.md)
- [MVP_PLAN.md](MVP_PLAN.md)
- [README.md](README.md)
