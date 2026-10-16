# MVP-Plan für TRUST://

## 1. Ziel

TRUST:// soll als offener Standard und Referenzimplementierung die nachweisbare Herkunft digitaler Inhalte zwischen Systemen, Plattformen und Anwendungen standardisieren. Das Produkt soll es ermöglichen, Herkunft, Integrität und Behauptung eindeutig zu trennen und interoperabel auszutauschen.

## 2. Produktziel

Ziel des MVP ist nicht, „Vertrauen“ zu erzeugen, sondern verifizierbare Tatsachen über Inhalte bereitstellen:
- Woher kommt ein Inhalt?
- Ist er unverändert geblieben?
- Wer behauptet Herkunft oder Erzeugung?
- Welche Behauptungen sind signiert und welche nur behauptet?

## 3. Nutzer und Nutzungsszenarien

### Hauptnutzer
- Plattformen und Content-Integratoren
- Medien- und Archiv-Organisationen
- Sicherheits- und Verifizierungs-Teams
- Entwickler von Browser- und Web-Integrationen

### Verwendung
- Ein Erlebnis oder System prüft einen digitalen Inhalt gegen ein Manifest oder einen Record.
- Der Record zeigt Herkunft, Status und Fingerabdruck an.
- Plattformen können den Zustand lokal interpretieren, ohne selbst „Wahrheit“ zu definieren.

## 4. Kernfunktionen des MVP

### 4.1 Record-Erzeugung
- Der Record wird aus geprüften Fakten abgeleitet.
- Zustände werden aus origin, integrity und generation kalkuliert.
- Das Gitter bleibt stabil und dokumentiert.

### 4.2 Verifizierung
- Signaturprüfung und Policy-Entscheidung sind getrennt.
- Fehlgeschlagene oder unklare Prüfungen erzeugen keinen verified-Status.
- `unknown` und `invalid` bleiben deutlich unterschieden.

### 4.3 Fingerabdruckprüfung
- Der Fingerabdruck wird als separate Eigenschaft des Inhalts behandelt.
- mismatch wird sichtbar gemeldet, ohne den Status künstlich zu heben.

### 4.4 Ableitung (Derivation)
- Ein bearbeiteter Inhalt kann als Ableitung von einer signierten Quelle behandelt werden.
- Derivation beeinflusst nur integrity, nie origin.

### 4.5 Browser-/Demo-Integration
- Ein demonstrierbares Frontend zeigtStatus, Signatur und Fingerabdruck an.
- Die Demo kann lokal ausgeliefert werden und ist ein Testkanal für Nutzerfeedback.

## 5. Nicht im MVP

- Vollständig interoperable zweite Implementierung
- Reale TSA-/CRL-Laufzeit gegen produktive Services
- Vollständige Plattform-API für externe Integratoren
- Multi-Backend-Integration mit vollständiger Record-Verteilung

## 6. Produkt-Phasen

### Phase 1: Nachweis und Spezifikation
- Abschluss von Record-Format und Invarianten
- Stabilisierung der Statuslogik und Testsuiten
- Dokumentation der drei Achsen: origin, integrity, generation

### Phase 2: Referenzimplementierung
- Abschluss der Verifier- und Policy-Schicht
- Verankerung der Fingerabdrucklogik
- Testdeckung für Ableitung, Signatur und Nutzungsszenarien

### Phase 3: Demo und Validierung
- Browser-Demo, lokal nutzbar
- erste reale externe Verifizierungs- und Timestamp-Tests
- Bewertung der UX und Verständlichkeit durch Nutzer

### Phase 4: Standardisierung und Interop
- zweite Implementierung
- Cross-Implementation-Tests
- sichtbare Release-Qualität als öffentlicher Standard

## 7. Erfolgsmetriken

- 100+ Validierungsszenarien oder Testvektoren durchlaufen
- eine lauffähige Browser-Demo
- mindestens ein vollständiger realer Verifier-/Timestamp-Lauf
- eindeutige, verständliche Statusausgabe im Frontend
- erste Interop-Tests zwischen zwei Implementierungen

## 8. Akronym/Produkt-Value-Proposition

TRUST:// bietet einen harten, prüfbaren Standard für Herkunft in einer Welt, in der Inhalte schnell verbreitet, verändert und umdeutet werden. Es schafft keine „Wahrheit“ als Dogma, sondern eine transparente, nachvollziehbare Matrix aus Tatsachen, Behauptungen und Prüfungsresultaten.

## 9. Akzeptanzkriterien

Ein MVP gilt als erfolgreich, wenn:
- ein Content-Record aus validen Belegen ableitbar ist,
- Status und Fingerabdruck sauber getrennt dargestellt werden,
- Ableitungen korrekt als modified/derived behandelt werden,
- fehlgeschlagene Prüfungen nicht als verified gemeldet werden,
- die Demo für technisch versierte Nutzer nachvollziehbar ist.

## 10. nächsten Schritte

1. reale TSA-/CRL-Integration
2. Interop mit zweiter Implementierung
3. Browser- und API-Produktionsreife
4. Standardisierung und Community-Review

Herkunft wird dauerhaft nachprüfbar, nicht dauerhaft wahr.
