# TRUST: Projektstände und Repository-Konsolidierung

Das aktive Hauptprojekt bleibt dieses Repository auf `main`. Am 9. November 2026
wurden zusätzliche öffentliche Entwicklungsstände desselben Projekts hier
zusammengefasst. Unterschiedliche Implementierungen wurden nicht blind gemischt.

| Bisheriger Repository-Name | Erhaltener Stand |
|---|---|
| `Trust` | [Unified-Gerüst und eigene Historie](https://github.com/dy2yr4nz7n-cell/trust-protocol/tree/archive/Trust/main) |
| `trust-protocol-unified` | [Unified-Projektplanung](https://github.com/dy2yr4nz7n-cell/trust-protocol/tree/archive/trust-protocol-unified/main) |
| `jouiiifjf` | [CRL-/OCSP-Referenzimplementierung](https://github.com/dy2yr4nz7n-cell/trust-protocol/tree/archive/jouiiifjf/main) |
| X.509-Reparatur-Snapshot | [Bereits integrierte Korrekturen und Tests](docs/X509-CONSOLIDATION.md) |

Die Archivbranches sind unveränderte historische Quellstände. Insbesondere ist
das CRL-/OCSP-Modul dadurch weder in die laufende Anwendung eingebaut noch als
produktionsreif bestätigt. Der zusätzliche Unified-PR-Stand liegt unter dem Tag
`archive/trust-protocol-unified/pull/1/head`.

Der eigenständige private Go-/mTLS-/WASM-Dienst bleibt separat. Python-Bindings,
Rust-SDK und PHP-Erweiterung bleiben ebenfalls eigenständige Bibliotheksprojekte.

Die Übertragung wurde durch exakten Vergleich aller übernommenen Git-Referenzen
geprüft. Issues, Kommentare und Repository-Metadaten wurden im privaten
Repository-Verwaltungsprojekt gesichert; Git-Historien zusätzlich als verifizierte
Bundles. Private Snapshot-Historien wurden nicht in dieses öffentliche Repository
übernommen.
