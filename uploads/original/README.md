# TRUST Protocol – Railway-Startpaket

Dies ist ein statischer Prototyp der Benutzeroberfläche. Er enthält **keinen funktionierenden Node.js-Server, keine C2PA-Prüfung und keine KI-Erkennung**.

## Railway

1. In Railway: **New Project → Deploy from GitHub Repo**
2. GitHub-Konto verbinden und dieses Repository auswählen.
3. Branch `main` auswählen und **Deploy Now** klicken.
4. Danach: **Service → Settings → Networking → Generate Domain**.

Railway erkennt das vorhandene `Dockerfile` automatisch. Die Anwendung hört auf dem von Railway zugewiesenen Port (`$PORT`).

## Lokal testen

```sh
docker build -t trust-protocol .
docker run --rm -p 3000:3000 trust-protocol
```

Öffne anschließend http://localhost:3000

## Grenzen

- Keine echte C2PA-Verifikation
- Keine KI-Erkennung
- Keine Benutzerauthentifizierung
- Keine dauerhafte Speicherung
- Nur Demonstrationsoberfläche
