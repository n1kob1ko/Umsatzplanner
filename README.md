# Umsatzplanner

Einfacher Umsatz-, Lager- und Einkaufsplaner für Lokale. Läuft online mit einem Zugang pro Kunde.

- `public/index.html` ist die App. Ohne Server funktioniert dieselbe Datei auch offline (Daten im Browser, KI mit eigenem API-Schlüssel).
- `server.js` liefert die App aus, speichert die Daten pro Kunde (SQLite) und leitet KI-Anfragen mit dem Schlüssel des Betreibers an Claude weiter.
- `/admin` ist die Verwaltung: Kunden anlegen, Passwort neu setzen, Geräte abmelden, sperren, Daten herunterladen oder auf einen Tagesstand zurücksetzen.

## Einstellungen (Umgebungsvariablen)

| Variable | Bedeutung |
|---|---|
| `ADMIN_PASSWORD` | Passwort für `/admin` (Pflicht, lang und zufällig wählen) |
| `ANTHROPIC_API_KEY` | Schlüssel für die KI (Speisekarte/Rezepte auslesen). Ohne ihn ist die KI aus. |
| `DATA_DIR` | Ordner für die Datenbank. Standard `/data` (Railway-Volume), sonst `./data` |
| `MAX_GERAETE` | Geräte pro Kunde gleichzeitig, Standard 2 |
| `KI_LIMIT_TAG` | KI-Durchgänge pro Kunde und Tag, Standard 20 |

## Railway

Service aus diesem Repo (Dockerfile), Volume auf `/data` mounten, Domain erzeugen, `ADMIN_PASSWORD` und `ANTHROPIC_API_KEY` als Variablen setzen. Healthcheck: `/health`.

## Lokal

```
npm install
ADMIN_PASSWORD=test npm start   # http://localhost:3000/admin
```
