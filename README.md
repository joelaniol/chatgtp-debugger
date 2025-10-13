# ChatGPT Desktop Inspector (v5.1)

Desktop-Tool zum schnellen Auslesen der lokalen ChatGPT-Desktop-Datenbanken unter Windows: Logs, IndexedDB, Session Storage und Local Storage (LevelDB). Fokus liegt auf schneller Navigation, automatischer Pfaderkennung und einfacher Export-Funktion.

## Features
- Auto-Detect der wichtigsten Verzeichnisse (Microsoft Store und klassische EXE-Installation) laeuft beim Start automatisch und kann jederzeit erneut angestossen werden.
- Optionaler Root-Scan, um alle Quellen unterhalb eines ausgewaehlten Verzeichnisses zu finden.
- Tabs fuer Logs, IndexedDB, Session Storage und Local Storage inkl. String-Extraktion (ASCII, UTF-16LE).
- Automatisches Strings-Scanning: Binaerdateien werden beim Anklicken sofort extrahiert; der Button dient fuer erneute Scans.
- Kompakte Pfad-Uebersicht mit Statusanzeige; manuelle Anpassungen erfolgen ueber den Button `Erweiterte Pfade ...`.
- Telemetry-Tab aggregiert Sentry-Session/Queue sowie Crashpad-Hinweise.
- Netzwerk-, Konfig- und Speicher-Tabs liefern JSON-Pretty-Print und schreibgeschuetzte SQLite-Vorschauen (Cookies, Trust Tokens, QuotaManager, SharedStorage, DIPS, PrivateAggregation).
- MCP Auto-Suche, die relevante Hinweise in allen Quellen zusammenfasst (`outputs/mcp_report.txt`).
- Export der angezeigten Strings in Textdateien.

## Voraussetzungen
- Windows mit installierter Python 3.9+ Runtime (`py -3` oder `python` im PATH).
- Schreibrechte im Projektordner (fuer `.venv/` und `outputs/`).

## Schnellstart (empfohlen)
1. Repository klonen oder herunterladen und entpacken.
2. `start.bat` per Doppelklick ausfuehren.
   - Erstellt bei Bedarf `.venv`.
   - Installiert `requirements.txt` (aktuell nur `chardet`).
   - Startet direkt die Anwendung.
3. Nach dem Start erkennt die App alle Quellen automatisch. Optional einen Root-Ordner setzen und `Auto finden (alle)` nutzen oder mit `Neu laden (alle)` bzw. `Ordner waehlen` gezielt aktualisieren.

## Manueller Start
```powershell
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Falls `py` nicht verfuegbar ist, stattdessen `python` verwenden. Fuer UTF-8-Ausgabe kann optional `set PYTHONUTF8=1` gesetzt werden.

## Bedienkonzept
- **Pfad-Uebersicht:** Die Startseite zeigt fuer jede Quelle den Status (`Gefunden` oder `Nicht gefunden`). Feinanpassungen koennen ueber `Erweiterte Pfade ...` vorgenommen werden.
- **Root (optional):** Basisordner fuer die automatische Suche. `Auto finden (alle)` stoesst eine komplette Neu-Detektion an, `Neu laden (alle)` scannt die aktuellen Pfade erneut. `Root waehlen` aktualisiert den Pfad sofort.
- **Tabs:** Logs, IndexedDB, Session Storage und Local Storage liefern Text- und String-Ansichten; laengere Operationen laufen in separaten Threads.
- **Telemetry / Netzwerk / Konfiguration / Speicher:** Neue Viewer fuer Sentry, Crashpad, Netzwerk-Dateien (HTTP/QUIC, Cookies), Konfigurationsdateien (config.json, Preferences) sowie SQLite-basierte Speicher (QuotaManager, SharedStorage, DIPS, PrivateAggregation) mit schreibgeschuetzter Vorschau.
- **Automatisches Strings-Scanning:** Beim Anklicken einer Binaerdatei startet die Extraktion automatisch (ASCII, UTF-16LE). Der Button `Strings erneut scannen` wiederholt den Vorgang mit angepassten Parametern.
- **Export:** Speichert den aktuellen Inhalt des jeweiligen Viewers unter `outputs/<dateiname>.strings.txt`.

## MCP Auto-Suche
- Startet einen Hintergrund-Thread und durchsucht alle Quellen anhand der Muster in `text_utils.DEFAULT_MCP_PATTERNS`.
- Ergebnis wird im Ordner `outputs/` als `mcp_report.txt` abgelegt.
- Die Statusleiste zeigt Fortschritt und Fehler an.

## Datenquellen & Pfade
- Automatische Erkennung nutzt Variablen `LOCALAPPDATA` und `APPDATA`.
- Unterstuetzte Ordner/Dateien (werden automatisch erkannt und im UI zusammengefasst):
  - `Logs`
  - `IndexedDB/<site>.indexeddb.leveldb`
  - `Session Storage`
  - `Local Storage/leveldb`
  - `Network` (u. a. `Network Persistent State`, `TransportSecurity`, `Cookies`, `Trust Tokens`)
  - `sentry/` (Session/Queue)
  - `Crashpad/` (Reports/Attachments)
  - `config.json`, `Local State`, `Preferences`
  - `WebStorage/QuotaManager`, `SharedStorage`, `DIPS`, `PrivateAggregation`
- Bei mehreren Kandidaten wird der wahrscheinlichste Ordner (z. B. `https_chatgpt.com_0.indexeddb.leveldb`) bevorzugt.

## Troubleshooting
- **Leere Tabs:** Pfade pruefen oder `Auto finden (alle)`/`Neu laden (alle)` ausfuehren.
- **Keine Python-Installation:** Offizielle Python-Version installieren (https://www.python.org/downloads/) und waehrend des Setups `Add Python to PATH` aktivieren.
- **Unicode-Artefakte:** Ausgabe erfolgt UTF-8-basiert. Falls Zeichen falsch angezeigt werden, sicherstellen, dass das Terminal bzw. die Ziel-Datei UTF-8 unterstuetzt.

## Lizenz
Keine Lizenz hinterlegt - vor Nutzung oder Verteilung bitte mit dem Projektinhaber klaeren.
