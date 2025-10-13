# ChatGPT Desktop Inspector (v5.1)

Desktop-Tool zum schnellen Auslesen der lokalen ChatGPT-Desktop-Datenbanken unter Windows: Logs, IndexedDB, Session Storage und Local Storage (LevelDB). Fokus liegt auf schneller Navigation, automatischer Pfaderkennung und einfacher Export-Funktion.

## Features
- Auto-Detect der wichtigsten Verzeichnisse (Microsoft Store und klassische EXE-Installation).
- Optionaler Root-Scan, um alle Quellen unterhalb eines ausgewaehlten Verzeichnisses zu finden.
- Tabs fuer Logs, IndexedDB, Session Storage und Local Storage inkl. String-Extraktion (ASCII, UTF-16LE).
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
3. In der App optional einen Root-Ordner auswaehlen und `Auto finden (alle)` starten oder die einzelnen Quellen-Ordner manuell setzen.

## Manueller Start
```powershell
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Falls `py` nicht verfuegbar ist, stattdessen `python` verwenden. Fuer UTF-8-Ausgabe kann optional `set PYTHONUTF8=1` gesetzt werden.

## Bedienkonzept
- **Root (optional):** Ordner waehlen, der als Ausgangspunkt fuer "Auto finden (alle)" dient.
- **Tabs:** Jeder Tab zeigt Dateien an, die wahlweise als Text oder Strings (mit Extraktion) gelesen werden koennen. Laden und Scannen laufen in separaten Threads, um die GUI reaktionsfaehig zu halten.
- **Strings scannen:** Extrahiert ASCII- und UTF-16LE-Strings aus Binaerdateien (LevelDB). Lange Dateien werden gestreamt, um Speicher zu sparen.
- **Export:** Speichert den aktuellen Inhalt des Editors unter `outputs/<dateiname>.strings.txt`.

## MCP Auto-Suche
- Startet einen Hintergrund-Thread und durchsucht alle Quellen anhand der Muster in `text_utils.DEFAULT_MCP_PATTERNS`.
- Ergebnis wird im Ordner `outputs/` als `mcp_report.txt` abgelegt.
- Die Statusleiste zeigt Fortschritt und Fehler an.

## Datenquellen & Pfade
- Automatische Erkennung nutzt Variablen `LOCALAPPDATA` und `APPDATA`.
- Unterstuetzte Ordner:
  - `Logs`
  - `IndexedDB/<site>.indexeddb.leveldb`
  - `Session Storage`
  - `Local Storage/leveldb`
- Bei mehreren Kandidaten wird der wahrscheinlichste Ordner (z. B. `https_chatgpt.com_0.indexeddb.leveldb`) bevorzugt.

## Troubleshooting
- **Leere Tabs:** Pfade pruefen oder die Auto-Erkennung erneut ausfuehren.
- **Keine Python-Installation:** Offizielle Python-Version installieren (https://www.python.org/downloads/) und waehrend des Setups `Add Python to PATH` aktivieren.
- **Unicode-Artefakte:** Ausgabe erfolgt UTF-8-basiert. Falls Zeichen falsch angezeigt werden, sicherstellen, dass das Terminal bzw. die Ziel-Datei UTF-8 unterstuetzt.

## Lizenz
Keine Lizenz hinterlegt - vor Nutzung oder Verteilung bitte mit dem Projektinhaber klaeren.
