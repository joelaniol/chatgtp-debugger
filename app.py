import json
import os
import sqlite3
import threading
import winreg
from pathlib import Path
from typing import List, Optional
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from text_utils import (
    safe_read_text, extract_strings_from_file,
    list_candidate_files_in_leveldb, list_log_files,
    detect_default_paths, autodetect_from_root, search_lines, DEFAULT_MCP_PATTERNS
)

APP_TITLE = "ChatGPT Desktop Inspector (v5.1)"
DEFAULT_EXPORT_DIR = "outputs"

class InspectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1220x800")
        self.minsize(1040, 680)

        # Paths & defaults
        defaults = detect_default_paths()
        self.root_dir = tk.StringVar(value="")
        self.indexeddb_dir = tk.StringVar(value=defaults.get("indexeddb",""))
        self.session_dir = tk.StringVar(value=defaults.get("session",""))
        self.logs_dir = tk.StringVar(value=defaults.get("logs",""))
        self.localstorage_dir = tk.StringVar(value=defaults.get("localstorage",""))
        self.network_dir = tk.StringVar(value=defaults.get("network",""))
        self.sentry_dir = tk.StringVar(value=defaults.get("sentry",""))
        self.config_file = tk.StringVar(value=defaults.get("config",""))
        self.local_state_file = tk.StringVar(value=defaults.get("local_state",""))
        self.preferences_file = tk.StringVar(value=defaults.get("preferences",""))
        self.crashpad_dir = tk.StringVar(value=defaults.get("crashpad",""))
        self.sharedstorage_file = tk.StringVar(value=defaults.get("sharedstorage",""))
        self.quota_manager_file = tk.StringVar(value=defaults.get("quota_manager",""))
        self.dips_file = tk.StringVar(value=defaults.get("dips",""))
        self.privateaggregation_dir = tk.StringVar(value=defaults.get("privateaggregation",""))
        self.cache_data_dir = tk.StringVar(value=defaults.get("cache_data",""))
        self.code_cache_dir = tk.StringVar(value=defaults.get("code_cache",""))
        self.settings_file = tk.StringVar(value=defaults.get("settings",""))
        self.package_root_dir = tk.StringVar(value=defaults.get("package_root",""))
        self.base_dir = tk.StringVar(value=defaults.get("base",""))
        self._registry_defs = [
            ("reg_app_path", "Registry App Path", "HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chatgpt.exe", None, False),
            ("reg_apphost_indexeddb", "Registry AppHost IndexedDB", "HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\AppHost\\IndexedDB", "OpenAI.ChatGPT-Desktop_", True),
            ("reg_background_access", "Registry BackgroundAccessApplications", "HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications", "OpenAI.ChatGPT-Desktop_", True),
            ("reg_capability_microphone", "Registry Capability Microphone", "HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone", "OpenAI.ChatGPT-Desktop_", True),
            ("reg_capability_webcam", "Registry Capability Webcam", "HKCU", r"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam", "OpenAI.ChatGPT-Desktop_", True),
            ("reg_appmodel_packages", "Registry AppModel Packages", "HKCU", r"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages", "OpenAI.ChatGPT-Desktop_", True),
            ("reg_appcontainer_storage", "Registry AppContainer Storage", "HKCU", r"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage", "openai.chatgpt-desktop_", True),
            ("reg_appmodel_systemdata", "Registry AppModel SystemAppData", "HKCU", r"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData", "OpenAI.ChatGPT-Desktop_", True),
        ]
        self.registry_vars = {key: tk.StringVar(value="") for key, *_ in self._registry_defs}
        self.status_var = tk.StringVar(value="Bereit")

        # Data caches
        self.idx_text = []; self.idx_bin = []
        self.ses_text = []; self.ses_bin = []
        self.ls_text = []; self.ls_bin = []
        self.logs_files = []
        self.idx_minlen_var = self.idx_utf16_var = self.idx_maxmb_var = None
        self.ses_minlen_var = self.ses_utf16_var = self.ses_maxmb_var = None
        self.ls_minlen_var = self.ls_utf16_var = self.ls_maxmb_var = None
        self.telemetry_text = None
        self.struct_views = {}

        self._build_ui()
        Path(DEFAULT_EXPORT_DIR).mkdir(exist_ok=True)
        self._refresh_registry_sources()
        self.auto_find_all(force=True)

    def _build_ui(self):
        top = ttk.LabelFrame(self, text="Quellen (automatisch erkannt)")
        top.pack(fill="x", padx=8, pady=8)

        row0 = ttk.Frame(top); row0.pack(fill="x", pady=(0,6))
        ttk.Label(row0, text="Root (optional):").pack(side="left")
        ttk.Entry(row0, textvariable=self.root_dir, width=80).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(
            row0,
            text="Root waehlen",
            command=lambda:self._choose_dir(self.root_dir, lambda: self.auto_find_all(force=True))
        ).pack(side="left")
        ttk.Button(row0, text="Auto finden (alle)", command=lambda:self.auto_find_all(force=True)).pack(side="left", padx=6)
        ttk.Button(row0, text="Neu laden (alle)", command=self.scan_all).pack(side="left")

        summary = ttk.Frame(top); summary.pack(fill="x", pady=(4,4))
        ttk.Label(summary, text="Gefundene Quellen:").pack(anchor="w")

        stats_row = ttk.Frame(summary); stats_row.pack(fill="x", pady=(2,0))
        self.summary_found_var = tk.StringVar(value="Gefunden: 0")
        self.summary_missing_var = tk.StringVar(value="Nicht gefunden: 0")
        ttk.Label(stats_row, textvariable=self.summary_found_var, foreground="#1f7f37").pack(side="left")
        ttk.Label(stats_row, textvariable=self.summary_missing_var, foreground="#b32424").pack(side="left", padx=12)
        self.summary_toggle_button = ttk.Button(
            stats_row,
            text="Details anzeigen",
            command=self.toggle_summary_details
        )
        self.summary_toggle_button.pack(side="left")

        self.summary_details_frame = ttk.Frame(summary)
        self.summary_details_frame.pack(fill="x", pady=(2,0))
        self.summary_details_frame.columnconfigure(1, weight=1)

        self.path_summary_labels = {}
        for idx, (key, label, var) in enumerate(self._path_summary_items()):
            ttk.Label(self.summary_details_frame, text=f"{label}:").grid(row=idx, column=0, sticky="w", padx=(0,6), pady=1)
            status_label = tk.Label(self.summary_details_frame, text="-", anchor="w")
            status_label.grid(row=idx, column=1, sticky="w", pady=1)
            self.path_summary_labels[key] = status_label

        self.summary_details_visible = True
        self.toggle_summary_details(force=False)

        controls = ttk.Frame(top); controls.pack(fill="x", pady=(4,0))
        ttk.Button(controls, text="Erweiterte Pfade ...", command=self.open_path_manager).pack(side="left")

        tools = ttk.Frame(self); tools.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(tools, text="MCP Auto-Suche (Report)", command=self.run_mcp_auto_search).pack(side="left")

        self.nb = ttk.Notebook(self); self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        # Tabs
        self.tab_logs = ttk.Frame(self.nb); self.nb.add(self.tab_logs, text="Logs")
        self._build_tab_logs(self.tab_logs)

        self.tab_idx = ttk.Frame(self.nb); self.nb.add(self.tab_idx, text="IndexedDB / LevelDB")
        self._build_tab_leveldb(self.tab_idx, which="idx")

        self.tab_ses = ttk.Frame(self.nb); self.nb.add(self.tab_ses, text="Session Storage")
        self._build_tab_leveldb(self.tab_ses, which="ses")

        self.tab_ls = ttk.Frame(self.nb); self.nb.add(self.tab_ls, text="Local Storage (leveldb)")
        self._build_tab_leveldb(self.tab_ls, which="ls")

        self.tab_telemetry = ttk.Frame(self.nb); self.nb.add(self.tab_telemetry, text="Telemetry (Sentry)")
        self._build_tab_telemetry(self.tab_telemetry)

        self.tab_network = ttk.Frame(self.nb); self.nb.add(self.tab_network, text="Netzwerk")
        self._build_tab_structured(self.tab_network, which="network")

        self.tab_config = ttk.Frame(self.nb); self.nb.add(self.tab_config, text="Konfiguration")
        self._build_tab_structured(self.tab_config, which="config")

        self.tab_storage = ttk.Frame(self.nb); self.nb.add(self.tab_storage, text="Speicher (SQLite)")
        self._build_tab_structured(self.tab_storage, which="storage")

        self.tab_install = ttk.Frame(self.nb); self.nb.add(self.tab_install, text="Installation")
        self._build_tab_structured(self.tab_install, which="install")

        self.tab_registry = ttk.Frame(self.nb); self.nb.add(self.tab_registry, text="Registrierung")
        self._build_tab_structured(self.tab_registry, which="registry")

        # Status bar
        sb = ttk.Frame(self); sb.pack(fill="x")
        ttk.Label(sb, textvariable=self.status_var, anchor="w").pack(fill="x")

        for _, _, var in self._path_summary_items():
            var.trace_add("write", lambda *_: self._update_path_summary())
        self._update_path_summary()

    def _path_entries(self):
        entries = [
            ("logs", "Logs", self.logs_dir, "dir"),
            ("indexeddb", "IndexedDB", self.indexeddb_dir, "dir"),
            ("session", "Session Storage", self.session_dir, "dir"),
            ("localstorage", "Local Storage (leveldb)", self.localstorage_dir, "dir"),
            ("network", "Network", self.network_dir, "dir"),
            ("sentry", "Sentry", self.sentry_dir, "dir"),
            ("crashpad", "Crashpad", self.crashpad_dir, "dir"),
            ("config", "config.json", self.config_file, "file"),
            ("local_state", "Local State", self.local_state_file, "file"),
            ("preferences", "Preferences", self.preferences_file, "file"),
            ("sharedstorage", "SharedStorage", self.sharedstorage_file, "file"),
            ("quota_manager", "QuotaManager", self.quota_manager_file, "file"),
            ("dips", "DIPS", self.dips_file, "file"),
            ("privateaggregation", "PrivateAggregation", self.privateaggregation_dir, "dir"),
            ("cache_data", "Cache Data", self.cache_data_dir, "dir"),
            ("code_cache", "Code Cache", self.code_cache_dir, "dir"),
            ("settings", "settings.dat", self.settings_file, "file"),
            ("package_root", "Package Root", self.package_root_dir, "dir"),
        ]
        for key, label, *_rest in self._registry_defs:
            entries.append((key, label, self.registry_vars[key], "registry"))
        return entries

    def _path_summary_items(self):
        return [(key, label, var) for key, label, var, _ in self._path_entries()]

    def _update_path_summary(self):
        found = 0
        missing = 0
        for key, label, var, _kind in self._path_entries():
            summary_lbl = self.path_summary_labels.get(key)
            if not summary_lbl:
                continue
            path = var.get().strip()
            if path:
                summary_lbl.config(text="Gefunden", fg="#1f7f37")
                found += 1
            else:
                summary_lbl.config(text="Nicht gefunden", fg="#b32424")
                missing += 1
        if hasattr(self, "summary_found_var"):
            self.summary_found_var.set(f"Gefunden: {found}")
        if hasattr(self, "summary_missing_var"):
            self.summary_missing_var.set(f"Nicht gefunden: {missing}")

    def _refresh_registry_sources(self):
        for key, _label, root_name, base_path, pattern, multi in self._registry_defs:
            matches = self._list_registry_matches(root_name, base_path, pattern, multi)
            value = matches[0] if matches else ""
            self.registry_vars[key].set(value)
        self._update_path_summary()

    def toggle_summary_details(self, force: Optional[bool] = None):
        show = not getattr(self, "summary_details_visible", False)
        if force is not None:
            show = force
        if show:
            self.summary_details_frame.pack(fill="x", pady=(2,0))
            self.summary_toggle_button.config(text="Details ausblenden")
            self.summary_details_visible = True
        else:
            self.summary_details_frame.pack_forget()
            self.summary_toggle_button.config(text="Details anzeigen")
            self.summary_details_visible = False
        # ensure counters stay accurate
        self._update_path_summary()

    def open_path_manager(self):
        if hasattr(self, "_paths_dialog") and self._paths_dialog.winfo_exists():
            self._paths_dialog.lift()
            self._paths_dialog.focus_force()
            return
        win = tk.Toplevel(self)
        win.title("Erweiterte Pfade")
        win.geometry("780x420")
        win.resizable(False, False)
        self._paths_dialog = win

        body = ttk.Frame(win); body.pack(fill="both", expand=True, padx=12, pady=12)
        for key, label, var, kind in self._path_entries():
            row = ttk.Frame(body); row.pack(fill="x", pady=2)
            ttk.Label(row, text=f"{label}:").pack(side="left")
            if kind == "registry":
                entry = ttk.Entry(row, textvariable=var, width=70, state="readonly")
                entry.pack(side="left", fill="x", expand=True, padx=6)
                continue
            entry = ttk.Entry(row, textvariable=var, width=70)
            entry.pack(side="left", fill="x", expand=True, padx=6)
            entry.bind("<Return>", lambda _e: self._on_paths_changed(rescan=True))
            entry.bind("<KP_Enter>", lambda _e: self._on_paths_changed(rescan=True))
            ttk.Button(
                row,
                text="Auswaehlen",
                command=lambda v=var, k=kind: self._choose_path(v, lambda: self._on_paths_changed(rescan=True), kind=k)
            ).pack(side="left")

        buttons = ttk.Frame(body); buttons.pack(fill="x", pady=(10,0))
        ttk.Button(buttons, text="Auto finden (alle)", command=lambda: self.auto_find_all(force=True)).pack(side="left")
        ttk.Button(buttons, text="Neu laden", command=self.scan_all).pack(side="left", padx=6)
        ttk.Button(buttons, text="Schliessen", command=win.destroy).pack(side="right")

    def _on_paths_changed(self, rescan=False):
        self._update_path_summary()
        if rescan:
            self.scan_all()

    def _choose_path(self, var, on_change=None, kind="dir"):
        if kind == "registry":
            return
        if kind == "file":
            p = filedialog.askopenfilename(title="Datei auswaehlen")
        else:
            p = filedialog.askdirectory(title="Ordner auswaehlen")
        if p:
            var.set(p)
            if on_change:
                self.after_idle(on_change)

    def _choose_dir(self, var, on_change=None):
        self._choose_path(var, on_change=on_change, kind="dir")

    def scan_all(self):
        self._refresh_registry_sources()
        self.scan_logs()
        self.scan_indexeddb()
        self.scan_session()
        self.scan_localstorage()
        self.scan_structured("network")
        self.scan_structured("config")
        self.scan_structured("storage")
        self.scan_structured("registry")
        self.scan_telemetry()

    def auto_find_all(self, force=False):
        root = self.root_dir.get().strip()
        if root:
            found = autodetect_from_root(root)
        else:
            found = detect_default_paths()
        def maybe_set(var, key):
            if found.get(key) and (force or not var.get().strip()):
                var.set(found[key])
        maybe_set(self.logs_dir, "logs")
        maybe_set(self.indexeddb_dir, "indexeddb")
        maybe_set(self.session_dir, "session")
        maybe_set(self.localstorage_dir, "localstorage")
        maybe_set(self.network_dir, "network")
        maybe_set(self.sentry_dir, "sentry")
        maybe_set(self.crashpad_dir, "crashpad")
        maybe_set(self.config_file, "config")
        maybe_set(self.local_state_file, "local_state")
        maybe_set(self.preferences_file, "preferences")
        maybe_set(self.sharedstorage_file, "sharedstorage")
        maybe_set(self.quota_manager_file, "quota_manager")
        maybe_set(self.dips_file, "dips")
        maybe_set(self.privateaggregation_dir, "privateaggregation")
        maybe_set(self.base_dir, "base")
        self._refresh_registry_sources()
        self.status_var.set(
            "Auto-Erkennung: "
            f"Logs={bool(found.get('logs'))}, "
            f"IndexedDB={bool(found.get('indexeddb'))}, "
            f"Session={bool(found.get('session'))}, "
            f"LocalStorage={bool(found.get('localstorage'))}, "
            f"Network={bool(found.get('network'))}, "
            f"Sentry={bool(found.get('sentry'))}"
        )
        self.scan_all()

    # --- Logs Tab ---
    def _build_tab_logs(self, parent):
        top = ttk.Frame(parent); top.pack(fill="x")
        self.log_search_var = tk.StringVar(value="")
        ttk.Label(top, text="Suchen/Filtern:").pack(side="left")
        ttk.Entry(top, textvariable=self.log_search_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Anwenden", command=self.apply_log_filter).pack(side="left")
        ttk.Button(top, text="Zuruecksetzen", command=self.reset_log_filter).pack(side="left", padx=4)
        ttk.Button(top, text="Export Ansicht", command=self.export_log_view).pack(side="left", padx=6)

        mid = ttk.Frame(parent); mid.pack(fill="both", expand=True, pady=(6,0))
        left = ttk.Frame(mid); left.pack(side="left", fill="y", padx=(0,6))
        self.logs_list = tk.Listbox(left, width=48, height=20, exportselection=False)
        self.logs_list.pack(fill="y")
        self.logs_list.bind("<<ListboxSelect>>", self.on_select_log_file)

        right = ttk.Frame(mid); right.pack(side="left", fill="both", expand=True)
        self.log_text = tk.Text(right, wrap="none")
        self.log_text.pack(fill="both", expand=True)

    def scan_logs(self):
        folder = self.logs_dir.get().strip()
        self.logs_files = list_log_files(folder)
        self.logs_list.delete(0, "end")
        for p in self.logs_files:
            self.logs_list.insert("end", os.path.basename(p))
        self.log_text.delete("1.0","end")
        self.status_var.set(f"Logs: {len(self.logs_files)} Dateien gefunden.")

    def on_select_log_file(self, _evt=None):
        sel = self.logs_list.curselection()
        if not sel:
            return
        idx = sel[0]
        path = self.logs_files[idx]
        enc, content = safe_read_text(path)
        header = f"=== {os.path.basename(path)} (encoding={enc}) ===\n\n"
        self.log_text.delete("1.0","end")
        self.log_text.insert("1.0", header + content)
        self.status_var.set(f"{os.path.basename(path)} geladen.")

    def apply_log_filter(self):
        q = self.log_search_var.get().strip().lower()
        if not q:
            return
        data = self.log_text.get("1.0","end")
        lines = [ln for ln in data.splitlines() if q in ln.lower()]
        self.log_text.delete("1.0","end")
        self.log_text.insert("1.0", "\n".join(lines) if lines else "[Keine Treffer]")

    def reset_log_filter(self):
        self.on_select_log_file()

    def export_log_view(self):
        out = Path(DEFAULT_EXPORT_DIR) / "logs_view.txt"
        out.write_text(self.log_text.get("1.0","end"), encoding="utf-8", errors="replace")
        messagebox.showinfo("Export", f"Gespeichert: {out}")

    # --- LevelDB-like tabs (IndexedDB / Session / LocalStorage) ---
    def _build_tab_leveldb(self, parent, which="idx"):
        top = ttk.Frame(parent); top.pack(fill="x")
        minlen_label = ttk.Label(top, text="Min. Laenge:"); minlen_label.pack(side="left")
        minlen_var = tk.IntVar(value=8)
        ttk.Entry(top, textvariable=minlen_var, width=6).pack(side="left", padx=(4,10))
        utf16_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="UTF-16LE erkennen", variable=utf16_var).pack(side="left")
        ttk.Label(top, text="Max. MB (optional):").pack(side="left", padx=(10,0))
        maxmb_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=maxmb_var, width=6).pack(side="left", padx=(4,10))
        ttk.Button(top, text="Strings erneut scannen", command=lambda:self.scan_strings(which, minlen_var, utf16_var, maxmb_var)).pack(side="left")
        ttk.Button(top, text="Export Strings", command=lambda:self.export_current_strings(which)).pack(side="left", padx=6)
        if which == "idx":
            self.idx_minlen_var = minlen_var
            self.idx_utf16_var = utf16_var
            self.idx_maxmb_var = maxmb_var
        elif which == "ses":
            self.ses_minlen_var = minlen_var
            self.ses_utf16_var = utf16_var
            self.ses_maxmb_var = maxmb_var
        else:
            self.ls_minlen_var = minlen_var
            self.ls_utf16_var = utf16_var
            self.ls_maxmb_var = maxmb_var

        body = ttk.Frame(parent); body.pack(fill="both", expand=True)
        left = ttk.Frame(body); left.pack(side="left", fill="y", padx=(0,6))
        lb = tk.Listbox(left, width=48, height=18, exportselection=False)
        lb.pack(fill="y", expand=False)
        lb.bind("<<ListboxSelect>>", lambda _e: self.on_select_leveldb_file(which))
        if which == "idx": self.idx_list = lb
        elif which == "ses": self.ses_list = lb
        else: self.ls_list = lb

        b2 = ttk.Frame(left); b2.pack(fill="x", pady=4)
        ttk.Button(b2, text="Export Datei", command=lambda:self.export_current_text(which)).pack(side="left")

        right = ttk.Frame(body); right.pack(side="left", fill="both", expand=True)
        sb = ttk.Frame(right); sb.pack(fill="x")
        sv = tk.StringVar(value="")
        ttk.Label(sb, text="Suchen/Filtern:").pack(side="left")
        ttk.Entry(sb, textvariable=sv).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(sb, text="Anwenden", command=lambda:self.apply_leveldb_filter(which, sv)).pack(side="left")
        ttk.Button(sb, text="Zuruecksetzen", command=lambda:self.reset_leveldb_filter(which)).pack(side="left", padx=4)

        tv = tk.Text(right, wrap="none")
        tv.pack(fill="both", expand=True, pady=(6,0))
        if which == "idx": self.idx_textview = tv; self.idx_search_var = sv
        elif which == "ses": self.ses_textview = tv; self.ses_search_var = sv
        else: self.ls_textview = tv; self.ls_search_var = sv

    def scan_indexeddb(self):
        folder = self.indexeddb_dir.get().strip()
        self.idx_text, self.idx_bin = list_candidate_files_in_leveldb(folder)
        self.idx_list.delete(0, "end")
        for p in self.idx_text + self.idx_bin:
            self.idx_list.insert("end", os.path.basename(p))
        self.idx_textview.delete("1.0","end")
        self.status_var.set(f"IndexedDB: {len(self.idx_text)} Text, {len(self.idx_bin)} Binaerdateien.")

    def scan_session(self):
        folder = self.session_dir.get().strip()
        self.ses_text, self.ses_bin = list_candidate_files_in_leveldb(folder)
        self.ses_list.delete(0, "end")
        for p in self.ses_text + self.ses_bin:
            self.ses_list.insert("end", os.path.basename(p))
        self.ses_textview.delete("1.0","end")
        self.status_var.set(f"Session Storage: {len(self.ses_text)} Text, {len(self.ses_bin)} Binaerdateien.")

    def scan_localstorage(self):
        folder = self.localstorage_dir.get().strip()
        self.ls_text, self.ls_bin = list_candidate_files_in_leveldb(folder)
        self.ls_list.delete(0, "end")
        for p in self.ls_text + self.ls_bin:
            self.ls_list.insert("end", os.path.basename(p))
        self.ls_textview.delete("1.0","end")
        self.status_var.set(f"Local Storage: {len(self.ls_text)} Text, {len(self.ls_bin)} Binaerdateien.")

    def _resolve_leveldb_path(self, which, idx):
        if which == "idx":
            files = self.idx_text + self.idx_bin
        elif which == "ses":
            files = self.ses_text + self.ses_bin
        else:
            files = self.ls_text + self.ls_bin
        if idx < 0 or idx >= len(files):
            return None
        return files[idx]

    def _leveldb_controls(self, which):
        if which == "idx":
            return self.idx_minlen_var, self.idx_utf16_var, self.idx_maxmb_var
        if which == "ses":
            return self.ses_minlen_var, self.ses_utf16_var, self.ses_maxmb_var
        return self.ls_minlen_var, self.ls_utf16_var, self.ls_maxmb_var

    def on_select_leveldb_file(self, which):
        if which == "idx":
            lb, tv, text_files = self.idx_list, self.idx_textview, self.idx_text
        elif which == "ses":
            lb, tv, text_files = self.ses_list, self.ses_textview, self.ses_text
        else:
            lb, tv, text_files = self.ls_list, self.ls_textview, self.ls_text

        sel = lb.curselection()
        if not sel: return
        i = sel[0]
        if i < len(text_files):
            path = self._resolve_leveldb_path(which, i)
            enc, content = safe_read_text(path)
            header = f"=== {os.path.basename(path)} (encoding={enc}) ===\n\n"
            tv.delete("1.0","end")
            tv.insert("1.0", header + content)
        else:
            minlen_var, utf16_var, maxmb_var = self._leveldb_controls(which)
            if minlen_var is None:
                tv.delete("1.0","end")
                tv.insert("1.0", "[Binaerdatei ausgewaehlt. Automatischer Scan nicht verfuegbar.]")
                return
            self.scan_strings(which, minlen_var, utf16_var, maxmb_var)

    def apply_leveldb_filter(self, which, var):
        q = var.get().strip().lower()
        tv = self.idx_textview if which=="idx" else self.ses_textview if which=="ses" else self.ls_textview
        if not q: return
        data = tv.get("1.0","end")
        lines = [ln for ln in data.splitlines() if q in ln.lower()]
        tv.delete("1.0","end")
        tv.insert("1.0", "\n".join(lines) if lines else "[Keine Treffer]")

    def reset_leveldb_filter(self, which):
        self.on_select_leveldb_file(which)

    def export_current_text(self, which):
        lb = self.idx_list if which=="idx" else self.ses_list if which=="ses" else self.ls_list
        text_files = self.idx_text if which=="idx" else self.ses_text if which=="ses" else self.ls_text
        sel = lb.curselection()
        if not sel:
            messagebox.showinfo("Export", "Keine Datei ausgewaehlt.")
            return
        idx = sel[0]
        if idx >= len(text_files):
            messagebox.showinfo("Export", "Binaerdatei: Bitte 'Export Strings' benutzen.")
            return
        path = self._resolve_leveldb_path(which, idx)
        enc, content = safe_read_text(path)
        out = Path(DEFAULT_EXPORT_DIR) / f"{os.path.basename(path)}.txt"
        out.write_text(content, encoding="utf-8", errors="replace")
        messagebox.showinfo("Export", f"Gespeichert: {out}")

    def scan_strings(self, which, minlen_var, utf16_var, maxmb_var):
        if which == "idx":
            lb, tv, text_files, bin_files = self.idx_list, self.idx_textview, self.idx_text, self.idx_bin
        elif which == "ses":
            lb, tv, text_files, bin_files = self.ses_list, self.ses_textview, self.ses_text, self.ses_bin
        else:
            lb, tv, text_files, bin_files = self.ls_list, self.ls_textview, self.ls_text, self.ls_bin

        sel = lb.curselection()
        if not sel:
            messagebox.showinfo("Hinweis", "Bitte zuerst eine Binaerdatei auswaehlen.")
            return
        idx = sel[0]
        if idx < len(text_files):
            messagebox.showinfo("Hinweis", "Textdatei ausgewaehlt. Bitte eine Binaerdatei (.ldb/.log/.sst) waehlen.")
            return
        path = (text_files + bin_files)[idx]
        try:
            minlen = int(minlen_var.get())
        except Exception:
            minlen = 8
        include_utf16le = bool(utf16_var.get())
        max_mb = None
        m = maxmb_var.get().strip()
        if m:
            try:
                v = int(m)
                if v > 0: max_mb = v
            except Exception:
                max_mb = None

        tv.delete("1.0","end")
        tv.insert("1.0", "[Bitte warten - Strings werden extrahiert ...]")
        self.status_var.set(f"Strings in {os.path.basename(path)} ...")

        def worker():
            try:
                total, strings = extract_strings_from_file(path, min_len=minlen, include_utf16le=include_utf16le, max_mb=max_mb)
            except Exception as ex:
                messagebox.showerror("Fehler", str(ex))
                self.status_var.set(f"Fehler: {ex}")
                return
            tv.delete("1.0","end")
            tv.insert("1.0", "\n".join(strings) if strings else "[Keine Strings gefunden]")
            mb = total/(1024*1024)
            self.status_var.set(f"Fertig. {len(strings)} Strings aus {mb:.2f} MiB.")

        threading.Thread(target=worker, daemon=True).start()

    def export_current_strings(self, which):
        tv = self.idx_textview if which=="idx" else self.ses_textview if which=="ses" else self.ls_textview
        lb = self.idx_list if which=="idx" else self.ses_list if which=="ses" else self.ls_list
        text_files = self.idx_text if which=="idx" else self.ses_text if which=="ses" else self.ls_text
        bin_files = self.idx_bin if which=="idx" else self.ses_bin if which=="ses" else self.ls_bin
        sel = lb.curselection()
        if not sel:
            messagebox.showinfo("Export", "Keine Binaerdatei ausgewaehlt.")
            return
        idx = sel[0]
        if idx < len(text_files):
            messagebox.showinfo("Export", "Textdatei: Bitte 'Export Datei' verwenden.")
            return
        path = (text_files + bin_files)[idx]
        data = tv.get("1.0","end")
        if not data.strip():
            messagebox.showinfo("Export", "Keine Strings im Editor. Bitte vorher 'Strings scannen'.")
            return
        out = Path(DEFAULT_EXPORT_DIR) / (os.path.basename(path) + ".strings.txt")
        out.write_text(data, encoding="utf-8", errors="replace")
        messagebox.showinfo("Export", f"Gespeichert: {out}")

    def _build_tab_telemetry(self, parent):
        top = ttk.Frame(parent); top.pack(fill="x")
        ttk.Button(top, text="Neu laden", command=self.scan_telemetry).pack(side="left")
        ttk.Button(
            top,
            text="Export Ansicht",
            command=lambda:self._export_text_widget(self.telemetry_text, "telemetry_view.txt")
        ).pack(side="left", padx=6)

        body = ttk.Frame(parent); body.pack(fill="both", expand=True, pady=(6,0))
        text = tk.Text(body, wrap="none")
        text.pack(side="left", fill="both", expand=True)
        scroll_y = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        scroll_y.pack(side="right", fill="y")
        text.configure(yscrollcommand=scroll_y.set)
        self.telemetry_text = text

    def _build_tab_structured(self, parent, which: str):
        container = ttk.Frame(parent); container.pack(fill="both", expand=True)

        top = ttk.Frame(container); top.pack(fill="x")
        ttk.Button(top, text="Neu laden", command=lambda:self.scan_structured(which)).pack(side="left")
        ttk.Button(
            top,
            text="Export Ansicht",
            command=lambda:self.export_structured(which)
        ).pack(side="left", padx=6)

        body = ttk.Frame(container); body.pack(fill="both", expand=True, pady=(6,0))

        left = ttk.Frame(body); left.pack(side="left", fill="y", padx=(0,6))
        lb = tk.Listbox(left, width=42, height=18, exportselection=False)
        lb.pack(side="left", fill="y")
        lb.bind("<<ListboxSelect>>", lambda _e, key=which: self.on_select_structured_file(key))

        right = ttk.Frame(body); right.pack(side="left", fill="both", expand=True)
        text = tk.Text(right, wrap="none")
        text.pack(side="left", fill="both", expand=True)
        scroll_y = ttk.Scrollbar(right, orient="vertical", command=text.yview)
        scroll_y.pack(side="left", fill="y")
        scroll_x = ttk.Scrollbar(right, orient="horizontal", command=text.xview)
        scroll_x.pack(side="bottom", fill="x")
        text.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        self.struct_views[which] = {"list": lb, "text": text, "files": []}

    def scan_telemetry(self):
        if self.telemetry_text is None:
            return
        self.telemetry_text.delete("1.0","end")
        sentry_dir = self.sentry_dir.get().strip()
        crashpad_dir = self.crashpad_dir.get().strip()
        if not sentry_dir or not os.path.isdir(sentry_dir):
            self.telemetry_text.insert("1.0", "[Sentry-Ordner nicht gefunden]\n")
        else:
            session_path = os.path.join(sentry_dir, "session.json")
            queue_path = os.path.join(sentry_dir, "queue", "queue-v2.json")
            self.telemetry_text.insert("end", "Sentry session.json\n")
            self.telemetry_text.insert("end", self._read_json_pretty(session_path) + "\n\n")
            self.telemetry_text.insert("end", "Sentry queue/queue-v2.json\n")
            self.telemetry_text.insert("end", self._read_json_pretty(queue_path) + "\n")
        if crashpad_dir and os.path.isdir(crashpad_dir):
            reports_dir = os.path.join(crashpad_dir, "reports")
            attachments_dir = os.path.join(crashpad_dir, "attachments")
            self.telemetry_text.insert("end", "\nCrashpad\n")
            if os.path.isdir(reports_dir):
                reports = sorted(os.listdir(reports_dir))
                if reports:
                    self.telemetry_text.insert("end", "  Reports:\n")
                    for name in reports[:20]:
                        self.telemetry_text.insert("end", f"    {name}\n")
                    if len(reports) > 20:
                        self.telemetry_text.insert("end", f"    ... ({len(reports)} gesamt)\n")
                else:
                    self.telemetry_text.insert("end", "  Keine Reports\n")
            else:
                self.telemetry_text.insert("end", "  reports/-Ordner nicht gefunden\n")
            if os.path.isdir(attachments_dir):
                attachments = sorted(os.listdir(attachments_dir))
                if attachments:
                    self.telemetry_text.insert("end", "  Attachments:\n")
                    for name in attachments[:20]:
                        self.telemetry_text.insert("end", f"    {name}\n")
                    if len(attachments) > 20:
                        self.telemetry_text.insert("end", f"    ... ({len(attachments)} gesamt)\n")
                else:
                    self.telemetry_text.insert("end", "  Keine Attachments\n")
        else:
            self.telemetry_text.insert("end", "\nCrashpad-Ordner nicht gefunden.\n")
        self.status_var.set("Telemetry aktualisiert.")

    def scan_structured(self, which: str):
        view = self.struct_views.get(which)
        if not view:
            return
        files = self._discover_structured_files(which)
        view["files"] = files
        lb = view["list"]
        lb.delete(0, "end")
        for item in files:
            lb.insert("end", item["label"])
        text = view["text"]
        text.delete("1.0","end")
        if files:
            lb.selection_set(0)
            self.on_select_structured_file(which, auto=True)
        else:
            text.insert("1.0", "[Keine Dateien gefunden]")
            self.status_var.set("Keine Dateien gefunden.")

    def on_select_structured_file(self, which: str, auto: bool = False):
        view = self.struct_views.get(which)
        if not view:
            return
        lb = view["list"]
        files = view["files"]
        sel = lb.curselection()
        if not sel:
            if auto and files:
                lb.selection_set(0)
                sel = (0,)
            else:
                return
        idx = sel[0]
        if idx < 0 or idx >= len(files):
            return
        record = files[idx]
        content = self._preview_structured_entry(record)
        text = view["text"]
        text.delete("1.0","end")
        text.insert("1.0", content)
        self.status_var.set(f"{record['label']} geladen.")

    def export_structured(self, which: str):
        view = self.struct_views.get(which)
        if not view:
            return
        filename = f"{which}_view.txt"
        self._export_text_widget(view["text"], filename)

    def _discover_structured_files(self, which: str):
        items = []
        if which == "network":
            base = self.network_dir.get().strip()
            if base and os.path.isdir(base):
                mapping = [
                    ("Network Persistent State (JSON)", os.path.join(base, "Network Persistent State")),
                    ("TransportSecurity (JSON)", os.path.join(base, "TransportSecurity")),
                    ("Cookies (SQLite)", os.path.join(base, "Cookies")),
                    ("Trust Tokens (SQLite)", os.path.join(base, "Trust Tokens")),
                ]
                for label, path in mapping:
                    self._add_structured_item(items, label, path)
        elif which == "config":
            mapping = [
                ("config.json", self.config_file.get().strip()),
                ("Local State", self.local_state_file.get().strip()),
                ("Preferences", self.preferences_file.get().strip()),
                ("config.lockfile", os.path.join(self.base_dir.get().strip(), "lockfile") if self.base_dir.get().strip() else ""),
            ]
            for label, path in mapping:
                self._add_structured_item(items, label, path)
        elif which == "storage":
            mapping = [
                ("QuotaManager (SQLite)", self.quota_manager_file.get().strip()),
                ("SharedStorage (SQLite)", self.sharedstorage_file.get().strip()),
                ("DIPS (SQLite)", self.dips_file.get().strip()),
            ]
            for label, path in mapping:
                self._add_structured_item(items, label, path)
            pa_dir = self.privateaggregation_dir.get().strip()
            if pa_dir:
                self._add_structured_item(items, "PrivateAggregation", pa_dir, allow_directory=True)
        elif which == "registry":
            for key, base_label, root_name, base_path, pattern, multi in self._registry_defs:
                matches = self._list_registry_matches(root_name, base_path, pattern, multi)
                if not matches:
                    continue
                if multi and len(matches) > 1:
                    for full in matches:
                        suffix = full.split('\\')[-1]
                        self._add_structured_item(items, f"{base_label}: {suffix}", full, kind="registry")
                else:
                    self._add_structured_item(items, base_label, matches[0], kind="registry")
        return items

    def _add_structured_item(self, items, label: str, path: str, allow_directory: bool = False, kind: str = "file", max_entries: Optional[int] = None):
        if not path:
            return
        if kind == "registry":
            items.append({"label": label, "path": path, "kind": "registry"})
            return
        if os.path.isfile(path):
            items.append({"label": label, "path": path, "kind": "file"})
        elif allow_directory and os.path.isdir(path):
            try:
                entries = sorted(os.listdir(path))
            except Exception:
                entries = []
            for idx, name in enumerate(entries):
                if max_entries is not None and idx >= max_entries:
                    break
                sub_path = os.path.join(path, name)
                if os.path.isfile(sub_path):
                    items.append({"label": f"{label}/{name}", "path": sub_path, "kind": "file"})

    def _preview_structured_entry(self, record: dict) -> str:
        kind = record.get("kind", "file")
        if kind == "registry":
            return self._preview_registry(record.get("path", ""))
        return self._preview_file(record.get("path", ""))

    def _preview_file(self, path: str) -> str:
        if not path or not os.path.exists(path):
            return "[Datei nicht gefunden]"
        try:
            if self._is_sqlite(path):
                return self._preview_sqlite(path)
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            try:
                obj = json.loads(text)
                return json.dumps(obj, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                pass
            enc, content = safe_read_text(path, max_bytes=2 * 1024 * 1024)
            return f"[encoding={enc}]\n{content}"
        except Exception as ex:
            return f"[Fehler beim Lesen: {ex}]"

    def _preview_registry(self, path: str) -> str:
        if not path:
            return "[Registry-Key nicht gefunden]"
        parts = path.split("\\", 1)
        if len(parts) != 2:
            return "[Ungueltiger Registry-Pfad]"
        root = self._registry_roots().get(parts[0].upper())
        if not root:
            return "[Unbekannter Registry-Root]"
        sub_path = parts[1]
        try:
            with winreg.OpenKey(root, sub_path, 0, winreg.KEY_READ) as key:
                info = winreg.QueryInfoKey(key)
                lines = [f"[{path}]", ""]
                for idx in range(info[1]):
                    value_name, value_data, value_type = winreg.EnumValue(key, idx)
                    value_name = value_name or "(Default)"
                    lines.append(f"{value_name} = {value_data!r} ({self._registry_type_name(value_type)})")
                if info[0]:
                    lines.append("")
                    lines.append("Subkeys:")
                    for idx in range(info[0]):
                        sub = winreg.EnumKey(key, idx)
                        lines.append(f"  {sub}")
                return "\n".join(lines) if lines else "[Keine Werte]"
        except FileNotFoundError:
            return "[Registry-Key nicht gefunden]"
        except OSError as ex:
            return f"[Fehler beim Lesen: {ex}]"

    @staticmethod
    def _registry_roots() -> dict:
        return {
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
            "HKCC": winreg.HKEY_CURRENT_CONFIG,
        }

    @staticmethod
    def _registry_type_name(value_type: int) -> str:
        mapping = {
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_QWORD: "REG_QWORD",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
            winreg.REG_NONE: "REG_NONE",
        }
        return mapping.get(value_type, f"TYPE_{value_type}")

    def _list_registry_matches(self, root_name: str, base_path: str, pattern: Optional[str], multi: bool) -> List[str]:
        roots = self._registry_roots()
        root = roots.get(root_name.upper())
        if not root:
            return []
        try:
            with winreg.OpenKey(root, base_path, 0, winreg.KEY_READ) as key:
                if pattern:
                    matches: List[str] = []
                    info = winreg.QueryInfoKey(key)
                    pattern_lower = pattern.lower()
                    for idx in range(info[0]):
                        sub = winreg.EnumKey(key, idx)
                        sub_lower = sub.lower()
                        if multi:
                            if sub_lower.startswith(pattern_lower):
                                matches.append(f"{root_name}\\{base_path}\\{sub}")
                        else:
                            if sub_lower == pattern_lower or sub_lower.startswith(pattern_lower):
                                matches.append(f"{root_name}\\{base_path}\\{sub}")
                    matches.sort(reverse=True)
                    return matches
                return [f"{root_name}\\{base_path}"]
        except FileNotFoundError:
            return []
        except OSError:
            return []

    def _read_json_pretty(self, path: str) -> str:
        if not path or not os.path.isfile(path):
            return "[Datei nicht gefunden]"
        try:
            data = Path(path).read_text(encoding="utf-8", errors="replace")
            if not data.strip():
                return "[Datei leer]"
            obj = json.loads(data)
            return json.dumps(obj, indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return data
        except Exception as ex:
            return f"[Fehler beim Lesen: {ex}]"

    @staticmethod
    def _is_sqlite(path: str) -> bool:
        try:
            with open(path, "rb") as fh:
                return fh.read(16) == b"SQLite format 3\x00"
        except Exception:
            return False

    def _preview_sqlite(self, path: str, row_limit: int = 25) -> str:
        lock_suffixes = ["-journal", "-wal", "-shm"]
        active_locks = [p for p in (path + suffix for suffix in lock_suffixes) if os.path.exists(p)]
        if active_locks:
            names = ", ".join(os.path.basename(p) for p in active_locks) or "Lock-Dateien"
            return f"[SQLite gesperrt ({names}). Bitte Anwendung schliessen und erneut versuchen.]"
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as ex:
            return f"[SQLite konnte nicht geoeffnet werden: {ex}]"
        try:
            tables = [
                row["name"] if isinstance(row, sqlite3.Row) else row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            ]
            if not tables:
                return "[Keine Tabellen gefunden]"
            lines = []
            for table in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                lines.append(f"== Tabelle: {table} ==")
                try:
                    cols = conn.execute(f"PRAGMA table_info({quoted})").fetchall()
                    if cols:
                        col_names = [
                            (col["name"] if isinstance(col, sqlite3.Row) else col[1])
                            for col in cols
                        ]
                        lines.append("Spalten: " + ", ".join(col_names))
                except sqlite3.Error as ex:
                    lines.append(f"[Spalten konnten nicht gelesen werden: {ex}]")
                try:
                    rows = conn.execute(f"SELECT * FROM {quoted} LIMIT {row_limit}").fetchall()
                    if not rows:
                        lines.append("(Keine Zeilen)")
                    else:
                        for row in rows:
                            if isinstance(row, sqlite3.Row):
                                lines.append(json.dumps(dict(row), ensure_ascii=False))
                            else:
                                lines.append(str(row))
                        if len(rows) == row_limit:
                            lines.append(f"... (erste {row_limit} Zeilen)")
                except sqlite3.Error as ex:
                    lines.append(f"[Zeilen konnten nicht gelesen werden: {ex}]")
                lines.append("")
            return "\n".join(lines).strip()
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _read_file_for_search(self, path: str) -> str:
        if not path or not os.path.exists(path):
            return ""
        if self._is_sqlite(path):
            return self._preview_sqlite(path, row_limit=100)
        try:
            _, content = safe_read_text(path, max_bytes=2 * 1024 * 1024)
            return content
        except Exception:
            return ""

    def _export_text_widget(self, widget, filename: str):
        if widget is None:
            messagebox.showinfo("Export", "Keine Ansicht ausgewaehlt.")
            return
        data = widget.get("1.0","end")
        if not data.strip():
            messagebox.showinfo("Export", "Keine Daten im Viewer.")
            return
        out = Path(DEFAULT_EXPORT_DIR) / filename
        out.write_text(data, encoding="utf-8", errors="replace")
        messagebox.showinfo("Export", f"Gespeichert: {out}")

    # --- MCP Auto-Search ---
    def run_mcp_auto_search(self):
        out_path = Path(DEFAULT_EXPORT_DIR) / "mcp_report.txt"
        self.status_var.set("MCP Auto-Suche laeuft ...")
        messagebox.showinfo("MCP Auto-Suche", "Die Suche laeuft im Hintergrund. Das Ergebnis wird in 'outputs/mcp_report.txt' gespeichert.")

        logs_dir = self.logs_dir.get().strip()
        idx_dir = self.indexeddb_dir.get().strip()
        ses_dir = self.session_dir.get().strip()
        ls_dir = self.localstorage_dir.get().strip()

        def worker():
            try:
                report_lines = []
                report_lines.append("=== ChatGPT Desktop Inspector - MCP Auto-Suche ===\n")
                report_lines.append(f"Logs: {logs_dir}\nIndexedDB: {idx_dir}\nSession: {ses_dir}\nLocalStorage: {ls_dir}\n\n")

                # 1) Logs
                report_lines.append("[LOGS]\n")
                log_files = list_log_files(logs_dir)
                if not log_files:
                    report_lines.append("(keine Logdateien gefunden)\n\n")
                else:
                    for p in log_files:
                        enc, content = safe_read_text(p)
                        hits = search_lines(content.splitlines(), DEFAULT_MCP_PATTERNS)
                        report_lines.append(f"-- {os.path.basename(p)} ({enc}), Treffer: {len(hits)}\n")
                        if hits:
                            report_lines.extend([h+"\n" for h in hits[:1000]])
                        report_lines.append("\n")

                # 2) Session Storage - Strings
                report_lines.append("[SESSION STORAGE - Strings] \n")
                ses_text, ses_bin = list_candidate_files_in_leveldb(ses_dir)
                for p in ses_bin[:50]:
                    try:
                        _, strings = extract_strings_from_file(p, min_len=8, include_utf16le=True, max_mb=16)
                        hits = search_lines(strings, DEFAULT_MCP_PATTERNS)
                        if hits:
                            report_lines.append(f"-- {os.path.basename(p)}: {len(hits)} Treffer\n")
                            report_lines.extend([h+"\n" for h in hits[:200]])
                    except Exception as ex:
                        report_lines.append(f"-- {os.path.basename(p)}: Fehler {ex}\n")
                report_lines.append("\n")

                # 3) IndexedDB - Strings
                report_lines.append("[INDEXEDDB - Strings] \n")
                idx_text, idx_bin = list_candidate_files_in_leveldb(idx_dir)
                for p in idx_bin[:50]:
                    try:
                        _, strings = extract_strings_from_file(p, min_len=8, include_utf16le=True, max_mb=16)
                        hits = search_lines(strings, DEFAULT_MCP_PATTERNS)
                        if hits:
                            report_lines.append(f"-- {os.path.basename(p)}: {len(hits)} Treffer\n")
                            report_lines.extend([h+"\n" for h in hits[:200]])
                    except Exception as ex:
                        report_lines.append(f"-- {os.path.basename(p)}: Fehler {ex}\n")
                report_lines.append("\n")

                # 4) Local Storage - Strings
                report_lines.append("[LOCAL STORAGE - Strings] \n")
                ls_text, ls_bin = list_candidate_files_in_leveldb(ls_dir)
                for p in ls_bin[:50]:
                    try:
                        _, strings = extract_strings_from_file(p, min_len=8, include_utf16le=True, max_mb=16)
                        hits = search_lines(strings, DEFAULT_MCP_PATTERNS)
                        if hits:
                            report_lines.append(f"-- {os.path.basename(p)}: {len(hits)} Treffer\n")
                            report_lines.extend([h+"\n" for h in hits[:200]])
                    except Exception as ex:
                        report_lines.append(f"-- {os.path.basename(p)}: Fehler {ex}\n")
                report_lines.append("\n")

                def add_file_group(title: str, entries):
                    report_lines.append(f"{title}\n")
                    found_any = False
                    for label, path in entries:
                        data = self._read_file_for_search(path)
                        if not data:
                            continue
                        hits = search_lines(data.splitlines(), DEFAULT_MCP_PATTERNS)
                        report_lines.append(f"-- {label}: {len(hits)} Treffer\n")
                        if hits:
                            found_any = True
                            report_lines.extend([h + "\n" for h in hits[:200]])
                        report_lines.append("\n")
                    if not entries:
                        report_lines.append("(keine Dateien gefunden)\n\n")
                    elif not found_any:
                        report_lines.append("(keine Treffer)\n\n")

                def search_strings_in_files(title: str, paths, use_extract: bool, max_mb: int = 8):
                    paths = list(paths)
                    report_lines.append(f"{title}\n")
                    if not paths:
                        report_lines.append("(keine Dateien gefunden)\n\n")
                        return
                    hits_found = False
                    for path in paths:
                        path_str = str(path)
                        try:
                            if use_extract:
                                _, strings = extract_strings_from_file(path_str, min_len=8, include_utf16le=True, max_mb=max_mb)
                                hits = search_lines(strings, DEFAULT_MCP_PATTERNS)
                            else:
                                _enc, content = safe_read_text(path_str, max_bytes=2 * 1024 * 1024)
                                hits = search_lines(content.splitlines(), DEFAULT_MCP_PATTERNS)
                        except Exception as ex:
                            report_lines.append(f"-- {os.path.basename(path_str)}: Fehler {ex}\n\n")
                            continue
                        report_lines.append(f"-- {os.path.basename(path_str)}: {len(hits)} Treffer\n")
                        if hits:
                            hits_found = True
                            report_lines.extend([h + "\n" for h in hits[:200]])
                        report_lines.append("\n")
                    if not hits_found:
                        report_lines.append("(keine Treffer)\n\n")

                cache_dir = self.cache_data_dir.get().strip()
                if cache_dir and os.path.isdir(cache_dir):
                    data_paths = sorted(
                        Path(cache_dir).glob("data*"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True
                    )[:8]
                    search_strings_in_files("[CACHE DATA - Strings]", data_paths, use_extract=True, max_mb=8)
                else:
                    report_lines.append("[CACHE DATA - Strings]\n(Verzeichnis nicht gefunden)\n\n")

                code_dir = self.code_cache_dir.get().strip()
                if code_dir and os.path.isdir(code_dir):
                    js_paths = sorted(
                        Path(code_dir).rglob("*.js"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True
                    )[:20]
                    search_strings_in_files("[CODE CACHE - Text]", js_paths, use_extract=False)
                else:
                    report_lines.append("[CODE CACHE - Text]\n(Verzeichnis nicht gefunden)\n\n")

                install_root = self.package_root_dir.get().strip()
                install_text_paths = []
                install_binary_paths = []
                if install_root and os.path.isdir(install_root):
                    pkg = Path(install_root)
                    for rel in [
                        ("AppxManifest.xml", False),
                        (("AppxMetadata", "AppxBlockMap.xml"), False),
                        ("priconfig.xml", False),
                        (("app", "LICENSE"), False),
                        (("app", "LICENSES.chromium.html"), False),
                        (("app", "version"), False),
                    ]:
                        parts, is_binary = (rel, False) if isinstance(rel, str) else rel
                        if isinstance(parts, tuple):
                            target = pkg.joinpath(*parts)
                        else:
                            target = pkg / parts
                        if target.exists():
                            install_text_paths.append(target)
                    for rel in [
                        ("settings", "settings.dat"),
                    ]:
                        target = pkg.joinpath(*rel)
                        if target.exists():
                            install_text_paths.append(target)
                    for rel in [
                        (("app", "resources.pak"), True),
                        (("app", "resources", "app.asar"), True),
                        (("app", "snapshot_blob.bin"), True),
                        (("app", "v8_context_snapshot.bin"), True),
                    ]:
                        parts, _ = rel
                        target = pkg.joinpath(*parts)
                        if target.exists():
                            install_binary_paths.append(target)
                if install_text_paths:
                    search_strings_in_files("[INSTALLATION - Text]", install_text_paths, use_extract=False)
                else:
                    report_lines.append("[INSTALLATION - Text]\n(keine Dateien gefunden)\n\n")
                if install_binary_paths:
                    search_strings_in_files("[INSTALLATION - Strings]", install_binary_paths, use_extract=True, max_mb=6)
                else:
                    report_lines.append("[INSTALLATION - Strings]\n(keine Dateien gefunden)\n\n")

                network_dir = self.network_dir.get().strip()
                if network_dir and os.path.isdir(network_dir):
                    add_file_group(
                        "[NETWORK / SECURITY]",
                        [
                            ("Network Persistent State", os.path.join(network_dir, "Network Persistent State")),
                            ("TransportSecurity", os.path.join(network_dir, "TransportSecurity")),
                            ("Cookies (SQLite)", os.path.join(network_dir, "Cookies")),
                            ("Trust Tokens (SQLite)", os.path.join(network_dir, "Trust Tokens")),
                        ],
                    )

                add_file_group(
                    "[CONFIGURATION]",
                    [
                        ("config.json", self.config_file.get().strip()),
                        ("Local State", self.local_state_file.get().strip()),
                        ("Preferences", self.preferences_file.get().strip()),
                    ],
                )

                add_file_group(
                    "[STORAGE / SQLITE]",
                    [
                        ("QuotaManager", self.quota_manager_file.get().strip()),
                        ("SharedStorage", self.sharedstorage_file.get().strip()),
                        ("DIPS", self.dips_file.get().strip()),
                    ],
                )

                sentry_dir = self.sentry_dir.get().strip()
                sentry_entries = []
                if sentry_dir and os.path.isdir(sentry_dir):
                    sentry_entries.append(("sentry/session.json", os.path.join(sentry_dir, "session.json")))
                    sentry_entries.append(("sentry/queue/queue-v2.json", os.path.join(sentry_dir, "queue", "queue-v2.json")))
                add_file_group("[TELEMETRY]", sentry_entries)

                out_path.write_text("".join(report_lines), encoding="utf-8", errors="replace")
                self.status_var.set(f"Auto-Suche fertig. Report: {out_path}")
            except Exception as ex:
                self.status_var.set(f"Fehler: {ex}")
                messagebox.showerror("Fehler", str(ex))

        threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    app = InspectorApp()
    app.mainloop()


