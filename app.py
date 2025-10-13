import os
import threading
from pathlib import Path
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
        self.status_var = tk.StringVar(value="Bereit")

        # Data caches
        self.idx_text = []; self.idx_bin = []
        self.ses_text = []; self.ses_bin = []
        self.ls_text = []; self.ls_bin = []
        self.logs_files = []

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self); top.pack(fill="x", padx=8, pady=8)

        row0 = ttk.Frame(top); row0.pack(fill="x", pady=(0,4))
        ttk.Label(row0, text="Root (optional):").pack(side="left")
        ttk.Entry(row0, textvariable=self.root_dir, width=80).pack(side="left", padx=6)
        ttk.Button(row0, text="Root wählen", command=lambda:self._choose_dir(self.root_dir)).pack(side="left")
        ttk.Button(row0, text="Auto finden (alle)", command=self.auto_find_all).pack(side="left", padx=6)

        row1 = ttk.Frame(top); row1.pack(fill="x", pady=(0,4))
        ttk.Label(row1, text="Logs:").pack(side="left")
        ttk.Entry(row1, textvariable=self.logs_dir, width=85).pack(side="left", padx=6)
        ttk.Button(row1, text="Ordner wählen", command=lambda:self._choose_dir(self.logs_dir)).pack(side="left")
        ttk.Button(row1, text="Neu scannen", command=self.scan_logs).pack(side="left", padx=6)

        row2 = ttk.Frame(top); row2.pack(fill="x", pady=(0,4))
        ttk.Label(row2, text="IndexedDB:").pack(side="left")
        ttk.Entry(row2, textvariable=self.indexeddb_dir, width=80).pack(side="left", padx=6)
        ttk.Button(row2, text="Ordner wählen", command=lambda:self._choose_dir(self.indexeddb_dir)).pack(side="left")
        ttk.Button(row2, text="Neu scannen", command=self.scan_indexeddb).pack(side="left", padx=6)

        row3 = ttk.Frame(top); row3.pack(fill="x", pady=(0,4))
        ttk.Label(row3, text="Session Storage:").pack(side="left")
        ttk.Entry(row3, textvariable=self.session_dir, width=78).pack(side="left", padx=6)
        ttk.Button(row3, text="Ordner wählen", command=lambda:self._choose_dir(self.session_dir)).pack(side="left")
        ttk.Button(row3, text="Neu scannen", command=self.scan_session).pack(side="left", padx=6)

        row4 = ttk.Frame(top); row4.pack(fill="x", pady=(0,4))
        ttk.Label(row4, text="Local Storage (leveldb):").pack(side="left")
        ttk.Entry(row4, textvariable=self.localstorage_dir, width=70).pack(side="left", padx=6)
        ttk.Button(row4, text="Ordner wählen", command=lambda:self._choose_dir(self.localstorage_dir)).pack(side="left")
        ttk.Button(row4, text="Neu scannen", command=self.scan_localstorage).pack(side="left", padx=6)

        row5 = ttk.Frame(top); row5.pack(fill="x", pady=(4,0))
        ttk.Button(row5, text="🔎 MCP Auto‑Suche (Report)", command=self.run_mcp_auto_search).pack(side="left")

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

        # Status bar
        sb = ttk.Frame(self); sb.pack(fill="x")
        ttk.Label(sb, textvariable=self.status_var, anchor="w").pack(fill="x")

        Path(DEFAULT_EXPORT_DIR).mkdir(exist_ok=True)

        # Initial scans
        self.scan_logs(); self.scan_indexeddb(); self.scan_session(); self.scan_localstorage()

    def _choose_dir(self, var):
        p = filedialog.askdirectory(title="Ordner auswählen")
        if p:
            var.set(p)

    def auto_find_all(self):
        root = self.root_dir.get().strip()
        if root:
            found = autodetect_from_root(root)
        else:
            found = detect_default_paths()
        if found.get("logs") and not self.logs_dir.get().strip():
            self.logs_dir.set(found["logs"])
        if found.get("indexeddb") and not self.indexeddb_dir.get().strip():
            self.indexeddb_dir.set(found["indexeddb"])
        if found.get("session") and not self.session_dir.get().strip():
            self.session_dir.set(found["session"])
        if found.get("localstorage") and not self.localstorage_dir.get().strip():
            self.localstorage_dir.set(found["localstorage"])
        self.status_var.set(f"Auto‑Erkennung: Logs={bool(found.get('logs'))}, IndexedDB={bool(found.get('indexeddb'))}, Session={bool(found.get('session'))}, LocalStorage={bool(found.get('localstorage'))}")
        self.scan_logs(); self.scan_indexeddb(); self.scan_session(); self.scan_localstorage()

    # --- Logs Tab ---
    def _build_tab_logs(self, parent):
        top = ttk.Frame(parent); top.pack(fill="x")
        self.log_search_var = tk.StringVar(value="")
        ttk.Label(top, text="Suchen/Filtern:").pack(side="left")
        ttk.Entry(top, textvariable=self.log_search_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Anwenden", command=self.apply_log_filter).pack(side="left")
        ttk.Button(top, text="Zurücksetzen", command=self.reset_log_filter).pack(side="left", padx=4)
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
        minlen_label = ttk.Label(top, text="Min. Länge:"); minlen_label.pack(side="left")
        minlen_var = tk.IntVar(value=8)
        ttk.Entry(top, textvariable=minlen_var, width=6).pack(side="left", padx=(4,10))
        utf16_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="UTF-16LE erkennen", variable=utf16_var).pack(side="left")
        ttk.Label(top, text="Max. MB (optional):").pack(side="left", padx=(10,0))
        maxmb_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=maxmb_var, width=6).pack(side="left", padx=(4,10))
        ttk.Button(top, text="Strings scannen", command=lambda:self.scan_strings(which, minlen_var, utf16_var, maxmb_var)).pack(side="left")
        ttk.Button(top, text="Export Strings", command=lambda:self.export_current_strings(which)).pack(side="left", padx=6)

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
        ttk.Button(sb, text="Zurücksetzen", command=lambda:self.reset_leveldb_filter(which)).pack(side="left", padx=4)

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
        self.status_var.set(f"IndexedDB: {len(self.idx_text)} Text, {len(self.idx_bin)} Binärdateien.")

    def scan_session(self):
        folder = self.session_dir.get().strip()
        self.ses_text, self.ses_bin = list_candidate_files_in_leveldb(folder)
        self.ses_list.delete(0, "end")
        for p in self.ses_text + self.ses_bin:
            self.ses_list.insert("end", os.path.basename(p))
        self.ses_textview.delete("1.0","end")
        self.status_var.set(f"Session Storage: {len(self.ses_text)} Text, {len(self.ses_bin)} Binärdateien.")

    def scan_localstorage(self):
        folder = self.localstorage_dir.get().strip()
        self.ls_text, self.ls_bin = list_candidate_files_in_leveldb(folder)
        self.ls_list.delete(0, "end")
        for p in self.ls_text + self.ls_bin:
            self.ls_list.insert("end", os.path.basename(p))
        self.ls_textview.delete("1.0","end")
        self.status_var.set(f"Local Storage: {len(self.ls_text)} Text, {len(self.ls_bin)} Binärdateien.")

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
            tv.delete("1.0","end")
            tv.insert("1.0", "[Binärdatei ausgewählt. Bitte 'Strings scannen' verwenden.]")

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
            messagebox.showinfo("Export", "Keine Datei ausgewählt.")
            return
        idx = sel[0]
        if idx >= len(text_files):
            messagebox.showinfo("Export", "Binärdatei: Bitte 'Export Strings' benutzen.")
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
            messagebox.showinfo("Hinweis", "Bitte zuerst eine Binärdatei auswählen.")
            return
        idx = sel[0]
        if idx < len(text_files):
            messagebox.showinfo("Hinweis", "Textdatei ausgewählt. Bitte eine Binärdatei (.ldb/.log/.sst) wählen.")
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
        tv.insert("1.0", "[Bitte warten – Strings werden extrahiert ...]")
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
            messagebox.showinfo("Export", "Keine Binärdatei ausgewählt.")
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

    # --- MCP Auto-Search ---
    def run_mcp_auto_search(self):
        out_path = Path(DEFAULT_EXPORT_DIR) / "mcp_report.txt"
        self.status_var.set("MCP-Auto-Suche läuft ...")
        messagebox.showinfo("MCP Auto‑Suche", "Die Suche läuft im Hintergrund. Das Ergebnis wird in 'outputs/mcp_report.txt' gespeichert.")

        logs_dir = self.logs_dir.get().strip()
        idx_dir = self.indexeddb_dir.get().strip()
        ses_dir = self.session_dir.get().strip()
        ls_dir = self.localstorage_dir.get().strip()

        def worker():
            try:
                report_lines = []
                report_lines.append("=== ChatGPT Desktop Inspector – MCP Auto‑Suche ===\n")
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

                # 2) Session Storage – Strings
                report_lines.append("[SESSION STORAGE – Strings] \n")
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

                # 3) IndexedDB – Strings
                report_lines.append("[INDEXEDDB – Strings] \n")
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

                # 4) Local Storage – Strings
                report_lines.append("[LOCAL STORAGE – Strings] \n")
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

                out_path.write_text("".join(report_lines), encoding="utf-8", errors="replace")
                self.status_var.set(f"Auto‑Suche fertig. Report: {out_path}")
            except Exception as ex:
                self.status_var.set(f"Fehler: {ex}")
                messagebox.showerror("Fehler", str(ex))

        threading.Thread(target=worker, daemon=True).start()

if __name__ == "__main__":
    app = InspectorApp()
    app.mainloop()
