import os
import re
from pathlib import Path
from typing import Tuple, List, Optional, Iterable

try:
    import chardet  # type: ignore
except Exception:
    chardet = None  # optional

PRINTABLE_ASCII = set(range(32, 127))
PRINTABLE_WITH_WS = PRINTABLE_ASCII | {9, 10, 11, 12, 13}

def _sanitize_extracted_string(s: str) -> str:
    # Replace carriage-return variants and control whitespace by readable separators
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\t", "    ").replace("\v", "\n").replace("\f", "\n")
    # Collapse overly long newline runs to keep view compact
    while "\n\n\n" in s:
        s = s.replace("\n\n\n", "\n\n")
    return s.strip()

def safe_read_text(path: str, max_bytes: Optional[int] = None) -> Tuple[str, str]:
    p = Path(path)
    data = p.read_bytes() if max_bytes is None else p.read_bytes()[:max_bytes]
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return ("utf-16", data.decode("utf-16"))
        except Exception:
            pass
    try:
        return ("utf-8", data.decode("utf-8"))
    except Exception:
        pass
    if chardet is not None:
        try:
            det = chardet.detect(data or b"")
            enc = det.get("encoding") or "latin-1"
            return (enc, data.decode(enc, errors="replace"))
        except Exception:
            pass
    return ("latin-1", data.decode("latin-1", errors="replace"))

def _ascii_strings_from_bytes(b: bytes, min_len: int) -> List[str]:
    out: List[str] = []
    acc: List[int] = []
    def flush():
        if len(acc) >= min_len:
            out.append(bytes(acc).decode("ascii", errors="ignore"))
        acc.clear()
    for ch in b:
        if ch in PRINTABLE_WITH_WS:
            acc.append(ch)
        else:
            if acc:
                flush()
    if acc:
        flush()
    return out

def _utf16le_strings_from_bytes(b: bytes, min_len: int) -> List[str]:
    out: List[str] = []
    run: List[int] = []
    i = 0
    while i + 1 < len(b):
        lo = b[i]
        hi = b[i+1]
        if hi == 0x00 and (lo in PRINTABLE_WITH_WS):
            run.append(lo)
        else:
            if len(run) >= min_len:
                out.append(bytes(run).decode("ascii", errors="ignore"))
            run = []
        i += 2
    if len(run) >= min_len:
        out.append(bytes(run).decode("ascii", errors="ignore"))
    return out

def extract_strings_from_file(path: str, min_len: int = 8, include_utf16le: bool = True, max_mb: Optional[int] = None):
    size = os.path.getsize(path)
    total = 0
    strings_all: List[str] = []
    chunk_size = 1024 * 1024
    limit_bytes = None if max_mb is None else max_mb * 1024 * 1024
    with open(path, "rb") as f:
        while True:
            if limit_bytes is not None and total >= limit_bytes:
                break
            to_read = chunk_size if limit_bytes is None else min(chunk_size, limit_bytes - total)
            data = f.read(to_read)
            if not data:
                break
            total += len(data)
            strings_all.extend(_ascii_strings_from_bytes(data, min_len))
            if include_utf16le:
                strings_all.extend(_utf16le_strings_from_bytes(data, min_len))
    seen = set()
    unique = []
    for s in strings_all:
        if s not in seen:
            seen.add(s)
            cleaned = _sanitize_extracted_string(s)
            if cleaned:
                unique.append(cleaned)
    return (total, unique)

def list_candidate_files_in_leveldb(folder: str):
    text_files = []
    bin_files = []
    if not folder or not os.path.isdir(folder):
        return (text_files, bin_files)
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        up = name.upper()
        if up == "CURRENT" or up.startswith("LOG") or up.startswith("MANIFEST"):
            text_files.append(path)
        elif name.lower().endswith((".ldb", ".log", ".sst", ".db")):
            bin_files.append(path)
    text_files.sort()
    bin_files.sort()
    return (text_files, bin_files)

def list_log_files(folder: str) -> List[str]:
    out: List[str] = []
    if not folder or not os.path.isdir(folder):
        return out
    for name in os.listdir(folder):
        if name.lower().endswith((".log", ".txt")):
            p = os.path.join(folder, name)
            if os.path.isfile(p):
                out.append(p)
    out.sort()
    return out

def detect_default_paths() -> dict:
    paths = {"indexeddb":"", "session":"", "logs":"", "localstorage":""}
    la = os.getenv("LOCALAPPDATA", "")
    ra = os.getenv("APPDATA", "")
    # Microsoft Store App
    store_root = os.path.join(la, "Packages")
    if os.path.isdir(store_root):
        candidates = [d for d in os.listdir(store_root) if d.startswith("OpenAI.ChatGPT-Desktop_")]
        candidates.sort(reverse=True)
        for c in candidates:
            base = os.path.join(store_root, c, "LocalCache", "Roaming", "ChatGPT")
            idx = os.path.join(base, "IndexedDB")
            ses = os.path.join(base, "Session Storage")
            lg = os.path.join(base, "Logs")
            ls = os.path.join(base, "Local Storage", "leveldb")
            # choose best indexeddb path
            idx_final = choose_indexeddb(idx)
            if not paths["indexeddb"] and idx_final:
                paths["indexeddb"] = idx_final
            if not paths["session"] and os.path.isdir(ses):
                paths["session"] = ses
            if not paths["logs"] and os.path.isdir(lg):
                paths["logs"] = lg
            if not paths["localstorage"] and os.path.isdir(ls):
                paths["localstorage"] = ls
            if all(paths.values()):
                break
    # Classic EXE
    classic = os.path.join(ra, "ChatGPT")
    if os.path.isdir(classic):
        idx2 = os.path.join(classic, "IndexedDB")
        ses2 = os.path.join(classic, "Session Storage")
        lg2 = os.path.join(classic, "Logs")
        ls2 = os.path.join(classic, "Local Storage", "leveldb")
        idx2_final = choose_indexeddb(idx2)
        if not paths["indexeddb"] and idx2_final:
            paths["indexeddb"] = idx2_final
        if not paths["session"] and os.path.isdir(ses2):
            paths["session"] = ses2
        if not paths["logs"] and os.path.isdir(lg2):
            paths["logs"] = lg2
        if not paths["localstorage"] and os.path.isdir(ls2):
            paths["localstorage"] = ls2
    return paths

def choose_indexeddb(indexeddb_root: str) -> Optional[str]:
    # find "*.indexeddb.leveldb" under root
    if not indexeddb_root or not os.path.isdir(indexeddb_root):
        return None
    candidates = []
    for name in os.listdir(indexeddb_root):
        p = os.path.join(indexeddb_root, name)
        if os.path.isdir(p) and name.lower().endswith(".indexeddb.leveldb"):
            candidates.append(p)
    if not candidates:
        return None
    # prefer https_chatgpt.com_0.indexeddb.leveldb
    preferred = [c for c in candidates if os.path.basename(c).startswith("https_chatgpt.com_")]
    if preferred:
        return preferred[0]
    # else pick the one with most files
    candidates.sort(key=lambda d: len(os.listdir(d)), reverse=True)
    return candidates[0]

def autodetect_from_root(root: str) -> dict:
    # Search recursively (depth 5) for patterns
    found = {"indexeddb":"", "session":"", "logs":"", "localstorage":""}
    if not root or not os.path.isdir(root):
        return found
    max_depth = 5
    for cur_root, dirs, files in os.walk(root):
        depth = cur_root[len(root):].count(os.sep)
        if depth > max_depth:
            dirs[:] = []
            continue
        bn = os.path.basename(cur_root).lower()
        # Logs
        if bn == "logs" and not found["logs"]:
            found["logs"] = cur_root
        # Session Storage
        if bn == "session storage" and not found["session"]:
            found["session"] = cur_root
        # Local Storage leveldb
        if bn == "leveldb" and os.path.basename(os.path.dirname(cur_root)).lower() == "local storage" and not found["localstorage"]:
            found["localstorage"] = cur_root
        # IndexedDB candidate folders
        if bn.endswith(".indexeddb.leveldb") and not found["indexeddb"]:
            found["indexeddb"] = cur_root
        # Short-circuit if all found
        if all(found.values()):
            break
    return found

DEFAULT_MCP_PATTERNS = [
    r"\bmcp\b", r"model[-_ ]?control", r"sidetron",
    r"websocket", r"\bws:\/\/", r"\bwss:\/\/", r"socket", r"handshake",
    r"tls", r"ssl", r"certificate", r"cert", r"\berr_", r"net::err", r"http\s*\d{3}",
    r"403", r"401", r"407", r"proxy", r"tunnel", r"mitm", r"csp", r"cors",
    r"timeout", r"timed out", r"econnreset", r"etimedout", r"connection refused", r"enotfound",
]

def search_lines(lines: Iterable[str], patterns: List[str]) -> List[str]:
    res: List[str] = []
    regexes = [re.compile(pat, re.IGNORECASE) for pat in patterns]
    for i, ln in enumerate(lines, start=1):
        for rgx in regexes:
            if rgx.search(ln):
                res.append(f"{i:06d}: {ln.rstrip()}".rstrip())
                break
    return res
