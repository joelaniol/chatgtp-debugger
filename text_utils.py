import json
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

def _format_json_if_possible(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return text
    if not ((stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]"))):
        return text
    try:
        obj = json.loads(stripped)
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        return text

def _brace_delta(text: str) -> int:
    delta = 0
    in_string = False
    quote_char = ""
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote_char:
                in_string = False
        else:
            if ch in ("\"", "'"):
                in_string = True
                quote_char = ch
            elif ch in "{[":
                delta += 1
            elif ch in "]}":
                delta -= 1
    return delta

def _merge_json_chunks(strings: List[str]) -> List[str]:
    merged: List[str] = []
    buffer: List[str] = []
    depth = 0
    for s in strings:
        trimmed = s.lstrip()
        if not buffer and trimmed.startswith(("{", "[")):
            buffer = [s]
            depth = _brace_delta(s)
            if depth <= 0:
                joined = "\n".join(buffer)
                merged.append(_format_json_if_possible(joined))
                buffer = []
                depth = 0
            continue
        if buffer:
            buffer.append(s)
            depth += _brace_delta(s)
            if depth <= 0:
                joined = "\n".join(buffer)
                merged.append(_format_json_if_possible(joined))
                buffer = []
                depth = 0
            continue
        merged.append(_format_json_if_possible(s))
    if buffer:
        joined = "\n".join(buffer)
        merged.append(_format_json_if_possible(joined))
    return merged

def _postprocess_strings(strings: List[str]) -> List[str]:
    if not strings:
        return strings
    return _merge_json_chunks(strings)

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
    cleaned_strings: List[str] = []
    for s in strings_all:
        cleaned = _sanitize_extracted_string(s)
        if cleaned:
            cleaned_strings.append(cleaned)
    processed = _postprocess_strings(cleaned_strings)
    seen = set()
    unique = []
    for s in processed:
        if s not in seen:
            seen.add(s)
            unique.append(s)
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
    paths = {
        "indexeddb": "",
        "session": "",
        "logs": "",
        "localstorage": "",
        "network": "",
        "sentry": "",
        "config": "",
        "local_state": "",
        "preferences": "",
        "crashpad": "",
        "sharedstorage": "",
        "quota_manager": "",
        "dips": "",
        "privateaggregation": "",
        "cache_data": "",
        "code_cache": "",
        "settings": "",
        "package_root": "",
        "base": "",
    }

    def try_set_dir(key: str, path: str):
        if path and not paths.get(key) and os.path.isdir(path):
            paths[key] = path

    def try_set_file(key: str, path: str):
        if path and not paths.get(key) and os.path.isfile(path):
            paths[key] = path

    la = os.getenv("LOCALAPPDATA", "")
    ra = os.getenv("APPDATA", "")
    # Microsoft Store App
    store_root = os.path.join(la, "Packages")
    if os.path.isdir(store_root):
        candidates = [d for d in os.listdir(store_root) if d.startswith("OpenAI.ChatGPT-Desktop_")]
        candidates.sort(reverse=True)
        for c in candidates:
            base = os.path.join(store_root, c, "LocalCache", "Roaming", "ChatGPT")
            if not paths.get("base") and os.path.isdir(base):
                paths["base"] = base
            if os.path.isdir(base):
                try:
                    package_root = str(Path(base).parent.parent.parent)
                    try_set_dir("package_root", package_root)
                    try_set_file("settings", os.path.join(package_root, "Settings", "settings.dat"))
                except Exception:
                    pass
                try_set_dir("cache_data", os.path.join(base, "Cache", "Cache_Data"))
                try_set_dir("code_cache", os.path.join(base, "Code Cache"))
            idx = os.path.join(base, "IndexedDB")
            ses = os.path.join(base, "Session Storage")
            lg = os.path.join(base, "Logs")
            ls = os.path.join(base, "Local Storage", "leveldb")
            network_dir = os.path.join(base, "Network")
            sentry_dir = os.path.join(base, "sentry")
            crashpad_dir = os.path.join(base, "Crashpad")
            shared_storage = os.path.join(base, "SharedStorage")
            webstorage = os.path.join(base, "WebStorage")
            dips_file = os.path.join(base, "DIPS")
            private_aggregation = os.path.join(base, "PrivateAggregation")

            # choose best indexeddb path
            idx_final = choose_indexeddb(idx)
            if not paths["indexeddb"] and idx_final:
                paths["indexeddb"] = idx_final
            try_set_dir("session", ses)
            try_set_dir("logs", lg)
            try_set_dir("localstorage", ls)
            try_set_dir("network", network_dir)
            try_set_dir("sentry", sentry_dir)
            try_set_dir("crashpad", crashpad_dir)
            try_set_file("sharedstorage", shared_storage)
            try_set_file("quota_manager", os.path.join(webstorage, "QuotaManager"))
            try_set_file("dips", dips_file)
            try_set_dir("privateaggregation", private_aggregation)
            try_set_file("config", os.path.join(base, "config.json"))
            try_set_file("local_state", os.path.join(base, "Local State"))
            try_set_file("preferences", os.path.join(base, "Preferences"))
            if all(paths.get(k) for k in ("indexeddb", "session", "logs", "localstorage", "network", "sentry")):
                break
    # Classic EXE
    classic = os.path.join(ra, "ChatGPT")
    if os.path.isdir(classic):
        if not paths.get("base"):
            paths["base"] = classic
        idx2 = os.path.join(classic, "IndexedDB")
        ses2 = os.path.join(classic, "Session Storage")
        lg2 = os.path.join(classic, "Logs")
        ls2 = os.path.join(classic, "Local Storage", "leveldb")
        network2 = os.path.join(classic, "Network")
        sentry2 = os.path.join(classic, "sentry")
        crashpad2 = os.path.join(classic, "Crashpad")
        shared_storage2 = os.path.join(classic, "SharedStorage")
        webstorage2 = os.path.join(classic, "WebStorage")
        dips2 = os.path.join(classic, "DIPS")
        private_aggregation2 = os.path.join(classic, "PrivateAggregation")
        idx2_final = choose_indexeddb(idx2)
        if not paths["indexeddb"] and idx2_final:
            paths["indexeddb"] = idx2_final
        try_set_dir("session", ses2)
        try_set_dir("logs", lg2)
        try_set_dir("localstorage", ls2)
        try_set_dir("network", network2)
        try_set_dir("sentry", sentry2)
        try_set_dir("crashpad", crashpad2)
        try_set_file("sharedstorage", shared_storage2)
        try_set_file("quota_manager", os.path.join(webstorage2, "QuotaManager"))
        try_set_file("dips", dips2)
        try_set_dir("privateaggregation", private_aggregation2)
        try_set_file("config", os.path.join(classic, "config.json"))
        try_set_file("local_state", os.path.join(classic, "Local State"))
        try_set_file("preferences", os.path.join(classic, "Preferences"))
        try_set_dir("cache_data", os.path.join(classic, "Cache", "Cache_Data"))
        try_set_dir("code_cache", os.path.join(classic, "Code Cache"))
        try_set_file("settings", os.path.join(classic, "Settings", "settings.dat"))
        try_set_dir("package_root", classic)

    if paths.get("base"):
        base_path = Path(paths["base"])
        try:
            package_root = base_path.parent.parent.parent
        except ValueError:
            package_root = None
        if package_root and package_root.exists():
            try_set_dir("package_root", str(package_root))
            try_set_file("settings", str(package_root / "Settings" / "settings.dat"))
        try_set_dir("cache_data", os.path.join(paths["base"], "Cache", "Cache_Data"))
        try_set_dir("code_cache", os.path.join(paths["base"], "Code Cache"))
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
    found = {
        "indexeddb": "",
        "session": "",
        "logs": "",
        "localstorage": "",
        "network": "",
        "sentry": "",
        "config": "",
        "local_state": "",
        "preferences": "",
        "crashpad": "",
        "sharedstorage": "",
        "quota_manager": "",
        "dips": "",
        "privateaggregation": "",
        "cache_data": "",
        "code_cache": "",
        "settings": "",
        "package_root": "",
        "base": "",
    }
    if not root or not os.path.isdir(root):
        return found
    max_depth = 5
    for cur_root, dirs, files in os.walk(root):
        depth = cur_root[len(root):].count(os.sep)
        if depth > max_depth:
            dirs[:] = []
            continue
        bn = os.path.basename(cur_root).lower()
        if not found["base"]:
            found["base"] = root
        # Logs
        if bn == "logs" and not found["logs"]:
            found["logs"] = cur_root
        # Session Storage
        if bn == "session storage" and not found["session"]:
            found["session"] = cur_root
        # Local Storage leveldb
        if bn == "leveldb" and os.path.basename(os.path.dirname(cur_root)).lower() == "local storage" and not found["localstorage"]:
            found["localstorage"] = cur_root
        # Network directory
        if bn == "network" and not found["network"]:
            found["network"] = cur_root
        # Sentry directory
        if bn == "sentry" and not found["sentry"]:
            found["sentry"] = cur_root
        # Crashpad directory
        if bn == "crashpad" and not found["crashpad"]:
            found["crashpad"] = cur_root
        # Private Aggregation directory
        if bn == "privateaggregation" and not found["privateaggregation"]:
            found["privateaggregation"] = cur_root
        # IndexedDB candidate folders
        if bn.endswith(".indexeddb.leveldb") and not found["indexeddb"]:
            found["indexeddb"] = cur_root
        # File checks in current directory
        lowered_files = {f.lower(): os.path.join(cur_root, f) for f in files}
        if "config.json" in lowered_files and not found["config"]:
            found["config"] = lowered_files["config.json"]
        if "local state" in lowered_files and not found["local_state"]:
            found["local_state"] = lowered_files["local state"]
        if "preferences" in lowered_files and not found["preferences"]:
            found["preferences"] = lowered_files["preferences"]
        if "sharedstorage" in lowered_files and not found["sharedstorage"]:
            found["sharedstorage"] = lowered_files["sharedstorage"]
        if "quotamanager" in lowered_files and not found["quota_manager"]:
            found["quota_manager"] = lowered_files["quotamanager"]
        if "dips" in lowered_files and not found["dips"]:
            found["dips"] = lowered_files["dips"]
        if "settings.dat" in lowered_files and not found["settings"]:
            found["settings"] = lowered_files["settings.dat"]
        # Short-circuit if all found
        essential = ("indexeddb", "session", "logs", "localstorage")
        if all(found.get(k) for k in essential):
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
