#!/usr/bin/env python3
"""
Utility script to patch the installed ChatGPT Desktop app (Windows Store build)
so that the developer mode flag is always enabled. The script can also restore
the original `app.asar` from a backup that is created during the patch step.

Usage examples:
  python patch_debug_mode.py patch
  python patch_debug_mode.py patch --asar "C:\\Program Files\\WindowsApps\\...\\app\\resources\\app.asar"
  python patch_debug_mode.py restore

The script requires Node.js tooling (`npx asar`) to be available and write
access to the target `app.asar`. Run the script from an elevated shell if the
package directory is protected (e.g. WindowsApps).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Callable

# Reuse the path detection helpers so users do not have to pass explicit paths.
try:
    from text_utils import detect_default_paths  # type: ignore
except ImportError:
    detect_default_paths = None  # type: ignore


ASAR_BACKUP_SUFFIX = ".bak"
PATCH_MARKER = "/* patched-by-chat-gpt-debugger */"
ORIGINAL_TOKEN = 'ws = ot.getVersion() === "2.0.0"'
Logger = Optional[Callable[[str], None]]

PATCH_STATE_PATCHED = "patched"
PATCH_STATE_ORIGINAL = "original"
PATCH_STATE_UNSUPPORTED = "unsupported"
PATCH_STATE_MISSING = "missing"
PATCH_STATE_UNKNOWN = "unknown"

_CHUNK_SIZE = 1 << 20  # 1 MiB


class PatchError(RuntimeError):
    """Custom exception for clearer error reporting."""


def run_npx(args: list[str]) -> None:
    """Execute an npx command via cmd to avoid PowerShell execution policy."""
    cmd = ["cmd", "/c", "npx", "-y"] + args
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError as exc:
        raise PatchError(
            "npx executable was not found. Ensure Node.js is installed and npx "
            "is on PATH."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise PatchError(f"npx command failed: {' '.join(cmd)}") from exc


def resolve_asar_path(user_value: Optional[str]) -> Path:
    """Determine the app.asar path either from CLI input or detection logic."""
    if user_value:
        candidate = Path(user_value).expanduser()
        if candidate.is_dir():
            candidate = candidate / "app.asar"
        return candidate

    # Attempt auto-detection via text_utils if available.
    if detect_default_paths is not None:
        try:
            defaults = detect_default_paths()
            resources_dir = defaults.get("resources_dir")
            if resources_dir:
                candidate = Path(resources_dir) / "app.asar"
                if candidate.exists():
                    return candidate
        except Exception:
            # Fall back to heuristic search below.
            pass

    # Heuristic fallback: look inside WindowsApps.
    windows_apps = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WindowsApps"
    if windows_apps.is_dir():
        try:
            matches = sorted(
                windows_apps.glob("OpenAI.ChatGPT-Desktop_*_x64__*/app/resources/app.asar"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if matches:
                return matches[0]
        except PermissionError:
            pass  # Access denied; user will have to specify manually.

    raise PatchError(
        "Could not determine the location of app.asar automatically. "
        "Please supply the path via --asar."
    )


def ensure_exists(path: Path) -> None:
    if not path.exists():
        raise PatchError(f"Target file not found: {path}")


def backup_path(asar_path: Path) -> Path:
    return asar_path.with_suffix(asar_path.suffix + ASAR_BACKUP_SUFFIX)


def create_backup(asar_path: Path, force: bool) -> Path:
    dest = backup_path(asar_path)
    if dest.exists():
        if not force:
            raise PatchError(
                f"Backup already exists at {dest}. Use --force to overwrite "
                "or run the restore command first."
            )
        dest.unlink()
    shutil.copy2(asar_path, dest)
    return dest


def restore_backup(asar_path: Path, keep_backup: bool) -> None:
    src = backup_path(asar_path)
    if not src.exists():
        raise PatchError(f"No backup found at {src}")
    try:
        shutil.copy2(src, asar_path)
    except PermissionError as exc:
        raise PatchError(
            f"Permission denied while restoring {asar_path}. "
            "Run the script with elevated privileges."
        ) from exc
    if not keep_backup:
        src.unlink()


def extract_asar(asar_path: Path, output_dir: Path) -> None:
    run_npx(["asar", "extract", str(asar_path), str(output_dir)])


def pack_asar(source_dir: Path, output_path: Path) -> None:
    run_npx(["asar", "pack", str(source_dir), str(output_path)])


def patch_main_bundle(extracted_root: Path) -> None:
    """
    Modify the main bundle so that the dev-mode flag is effectively always true.
    The relevant statement is: ws = ot.getVersion() === "2.0.0"
    """
    candidates = list((extracted_root / ".vite" / "build").glob("main-*.js"))
    if not candidates:
        raise PatchError("Could not locate main-*.js inside extracted bundle.")
    target = candidates[0]
    text = target.read_text(encoding="utf-8")
    token = 'ws = ot.getVersion() === "2.0.0"'
    replacement = f'ws = true {PATCH_MARKER}'

    if PATCH_MARKER in text:
        raise PatchError("Bundle already appears to be patched.")

    if token not in text:
        raise PatchError(
            f"Failed to find expected version check token in {target}. "
            "The bundle format may have changed."
        )

    patched = text.replace(token, replacement, 1)
    target.write_text(patched, encoding="utf-8")


def _asar_contains(asar_path: Path, needle: str) -> bool:
    target = needle.encode("utf-8")
    try:
        with open(asar_path, "rb") as fh:
            buffer = b""
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    return False
                combined = buffer + chunk
                if target in combined:
                    return True
                if len(target) > 1:
                    buffer = combined[-(len(target) - 1):]
                else:
                    buffer = b""
    except OSError:
        return False


def is_patched(asar_path: Path) -> bool:
    return _asar_contains(asar_path, PATCH_MARKER)


def detects_original_signature(asar_path: Path) -> bool:
    return _asar_contains(asar_path, ORIGINAL_TOKEN)


def detect_patch_state(asar_path: Path) -> str:
    if not asar_path.exists():
        return PATCH_STATE_MISSING
    if is_patched(asar_path):
        return PATCH_STATE_PATCHED
    if detects_original_signature(asar_path):
        return PATCH_STATE_ORIGINAL
    return PATCH_STATE_UNSUPPORTED


def apply_patch(
    asar_path: Path,
    force_backup: bool,
    keep_temp: bool,
    logger: Logger = None,
) -> None:
    log = logger or print
    ensure_exists(asar_path)
    state = detect_patch_state(asar_path)
    if state == PATCH_STATE_PATCHED:
        raise PatchError("Die Zieldatei scheint bereits gepatcht zu sein.")
    if state == PATCH_STATE_UNSUPPORTED:
        log(
            "Warnung: Die Datei enthält nicht die erwartete Signatur. "
            "Der Patch wird versucht, könnte aber fehlschlagen."
        )
    backup = create_backup(asar_path, force_backup)
    log(f"Backup gespeichert unter: {backup}")

    temp_dir_ctx = tempfile.TemporaryDirectory()
    temp_dir = Path(temp_dir_ctx.name)
    try:
        extracted_dir = temp_dir / "extracted"
        extracted_dir.mkdir(parents=True, exist_ok=True)

        log("asar wird entpackt ...")
        extract_asar(asar_path, extracted_dir)

        log("Haupt-Bundle wird modifiziert ...")
        patch_main_bundle(extracted_dir)

        new_asar = temp_dir / "patched.asar"
        log("asar wird erneut gepackt (das kann einen Moment dauern) ...")
        pack_asar(extracted_dir, new_asar)

        try:
            shutil.copy2(new_asar, asar_path)
        except PermissionError as exc:
            raise PatchError(
                f"Permission denied writing {asar_path}. "
                "Run the script with elevated privileges."
            ) from exc

        if not is_patched(asar_path):
            raise PatchError(
                "Validierung fehlgeschlagen: Entwicklermodus-Markierung wurde nicht gefunden."
            )
        log("Patch erfolgreich angewendet. Entwicklermodus ist aktiv.")
        state_after = detect_patch_state(asar_path)
        if state_after != PATCH_STATE_PATCHED:
            log(f"Hinweis: Unerwarteter Patch-Status ({state_after}).")
    finally:
        if keep_temp:
            log(f"Tempor\u00e4res Verzeichnis beibehalten: {temp_dir}")
            temp_dir_ctx.cleanup = lambda: None  # type: ignore[attr-defined]
        else:
            temp_dir_ctx.cleanup()
        log("Vorgang abgeschlossen.")


def perform_restore(
    asar_path: Path,
    keep_backup: bool,
    logger: Logger = None,
) -> None:
    log = logger or print
    ensure_exists(asar_path)
    restore_backup(asar_path, keep_backup)
    if is_patched(asar_path):
        raise PatchError(
            "Wiederherstellung durchgef\u00fchrt, aber Entwicklermodus-Markierung ist weiterhin vorhanden."
        )
    state = detect_patch_state(asar_path)
    if state == PATCH_STATE_ORIGINAL:
        status_text = "Originalzustand erkannt"
    elif state == PATCH_STATE_UNSUPPORTED:
        status_text = "Status unklar (keine bekannte Signatur)"
    else:
        status_text = f"Status: {state}"
    log(f"Originaldatei wurde aus dem Backup wiederhergestellt: {asar_path}")
    log(status_text)
    if keep_backup:
        log("Backup-Datei wurde aufbewahrt.")
    else:
        log("Backup-Datei wurde entfernt.")



def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    patch_parser = subparsers.add_parser("patch", help="Patch app.asar to enable developer mode.")
    patch_parser.add_argument("--asar", help="Path to app.asar (file or containing directory).")
    patch_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing backup if present.",
    )
    patch_parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Do not delete temporary extraction directory (for inspection).",
    )

    restore_parser = subparsers.add_parser("restore", help="Restore the original app.asar from backup.")
    restore_parser.add_argument("--asar", help="Path to app.asar (file or containing directory).")
    restore_parser.add_argument(
        "--keep-backup",
        action="store_true",
        help="Keep the .bak file after restore (default is to delete).",
    )

    args = parser.parse_args()

    try:
        asar = resolve_asar_path(getattr(args, "asar", None))

        if args.command == "patch":
            apply_patch(
                asar,
                force_backup=args.force,
                keep_temp=args.keep_temp,
                logger=print,
            )
        elif args.command == "restore":
            perform_restore(
                asar,
                keep_backup=args.keep_backup,
                logger=print,
            )
        else:
            parser.error(f"Unknown command: {args.command}")

    except PatchError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


