#!/usr/bin/env python3
"""Encrypted snapshot of the panel database, the AWG interface config and peer drop-ins.

Runs on the host as root from a systemd timer. Standard library plus openssl, so
a copy of an archive that leaves the node is useless without BACKUP_KEY_FILE.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile


sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent import CONFIG_PATH_DEFAULT, AgentError, merged_values  # noqa: E402


def snapshot_database(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise AgentError(f"database {source} is missing")
    target = sqlite3.connect(destination)
    try:
        with sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True) as origin:
            origin.backup(target)
        check = target.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        target.close()
    if check != "ok":
        raise AgentError(f"database failed integrity_check: {check}")


def build_archive(staging: Path, archive: Path) -> int:
    with tarfile.open(archive, "w:gz") as tar:
        for entry in sorted(staging.iterdir()):
            tar.add(entry, arcname=entry.name)
        return len(tar.getnames())


def run_backup(values: dict[str, str], openssl: str) -> dict[str, object]:
    source_db = Path(values["BACKUP_SOURCE_DB"])
    backup_dir = Path(values["BACKUP_DIR"])
    key_file = Path(values["BACKUP_KEY_FILE"])
    retention = int(values["BACKUP_RETENTION"])
    interface_config = Path(values["INTERFACE_CONFIG"])
    peers_dir = Path(values["PEERS_DIR"])
    agent_config = CONFIG_PATH_DEFAULT

    if not key_file.is_file():
        raise AgentError(f"encryption key {key_file} is missing; create it with openssl rand -hex 32")
    if retention < 1:
        raise AgentError("BACKUP_RETENTION must be at least 1")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    encrypted = backup_dir / f"awg-panel-{stamp}.tar.gz.enc"

    with tempfile.TemporaryDirectory(prefix="awg-backup-") as scratch:
        workspace = Path(scratch)
        staging = workspace / "payload"
        staging.mkdir()
        snapshot_database(source_db, staging / "panel.sqlite3")
        for path in (interface_config, Path(agent_config)):
            if path.is_file():
                arcname = f"{values['INTERFACE']}.conf" if path == interface_config else path.name
                shutil.copy2(path, staging / arcname)
        if peers_dir.is_dir():
            shutil.copytree(peers_dir, staging / "panel-peers", ignore=shutil.ignore_patterns(".lock"))
        plain = workspace / "snapshot.tar.gz"
        entries = build_archive(staging, plain)

        temporary = encrypted.with_suffix(".part")
        subprocess.run(
            [
                openssl, "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                "-in", str(plain), "-out", str(temporary), "-pass", f"file:{key_file}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        temporary.chmod(0o600)
        temporary.replace(encrypted)

        subprocess.run(
            [
                openssl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                "-in", str(encrypted), "-out", str(workspace / "verify.tar.gz"), "-pass", f"file:{key_file}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        with tarfile.open(workspace / "verify.tar.gz", "r:gz") as verified:
            verified_entries = len(verified.getnames())

    kept = sorted(backup_dir.glob("awg-panel-*.tar.gz.enc"))
    for old in kept[:-retention]:
        old.unlink()
    return {
        "archive": str(encrypted),
        "bytes": encrypted.stat().st_size,
        "entries": entries,
        "verified_entries": verified_entries,
        "retained": len(kept[-retention:]),
    }


def main(argv: list[str]) -> int:
    config_path = CONFIG_PATH_DEFAULT
    if argv[:1] == ["--config"]:
        if len(argv) < 2:
            print(json.dumps({"error": "--config needs a path"}), file=sys.stderr)
            return 2
        config_path = Path(argv[1])
    try:
        openssl = shutil.which("openssl") or "/usr/bin/openssl"
        report = run_backup(merged_values(config_path), openssl)
        print(json.dumps(report))
    except (AgentError, OSError, sqlite3.Error, subprocess.SubprocessError, ValueError) as failure:
        print(json.dumps({"error": str(failure)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
