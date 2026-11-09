from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile

import pytest

from host_backup import AgentError, run_backup
from host_agent import merged_values


OPENSSL = shutil.which("openssl")


@pytest.fixture
def values(tmp_path: Path, monkeypatch) -> dict[str, str]:
    database = tmp_path / "panel.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE vpn_user (name TEXT)")
        conn.execute("INSERT INTO vpn_user VALUES ('anna')")
        conn.commit()
    (tmp_path / "awg0.conf").write_text("[Interface]\nPrivateKey = SECRET=\nListenPort = 1234\n")
    peers = tmp_path / "panel-peers"
    peers.mkdir()
    (peers / "anna.conf").write_text("[Peer]\nPublicKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nAllowedIPs = 10.66.0.2/32\n")
    (peers / ".lock").write_text("")
    key_file = tmp_path / "backup.key"
    key_file.write_text("0123456789abcdef" * 4)

    monkeypatch.setenv("BACKUP_SOURCE_DB", str(database))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("BACKUP_KEY_FILE", str(key_file))
    monkeypatch.setenv("BACKUP_RETENTION", "7")
    monkeypatch.setenv("INTERFACE_CONFIG", str(tmp_path / "awg0.conf"))
    monkeypatch.setenv("PEERS_DIR", str(peers))
    monkeypatch.setenv("INTERFACE", "awg0")
    return merged_values(tmp_path / "absent-agent.conf")


@pytest.mark.skipif(not OPENSSL, reason="openssl is not on PATH")
def test_backup_produces_a_readable_encrypted_archive(values) -> None:
    report = run_backup(values, OPENSSL)
    archive = Path(report["archive"])

    assert archive.is_file() and report["bytes"] > 0
    assert report["entries"] == report["verified_entries"]
    payload = archive.read_bytes()
    assert b"PrivateKey" not in payload and b"ListenPort" not in payload


@pytest.mark.skipif(not OPENSSL, reason="openssl is not on PATH")
def test_backup_contains_the_database_and_peer_files(values, tmp_path: Path) -> None:
    report = run_backup(values, OPENSSL)
    plain = tmp_path / "unfolded.tar.gz"
    subprocess.run(
        [
            OPENSSL, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
            "-in", report["archive"], "-out", str(plain), "-pass", f"file:{values['BACKUP_KEY_FILE']}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    with tarfile.open(plain, "r:gz") as tar:
        names = set(tar.getnames())

    assert {"panel.sqlite3", "awg0.conf", "panel-peers/anna.conf"} <= names
    assert not any(".lock" in name for name in names)
    with tarfile.open(plain, "r:gz") as tar:
        database = tar.extractfile("panel.sqlite3")
        destination = tmp_path / "restored.sqlite3"
        destination.write_bytes(database.read())
    with sqlite3.connect(destination) as conn:
        assert conn.execute("SELECT name FROM vpn_user").fetchone()[0] == "anna"


@pytest.mark.skipif(not OPENSSL, reason="openssl is not on PATH")
def test_retention_prunes_the_oldest_archives(values, tmp_path: Path) -> None:
    backup_dir = Path(values["BACKUP_DIR"])
    backup_dir.mkdir(parents=True, exist_ok=True)
    stale = [backup_dir / f"awg-panel-202601{day}-000000.tar.gz.enc" for day in ("01", "02")]
    for path in stale:
        path.write_bytes(b"stale")
    values["BACKUP_RETENTION"] = "1"

    report = run_backup(values, OPENSSL)

    assert not any(path.exists() for path in stale)
    assert report["retained"] == 1


def test_backup_refuses_without_a_key(values, tmp_path: Path) -> None:
    Path(values["BACKUP_KEY_FILE"]).unlink()
    with pytest.raises(AgentError, match="encryption key"):
        run_backup(values, OPENSSL or "openssl")


def test_backup_refuses_a_missing_database(values) -> None:
    values["BACKUP_SOURCE_DB"] = str(Path(values["BACKUP_SOURCE_DB"]).parent / "gone.sqlite3")
    with pytest.raises(AgentError, match="database"):
        run_backup(values, OPENSSL or "openssl")
