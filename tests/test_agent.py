import configparser
import dataclasses
import json
import os
from pathlib import Path
import re
import time
from urllib import error as urlerror

import pytest

import host_agent
from host_agent import Agent, AgentError, load_config, peer_document


PEER_KEY = "LeezOkX5ZDoMj4rl9My/osXJZRLvoihZAfLerFiyhy8="
SECOND_KEY = "aB3dE6fH9iK2lM5nP8qR1sT4vW7xY0zA3bC6dE9fG1h="

INTERFACE_CONFIG = """[Interface]
Address = 10.66.0.1/24
ListenPort = 1234
MTU = 1280
PrivateKey = FAKEPRIVATEKEY==
Jc = 6
Jmin = 50
Jmax = 1000
S1 = 153
S2 = 104
H1 = 1
H2 = 2
HeaderProtectionKey = 2DaQbwUbH3B8hxbGXQYUmmC5sD+ePlVkjKPaSK/0XXg=
RandomTrailers = on
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT
"""

IP_OUTPUT = "3: ens3    inet 192.0.2.10/32 brd 192.0.2.10 scope global ens3\\ valid_lft forever"

HYSTERIA_CONFIG = """listen: :43522
auth:
  type: http
  http:
    url: http://127.0.0.1:44091/authenticate
tls:
  cert: /etc/hysteria/tls.crt
  key: /etc/hysteria/tls.key
obfs:
  type: salamander
  salamander:
    password: "Obfs:Secret"
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true
"""


class FakeHost:
    """Stands in for `awg`, `ip` and fail2ban-client so tests need no root."""

    def __init__(self) -> None:
        self.runtime: dict[str, str] = {}
        self.calls: list[list[str]] = []
        self.fail_addconf = False
        self.dump = ""
        self.services: dict[str, str] = {"hysteria-server": "active"}
        self.bans: dict[str, list[str]] = {"sshd": ["203.0.113.9", "198.51.100.4"]}
        self.sequence = iter([PEER_KEY, SECOND_KEY])

    def jail_report(self, name: str) -> str:
        banned = self.bans[name]
        return (
            f"Status for the jail: {name}\n"
            "|- Filter\n"
            "|  |- Currently failed: 1\n"
            "|  |- Total failed:     12\n"
            "|  `- File list:        /var/log/auth.log\n"
            "`- Actions\n"
            f"   |- Currently banned: {len(banned)}\n"
            "   |- Total banned:     10\n"
            f"   `- Banned IP list:   {' '.join(banned)}\n"
        )

    def __call__(self, argv: list[str], stdin: str | None = None) -> str:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        rest = argv[1:]
        if tool == "ip":
            return IP_OUTPUT
        if tool == "systemctl":
            assert rest[0] == "is-active", rest
            return self.services.get(rest[1], "inactive")
        if tool == "openssl":
            assert rest[:2] == ["x509", "-noout"], rest
            return "SHA256 Fingerprint=03:10:A1:58:2F:F0:EE:6A:FF:70:A5:46:F2:EF:B6:17:5A:BD:64:18:D2:AC:30:13:BE:4D:A7:C1:00:B9:0D:AC"
        if tool == "fail2ban-client":
            if rest == ["ping"]:
                return "pong"
            if rest == ["status"]:
                return (
                    "Status\n"
                    f"|- Number of jail:\t{len(self.bans)}\n"
                    "`- Jail list:\t" + " ".join(self.bans) + "\n"
                )
            if rest[:1] == ["status"] and len(rest) == 2 and rest[1] in self.bans:
                return self.jail_report(rest[1])
            if rest[:1] == ["set"] and rest[1] in self.bans and rest[2] in {"banip", "unbanip"}:
                banned = self.bans[rest[1]]
                if rest[2] == "banip":
                    if rest[3] not in banned:
                        banned.append(rest[3])
                elif rest[3] in banned:
                    banned.remove(rest[3])
                return ""
            raise AssertionError(f"unexpected fail2ban-client call: {rest}")
        if rest[:1] == ["--version"]:
            return "amneziawg-tools v3.1-test"
        if rest[:1] == ["genkey"]:
            return "FAKEPRIV=abc"
        if rest[:1] == ["pubkey"]:
            assert stdin == "FAKEPRIV=abc"
            return next(self.sequence)
        if rest[:2] == ["show", "awg0"]:
            if rest[2:] == ["public-key"]:
                return "SERVERPUBaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1U="
            if rest[2:] == ["listen-port"]:
                return "1234"
            if rest[2:] == ["allowed-ips"]:
                return "\n".join(f"{key} {ip}/32" for key, ip in sorted(self.runtime.items()))
            if rest[2:] == ["dump"]:
                return self.dump
            raise AssertionError(f"unexpected show: {rest}")
        if rest[:1] == ["addconf"]:
            if self.fail_addconf:
                raise AgentError("awg addconf failed: No such device")
            text = Path(argv[3]).read_text()
            key = text.split("PublicKey = ")[1].split("\n")[0]
            address = text.split("AllowedIPs = ")[1].split("\n")[0]
            self.runtime[key] = address
            return ""
        if rest[:2] == ["set", "awg0"] and rest[2:3] == ["peer"]:
            key = rest[3]
            if rest[-1] == "remove":
                self.runtime.pop(key, None)
                return ""
            self.runtime[key] = rest[-1]
            return ""
        raise AssertionError(f"unexpected call: {argv}")


@pytest.fixture
def host() -> FakeHost:
    return FakeHost()


@pytest.fixture
def config(tmp_path: Path, monkeypatch) -> object:
    interface_config = tmp_path / "awg0.conf"
    interface_config.write_text(INTERFACE_CONFIG)
    hysteria_config = tmp_path / "hysteria.yaml"
    hysteria_config.write_text(HYSTERIA_CONFIG)
    (tmp_path / "tls.crt").write_text("CERT\n")
    monkeypatch.setenv("INTERFACE_CONFIG", str(interface_config))
    monkeypatch.setenv("HYSTERIA_CONFIG", str(hysteria_config))
    monkeypatch.setenv("HYSTERIA_CERT", str(tmp_path / "tls.crt"))
    monkeypatch.setenv("PEERS_DIR", str(tmp_path / "panel-peers"))
    monkeypatch.setenv("SOCKET_PATH", str(tmp_path / "agent.sock"))
    monkeypatch.setenv("FAIL2BAN_BIN", str(tmp_path / "fail2ban-client"))
    monkeypatch.setenv("PUBLIC_ENDPOINT", "")
    monkeypatch.setenv("BACKUP_SOURCE_DB", str(tmp_path / "panel.sqlite3"))
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("BACKUP_KEY_FILE", str(tmp_path / "backup.key"))
    return load_config(tmp_path / "no-such-agent.conf")


def test_create_writes_dropin_and_applies_it(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    result = agent.handle({"operation": "create", "name": "anna"})

    assert result["address"] == "10.66.0.2"
    assert result["public_key"] == PEER_KEY
    drop_in = config.peers_dir / "anna.conf"
    assert drop_in.is_file()
    assert f"PublicKey = {PEER_KEY}" in drop_in.read_text()
    assert Path(host.calls[-1][0]).name == "awg"
    assert host.calls[-1][1:] == ["addconf", "awg0", str(drop_in)]
    assert "awg0.conf" not in " ".join(host.calls[-1])


def test_generated_config_carries_awg_fingerprint_but_not_server_secrets(config, host: FakeHost) -> None:
    result = Agent(config, run=host).handle({"operation": "create", "name": "tim"})
    client = result["config"]

    for expected in ("Jc = 6", "Jmin = 50", "Jmax = 1000", "S1 = 153", "HeaderProtectionKey =", "MTU = 1280", "Endpoint = 192.0.2.10:1234"):
        assert expected in client
    for forbidden in ("ListenPort", "PostUp", "PostDown", "Address = 10.66.0.1"):
        assert forbidden not in client
    assert client.count("PrivateKey = ") == 1


def test_generated_profile_keeps_amnezia_split_tunneling_available(config, host: FakeHost) -> None:
    # эвристика клиента (serversUiController.cpp:231-238): AllowedIPs, не совпадающий с её собственной
    # строкой, читается как «конфиг уже с собственными маршрутами», и страница туннелирования
    # блокируется с сообщением «сервер не поддерживает»
    client = Agent(config, run=host).handle({"operation": "create", "name": "split"})["config"]

    allowed = [line for line in client.splitlines() if line.startswith("AllowedIPs")]
    assert allowed == ["AllowedIPs = 0.0.0.0/0, ::/0"]

    ips = [value.strip() for line in allowed for value in line.split("=", 1)[1].split(",")]
    own_routes = bool(ips) and "0.0.0.0/0" not in ips
    if not own_routes:
        own_routes = "AllowedIPs" in client and "AllowedIPs = 0.0.0.0/0, ::/0" not in client
    assert not own_routes


def test_create_rejects_existing_name(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    agent.handle({"operation": "create", "name": "dup"})

    result = agent.handle({"operation": "create", "name": "dup"})
    assert "already exists" in result["error"]
    assert len([call for call in host.calls if call[1:2] == ["genkey"]]) == 1


def test_create_skips_addresses_used_by_runtime_and_legacy_peers(config, host: FakeHost) -> None:
    host.runtime[PEER_KEY] = "10.66.0.2/32"
    (config.interface_config).write_text(
        INTERFACE_CONFIG + f"\n# panel-peer:{PEER_KEY}:old\n[Peer]\nPublicKey = {PEER_KEY}\nAllowedIPs = 10.66.0.3/32\n"
    )
    agent = Agent(config, run=host)

    result = agent.handle({"operation": "create", "name": "new"})
    assert result["address"] == "10.66.0.4"


def test_create_rolls_back_dropin_when_addconf_fails(config, host: FakeHost) -> None:
    host.fail_addconf = True
    result = Agent(config, run=host).handle({"operation": "create", "name": "orphan"})

    assert "error" in result
    assert not (config.peers_dir / "orphan.conf").exists()


@pytest.mark.parametrize("name", ["", "-lead", "with space", "x" * 33, "кириллица", None, 7])
def test_create_rejects_unusable_names(config, host: FakeHost, name) -> None:
    result = Agent(config, run=host).handle({"operation": "create", "name": name})
    assert "error" in result


def test_disable_and_enable_keep_the_file_out_of_boot(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    created = agent.handle({"operation": "create", "name": "puch"})

    assert agent.handle({"operation": "disable", "public_key": created["public_key"]})["status"] == "disabled"
    assert (config.peers_dir / "puch.conf.disabled").is_file()
    assert not (config.peers_dir / "puch.conf").exists()
    assert host.runtime == {}

    assert agent.handle({"operation": "enable", "public_key": created["public_key"]})["status"] == "active"
    assert (config.peers_dir / "puch.conf").is_file()
    assert host.runtime[PEER_KEY] == "10.66.0.2/32"


def test_delete_removes_runtime_and_file(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    created = agent.handle({"operation": "create", "name": "gone"})

    assert agent.handle({"operation": "delete", "public_key": created["public_key"]})["status"] == "deleted"
    assert list(config.peers_dir.glob("*.conf*")) == []
    assert host.runtime == {}


def test_operations_on_unknown_key_are_rejected(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    for operation in ("enable", "disable", "delete"):
        assert "error" in agent.handle({"operation": operation, "public_key": PEER_KEY})
    assert "error" in agent.handle({"operation": "disable", "public_key": "not-a-key"})


def test_status_reports_runtime_and_managed_counts(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    agent.handle({"operation": "create", "name": "one"})
    agent.handle({"operation": "create", "name": "two"})
    agent.handle({"operation": "disable", "public_key": SECOND_KEY})

    status = agent.handle({"operation": "status"})
    assert status["available"] is True
    assert status["port"] == 1234
    assert status["peers"] == 1
    assert status["managed"] == 1
    assert status["disabled"] == 1


def test_status_survives_a_missing_interface(config) -> None:
    def broken(argv, stdin=None):
        raise AgentError("awg show failed")

    status = Agent(config, run=broken).handle({"operation": "status"})
    assert status["available"] is False
    assert "unavailable" in status["detail"]


def test_migrate_moves_legacy_blocks_into_dropins(config, host: FakeHost) -> None:
    legacy = INTERFACE_CONFIG + f"\n# panel-peer:{PEER_KEY}:test\n[Peer]\nPublicKey = {PEER_KEY}\nAllowedIPs = 10.66.0.2/32\n"
    config.interface_config.write_text(legacy)
    agent = Agent(config, run=host)

    report = agent.migrate()

    assert report["migrated"] == ["test"]
    assert f"PublicKey = {PEER_KEY}" in (config.peers_dir / "test.conf").read_text()
    rewritten = config.interface_config.read_text()
    assert "panel-peer" not in rewritten and "[Peer]" not in rewritten
    assert Path(report["backup"]).is_file()


def test_migrate_refuses_to_overwrite_an_existing_dropin(config, host: FakeHost) -> None:
    config.interface_config.write_text(INTERFACE_CONFIG + f"\n# panel-peer:{PEER_KEY}:test\n[Peer]\nPublicKey = {PEER_KEY}\nAllowedIPs = 10.66.0.2/32\n")
    (config.peers_dir).mkdir(parents=True)
    (config.peers_dir / "test.conf").write_text(peer_document("test", SECOND_KEY, "10.66.0.9"))
    agent = Agent(config, run=host)

    with pytest.raises(AgentError, match="refusing to migrate"):
        agent.migrate()
    assert "panel-peer" in config.interface_config.read_text()


def test_apply_all_skips_disabled_peers(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)
    first = agent.handle({"operation": "create", "name": "live"})
    agent.handle({"operation": "create", "name": "off"})
    agent.handle({"operation": "disable", "public_key": SECOND_KEY})

    report = agent.apply_all()

    assert report["applied"] == ["live"]
    assert report["skipped_disabled"] == ["off"]
    assert host.runtime[first["public_key"]] == "10.66.0.2/32"


def test_fail2ban_reports_unconfigured_state(config, host: FakeHost) -> None:
    agent = Agent(config, run=host)

    assert agent.handle({"operation": "fail2ban"}) == {"installed": False, "running": False, "jails": []}


def test_fail2ban_reads_jail_counters(config, host: FakeHost) -> None:
    config.fail2ban_bin.write_text("#!/bin/sh\n")

    report = Agent(config, run=host).handle({"operation": "fail2ban"})

    assert report["installed"] is True
    assert report["running"] is True
    assert report["jails"] == [
        {"name": "sshd", "failed": 1, "banned": 2, "total": 10, "banned_ips": ["203.0.113.9", "198.51.100.4"]}
    ]


def test_fail2ban_reports_stopped_service(config, host: FakeHost) -> None:
    config.fail2ban_bin.write_text("#!/bin/sh\n")

    def no_ping(argv, stdin=None):
        if Path(argv[0]).name == "fail2ban-client":
            raise AgentError("fail2ban-client ping failed")
        return host(argv, stdin)

    report = Agent(config, run=no_ping).handle({"operation": "fail2ban"})
    assert report == {"installed": True, "running": False, "jails": []}


def test_f2b_sends_only_fail2ban_set_arguments(config, host: FakeHost) -> None:
    config.fail2ban_bin.write_text("#!/bin/sh\n")
    agent = Agent(config, run=host)

    banned = agent.handle({"operation": "f2b", "action": "ban", "jail": "sshd", "ip": "203.0.113.10"})
    unbanned = agent.handle({"operation": "f2b", "action": "unban", "jail": "sshd", "ip": "203.0.113.9"})

    assert ["set", "sshd", "banip", "203.0.113.10"] in [call[1:] for call in host.calls]
    assert ["set", "sshd", "unbanip", "203.0.113.9"] in [call[1:] for call in host.calls]
    assert banned["banned"] == 3
    assert banned["banned_ips"][-1] == "203.0.113.10"
    assert unbanned["banned"] == 2
    assert "203.0.113.9" not in unbanned["banned_ips"]


def test_f2b_rejects_names_and_addresses_it_cannot_trust(config, host: FakeHost) -> None:
    config.fail2ban_bin.write_text("#!/bin/sh\n")
    agent = Agent(config, run=host)

    cases = [
        ({"action": "stop", "jail": "sshd", "ip": "203.0.113.9"}, "unknown ban action"),
        ({"action": "ban", "jail": "sshd; rm", "ip": "203.0.113.9"}, "jail name"),
        ({"action": "ban", "jail": "recidive", "ip": "203.0.113.9"}, "unknown jail"),
        ({"action": "ban", "jail": "sshd", "ip": "203.0.113.9/32"}, "not a single IP"),
        ({"action": "ban", "jail": "sshd", "ip": "все"}, "not a single IP"),
        ({"action": "ban", "jail": "sshd", "ip": ""}, "address is required"),
    ]
    for payload, needle in cases:
        assert needle in agent.handle({"operation": "f2b", **payload})["error"], payload

    assert [call for call in host.calls if call[1:2] == ["set"]] == []


def test_f2b_refuses_a_service_that_is_not_running(config, host: FakeHost) -> None:
    absent = dataclasses.replace(config, fail2ban_bin=config.peers_dir / "absent-f2b")
    request = {"operation": "f2b", "action": "unban", "jail": "sshd", "ip": "203.0.113.9"}

    assert "not installed" in Agent(absent, run=host).handle(request)["error"]

    config.fail2ban_bin.write_text("#!/bin/sh\n")

    def no_ping(argv, stdin=None):
        if Path(argv[0]).name == "fail2ban-client" and argv[1:] == ["ping"]:
            raise AgentError("fail2ban-client ping failed")
        return host(argv, stdin)

    assert "not running" in Agent(config, run=no_ping).handle(request)["error"]


def test_backups_reports_a_missing_directory(config, host: FakeHost) -> None:
    report = Agent(config, run=host).handle({"operation": "backups"})

    assert report["exists"] is False
    assert report["count"] == 0
    assert report["archives"] == []
    assert report["retention"] == 7
    assert report["source_present"] is False
    assert report["key_present"] is False


def test_backups_lists_archives_newest_first(config, host: FakeHost) -> None:
    config.backup_dir.mkdir(parents=True)
    (config.backup_dir / "older.tar.gz.enc").write_bytes(b"x")
    newest = config.backup_dir / "newer.tar.gz.enc"
    newest.write_bytes(b"abcdefgh")
    now = time.time()
    os.utime(config.backup_dir / "older.tar.gz.enc", (now - 86_400, now - 86_400))
    os.utime(newest, (now, now))
    (config.backup_dir / "notes.txt").write_text("not an archive\n")
    config.backup_source_db.write_text("")
    config.backup_key_file.write_text("key\n")

    report = Agent(config, run=host).handle({"operation": "backups"})

    assert report["exists"] is True
    assert report["count"] == 2
    assert [item["name"] for item in report["archives"]] == ["newer.tar.gz.enc", "older.tar.gz.enc"]
    assert report["archives"][0]["size"] == 8
    assert report["archives"][0]["created"].endswith("UTC")
    assert report["source_present"] is True
    assert report["key_present"] is True


def test_settings_operation_exposes_effective_values(config, host: FakeHost) -> None:
    report = Agent(config, run=host).handle({"operation": "settings"})

    assert report["interface"] == "awg0"
    assert report["network"] == "10.66.0.0/24"
    assert report["gateway"] == "10.66.0.1"
    assert report["interface_config_present"] is True
    assert report["endpoint"] == "192.0.2.10"
    assert report["endpoint_error"] is None
    assert report["socket_group"] == 10001
    assert report["backup_retention"] == 7
    assert report["hysteria_stats_url"] == ""
    assert report["hysteria_stats_secret_present"] is False
    rendered = json.dumps(report)
    for forbidden in ("FAKEPRIVATEKEY", "HeaderProtectionKey"):
        assert forbidden not in rendered


def test_unknown_operation_is_rejected(config, host: FakeHost) -> None:
    error = Agent(config, run=host).handle({"operation": "reload-all"})["error"]
    assert "unsupported operation" in error


def test_every_enabled_unit_can_be_enabled(tmp_path: Path) -> None:
    """install.sh runs `systemctl enable`; a unit without [Install] makes that fail."""
    root = Path(__file__).resolve().parents[1]
    installer = (root / "install.sh").read_text()
    enabled = set(re.findall(r"systemctl (?:enable --now |enable )([\w.-]+\.service|[\w.-]+\.timer)", installer))
    assert enabled, "install.sh stopped enabling units"
    for unit in sorted(enabled):
        text = (root / "host-agent" / unit).read_text()
        assert "[Install]" in text, f"{unit} has no [Install] section"
        assert "WantedBy=" in text, f"{unit} has no WantedBy"


def test_run_dir_of_agent_socket_is_created_before_units_start() -> None:
    """ProtectSystem=strict cannot bind-mount a missing /run path: the start aborts with 226/NAMESPACE."""
    root = Path(__file__).resolve().parents[1]
    unit = (root / "host-agent" / "awg-panel-agent.service").read_text()
    run_paths = {
        part
        for line in re.findall(r"^ReadWritePaths=(.*)$", unit, re.M)
        for part in line.split()
        if part.startswith("/run/")
    }
    assert run_paths, "the agent unit stopped using a directory under /run"
    tmpfiles = (root / "host-agent" / "awg-panel.tmpfiles").read_text()
    declared = {
        line.split()[1]
        for line in tmpfiles.splitlines()
        if line.strip() and not line.startswith("#") and line.split()[0] == "d"
    }
    assert run_paths <= declared, f"missing in tmpfiles: {sorted(run_paths - declared)}"
    installer = (root / "install.sh").read_text()
    for path in sorted(run_paths):
        assert re.search(rf"{re.escape(path)}\s+0[0-7]{{3}}\s", tmpfiles), f"{path} has no mode"
    assert "/etc/tmpfiles.d/awg-panel.conf" in installer
    assert "systemd-tmpfiles --create" in installer


def test_ban_ladder_allows_two_failures_then_thirty_minutes() -> None:
    """Политика оператора от 06.11.2026: 2 неудачи → бан 1800 с, второй бан за сутки → -1."""
    root = Path(__file__).resolve().parents[1]
    parser = configparser.RawConfigParser()
    parser.read_string((root / "host-agent" / "fail2ban" / "jail.d" / "awg-panel.conf").read_text("utf-8"))
    working = ["sshd", "awg-panel", "awg-hy2"]
    for jail in working:
        assert parser.getint(jail, "maxretry", fallback=parser.getint("DEFAULT", "maxretry")) == 2, jail
        assert parser.getint(jail, "bantime", fallback=parser.getint("DEFAULT", "bantime")) == 1800, jail
    assert parser.getint("recidive", "maxretry") == 2
    assert parser.getint("recidive", "bantime") == -1
    assert "%(operator_ip)s" in parser.get("DEFAULT", "ignoreip"), "whitelist from *.local is not applied"


def test_config_rejects_typos_and_impossible_values(tmp_path: Path, monkeypatch) -> None:
    wrong_key = tmp_path / "agent.conf"
    wrong_key.write_text("INTERFCE=awg0\n")
    with pytest.raises(AgentError, match="unknown key"):
        load_config(wrong_key)

    bad_gateway = tmp_path / "gateway.conf"
    bad_gateway.write_text("GATEWAY_ADDRESS=192.168.9.1\n")
    with pytest.raises(AgentError, match="GATEWAY_ADDRESS"):
        load_config(bad_gateway)

    bad_timeout = tmp_path / "timeout.conf"
    bad_timeout.write_text("COMMAND_TIMEOUT=0\n")
    with pytest.raises(AgentError, match="COMMAND_TIMEOUT"):
        load_config(bad_timeout)

    monkeypatch.setenv("NETWORK", "10.66.0.0/31")
    with pytest.raises(AgentError, match="at least one client address"):
        load_config(tmp_path / "missing.conf")

    monkeypatch.setenv("NETWORK", "10.66.0.0/24")
    monkeypatch.setenv("BACKUP_RETENTION", "0")
    with pytest.raises(AgentError, match="BACKUP_RETENTION"):
        load_config(tmp_path / "also-missing.conf")


def test_config_file_values_are_actually_applied(tmp_path: Path, monkeypatch) -> None:
    written = tmp_path / "agent.conf"
    written.write_text("INTERFACE = wg1\nNETWORK=10.77.0.0/24\nGATEWAY_ADDRESS=10.77.0.1\nPEERS_DIR=/etc/awg/peers\n")
    for key in ("INTERFACE", "NETWORK", "GATEWAY_ADDRESS", "PEERS_DIR", "ENDPOINT_DEV", "AWG_BIN"):
        monkeypatch.delenv(key, raising=False)

    loaded = load_config(written)

    assert loaded.interface == "wg1"
    assert str(loaded.network) == "10.77.0.0/24"
    assert loaded.gateway == "10.77.0.1"
    assert loaded.peers_dir == Path("/etc/awg/peers")


def test_hysteria_reports_port_obfs_pin_and_state(config, host: FakeHost) -> None:
    result = Agent(config, run=host).handle({"operation": "hysteria"})

    assert result["installed"] is True
    assert result["port"] == "43522"
    assert result["obfs"] == {"type": "salamander", "password": "Obfs:Secret"}
    assert result["auth_type"] == "http"
    assert result["state"] == "active"
    assert result["pin_sha256"] == "0310A1582FF0EE6AFF70A546F2EFB6175ABD6418D2AC3013BE4DA7C100B90DAC"
    assert result["error"] is None


def test_hysteria_without_config_touches_nothing(config, host: FakeHost, monkeypatch) -> None:
    monkeypatch.setenv("HYSTERIA_CONFIG", str(Path("/no-such-dir") / "config.yaml"))
    result = Agent(load_config(Path("no-such-agent.conf")), run=host).handle({"operation": "hysteria"})

    assert result["installed"] is False
    assert "не найден" in result["error"]
    assert [call for call in host.calls if Path(call[0]).name in {"openssl", "systemctl"}] == []


def test_hysteria_shows_an_inactive_service(config, host: FakeHost) -> None:
    host.services["hysteria-server"] = "inactive"
    assert Agent(config, run=host).hysteria()["state"] == "inactive"


def test_hysteria_without_a_certificate_keeps_the_rest(config, host: FakeHost, monkeypatch) -> None:
    monkeypatch.setenv("HYSTERIA_CERT", str(Path("/no-such-dir") / "tls.crt"))
    result = Agent(load_config(Path("no-such-agent.conf")), run=host).hysteria()

    assert result["port"] == "43522"
    assert result["pin_sha256"] is None
    assert "сертификат" in result["error"]


# Формат `awg show <iface> dump` снят с живого узла: peer — 8 табулированных полей
# (ключ, psk, адрес клиента, разрешённая сеть, unix ts рукопожатия, принято,
# отправлено, keepalive), а строка интерфейса начинается с приватного ключа сервера.
DUMP_SECRET = "S" + "e" * 42 + "="
DUMP_HPK = "H" + "p" * 42 + "="


def interface_line() -> str:
    return "\t".join([DUMP_SECRET, DUMP_HPK, "42511"] + ["(none)"] * 18)


def peer_line(key, endpoint, address, handshake, rx, tx, keepalive="off") -> str:
    return "\t".join([key, "(none)", endpoint, f"{address}/32", str(handshake), str(rx), str(tx), keepalive])


def test_peers_reads_the_live_dump_shape(config, host: FakeHost) -> None:
    host.dump = "\n".join([
        interface_line(),
        peer_line(PEER_KEY, "198.51.100.20:49204", "10.66.0.2", 1793996402, 319182316, 3198020731),
        peer_line(SECOND_KEY, "(none)", "10.66.0.3", 0, 0, 0),
    ])
    report = Agent(config, run=host).handle({"operation": "peers"})

    assert report["interface"] == "awg0"
    assert report["error"] is None
    assert report["peers"] == [
        {"public_key": PEER_KEY, "endpoint": "198.51.100.20:49204", "handshake_at": 1793996402,
         "rx": 319182316, "tx": 3198020731},
        {"public_key": SECOND_KEY, "endpoint": None, "handshake_at": 0, "rx": 0, "tx": 0},
    ]
    # одна команда вместо show/allowed-ips/handshakes/transfer, и именно dump
    assert host.calls == [[str(config.awg_bin), "show", "awg0", "dump"]]
    rendered = json.dumps(report)
    for forbidden in (DUMP_SECRET, DUMP_HPK, "FAKEPRIVATEKEY", "HeaderProtectionKey"):
        assert forbidden not in rendered


def test_peers_ignores_lines_it_cannot_trust(config, host: FakeHost) -> None:
    host.dump = "\n".join([
        peer_line(PEER_KEY, "not-an-endpoint", "10.66.0.2", 1793996402, 10, 20),
        peer_line(SECOND_KEY, "(none)", "10.66.0.3", 1793996402, 10, 20).replace("/32", ""),
        "\t".join([PEER_KEY, "(none)"]),
        peer_line(PEER_KEY, "[2001:db8::1]:51820", "10.66.0.4", 1793996402, 10, 20),
    ])
    report = Agent(config, run=host).handle({"operation": "peers"})

    assert report["error"] is None
    assert [peer["public_key"] for peer in report["peers"]] == [PEER_KEY]
    assert report["peers"][0]["endpoint"] == "[2001:db8::1]:51820"


def test_peers_reports_an_interface_failure(config) -> None:
    def no_device(argv, stdin=None):
        raise AgentError("Command 'awg show awg0 dump' failed: Cannot find device 'awg0'")

    report = Agent(config, run=no_device).handle({"operation": "peers"})

    assert report["peers"] == []
    assert "Cannot find device" in report["error"]


class FakeStats:
    """Подменяет urlopen так же, как это делает агент для HYSTERIA_STATS_URL."""

    def __init__(self, bodies: dict[str, object]) -> None:
        self.bodies = bodies
        self.calls: list[tuple[str, str | None, object]] = []

    def __call__(self, request, timeout=None):
        path = "/traffic" if request.full_url.endswith("/traffic") else "/online"
        self.calls.append((request.full_url, request.get_header("Authorization"), timeout))
        return FakeResponse(self.bodies[path])


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode()

    def read(self, _limit: int) -> bytes:
        return self.body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args) -> bool:
        return False


def stats_config(config):
    return dataclasses.replace(config, hysteria_stats_url="http://127.0.0.1:9999", hysteria_stats_secret="s3cret")


def test_hy2_stats_reads_online_and_traffic(config, host: FakeHost, monkeypatch) -> None:
    node = stats_config(config)
    fake = FakeStats({
        "/online": {"anna": 2, "bogus": "не число", "": 1},
        "/traffic": {"anna": {"tx": 900, "rx": 400}, "broken": {"tx": "нет"}},
    })
    monkeypatch.setattr(host_agent.urlrequest, "urlopen", fake)
    report = Agent(node, run=host).handle({"operation": "hy2_stats"})

    assert report["configured"] is True
    assert report["error"] is None
    assert report["online"] == {"anna": 2}
    assert report["traffic"] == {"anna": {"tx": 900, "rx": 400}}
    assert fake.calls == [
        ("http://127.0.0.1:9999/online", "s3cret", config.command_timeout),
        ("http://127.0.0.1:9999/traffic", "s3cret", config.command_timeout),
    ]
    assert "s3cret" not in json.dumps(report)


def test_hy2_stats_without_configuration_opens_nothing(config, host: FakeHost, monkeypatch) -> None:
    def never(request, timeout=None):
        raise AssertionError("без HYSTERIA_STATS_URL запросов не бывает")

    monkeypatch.setattr(host_agent.urlrequest, "urlopen", never)
    report = Agent(config, run=host).handle({"operation": "hy2_stats"})

    assert report["configured"] is False
    assert report["online"] == {} and report["traffic"] == {}
    assert "trafficStats" in report["error"]


def test_hy2_stats_reports_an_unreachable_api(config, host: FakeHost, monkeypatch) -> None:
    node = stats_config(config)

    def refuse(request, timeout=None):
        raise urlerror.HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(host_agent.urlrequest, "urlopen", refuse)
    report = Agent(node, run=host).handle({"operation": "hy2_stats"})

    assert report["configured"] is True
    assert report["online"] == {}
    assert "401" in report["error"]
    assert "s3cret" not in json.dumps(report)


def test_hy2_stats_rejects_a_non_object_reply(config, host: FakeHost, monkeypatch) -> None:
    node = stats_config(config)
    monkeypatch.setattr(host_agent.urlrequest, "urlopen", FakeStats({"/online": [1, 2], "/traffic": {}}))
    report = Agent(node, run=host).handle({"operation": "hy2_stats"})

    assert "не объектом JSON" in report["error"]
    assert report["online"] == {}


def test_settings_never_prints_the_stats_secret(config, host: FakeHost) -> None:
    node = stats_config(config)
    report = Agent(node, run=host).handle({"operation": "settings"})

    assert report["hysteria_stats_url"] == "http://127.0.0.1:9999"
    assert report["hysteria_stats_secret_present"] is True
    assert "s3cret" not in json.dumps(report)
