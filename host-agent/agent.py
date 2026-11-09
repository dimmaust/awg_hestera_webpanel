#!/usr/bin/env python3
"""Host-side AmneziaWG adapter for the AWG panel.

Peers are stored as individual drop-in files in PEERS_DIR and applied with
`awg addconf`, so the interface config of an existing installation is never
rewritten.  Disabled peers keep a `.conf.disabled` suffix, which keeps them out
of the boot reload.  Every command is hard-coded: never interpolate
user-controlled values into a shell and never add a generic command passthrough.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
try:  # Linux-only advisory locking; unit tests also run on Windows.
    import fcntl
except ModuleNotFoundError:  # pragma: no cover
    fcntl = None
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
from urllib import error as urlerror
from urllib import request as urlrequest


CONFIG_PATH_DEFAULT = Path("/etc/awg-panel/agent.conf")
DEFAULTS = {
    "AWG_BIN": "/usr/bin/awg",
    "IP_BIN": "/usr/sbin/ip",
    "FAIL2BAN_BIN": "/usr/bin/fail2ban-client",
    "INTERFACE": "awg0",
    "NETWORK": "10.66.0.0/24",
    "GATEWAY_ADDRESS": "10.66.0.1",
    "INTERFACE_CONFIG": "/etc/amnezia/amneziawg/awg0.conf",
    "PEERS_DIR": "/etc/amnezia/amneziawg/panel-peers",
    "SOCKET_PATH": "/run/awg-panel/agent.sock",
    "SOCKET_GROUP": "10001",
    "ENDPOINT_DEV": "ens3",
    "PUBLIC_ENDPOINT": "",
    "CLIENT_DNS": "1.1.1.1",
    "COMMAND_TIMEOUT": "5",
    "BACKUP_SOURCE_DB": "/opt/awg-panel/data/panel.sqlite3",
    "BACKUP_DIR": "/var/backups/awg-panel",
    "BACKUP_KEY_FILE": "/etc/awg-panel/backup.key",
    "BACKUP_RETENTION": "7",
    "HYSTERIA_CONFIG": "/etc/hysteria/config.yaml",
    "HYSTERIA_CERT": "/etc/hysteria/tls.crt",
    "HYSTERIA_SERVICE": "hysteria-server",
    "HYSTERIA_SNI": "",
    "HYSTERIA_STATS_URL": "",
    "HYSTERIA_STATS_SECRET": "",
    "MTPROTO_API_URL": "",
    "MTPROTO_API_TOKEN": "",
    "MTPROTO_SERVICE": "telemt",
    "OPENSSL_BIN": "/usr/bin/openssl",
    "SYSTEMCTL_BIN": "/usr/bin/systemctl",
}
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
KEY_PATTERN = re.compile(r"[A-Za-z0-9+/]{43}=\Z")
JAIL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
F2B_ACTIONS = {"ban": "banip", "unban": "unbanip"}
# Поддомен в ссылку MTProto попадает в теле PATCH /v1/config, поэтому только ASCII-метка с точкой:
# без `/`, `:`, пробелов и IDN — иначе значение разошлось бы с тем, что генерит сам движок.
DOMAIN_PATTERN = re.compile(
    r"(?=[A-Za-z0-9.-]{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)
MT_ACTIONS = {
    "enable": ("POST", "/v1/users/{name}/enable"),
    "disable": ("POST", "/v1/users/{name}/disable"),
    "rotate": ("POST", "/v1/users/{name}/rotate-secret"),
    "delete": ("DELETE", "/v1/users/{name}"),
}
MT_RELOAD_DONE = {"succeeded", "rolled_back", "failed"}
MT_RELOAD_WAIT = 2.0   # сколько секунд агент догоняет терминальный статус перегрузки генерации
MT_RELOAD_POLL = 0.4   # пауза между опросами GET /v1/system/reload/{id}
MT_RELOAD_DRAIN = 30   # timeout_secs для reload=drain: сколько живут сессии старой генерации
LEGACY_BLOCK = re.compile(
    r"\n?# panel-peer:(?P<key>[A-Za-z0-9+/]{43}=):(?P<name>[^\n]+)\n"
    r"\[Peer\]\nPublicKey = (?P=key)\nAllowedIPs = (?P<address>[0-9.]+)/32\n"
)
PEER_KEY_LINE = re.compile(r"^PublicKey = (?P<key>[A-Za-z0-9+/]{43}=)$", re.M)
PEER_ADDRESS_LINE = re.compile(r"^AllowedIPs = (?P<address>[0-9.]+)/32$", re.M)
JAIL_COUNTER = re.compile(r"(Currently failed|Currently banned|Total banned)\s*:\s*(\d+)")
JAIL_BANNED = re.compile(r"Banned IP list\s*:\s*(.+)")
JAIL_LIST = re.compile(r"Jail list\s*:\s*(.+)")
HYSTERIA_LISTEN = re.compile(r"^listen:[ \t]*(.+?)[ \t]*$", re.M)
PEER_ENDPOINT = re.compile(r"^(?:\[[0-9A-Fa-f:.]+]|[0-9.]+):[0-9]+\Z")


class AgentError(RuntimeError):
    """A failure that is safe to report to the panel."""


@dataclass(frozen=True)
class Config:
    awg_bin: Path
    ip_bin: Path
    fail2ban_bin: Path
    interface: str
    network: ipaddress.IPv4Network
    gateway: str
    interface_config: Path
    peers_dir: Path
    socket_path: Path
    socket_group: int
    endpoint_dev: str
    public_endpoint: str
    client_dns: str
    command_timeout: int
    backup_source_db: Path
    backup_dir: Path
    backup_key_file: Path
    backup_retention: int
    hysteria_config: Path
    hysteria_cert: Path
    hysteria_service: str
    hysteria_sni: str
    hysteria_stats_url: str
    hysteria_stats_secret: str
    mtproto_api_url: str
    mtproto_api_token: str
    mtproto_service: str
    openssl_bin: Path
    systemctl_bin: Path


def read_config_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        key, separator, value = entry.partition("=")
        if not separator:
            raise AgentError(f"{path}: malformed line {line!r}")
        key = key.strip()
        if key not in DEFAULTS:
            raise AgentError(f"{path}: unknown key {key!r}")
        values[key] = value.strip()
    return values


def merged_values(path: Path = CONFIG_PATH_DEFAULT) -> dict[str, str]:
    """DEFAULTS, then the config file, then the environment."""
    values = dict(DEFAULTS)
    values.update(read_config_file(path))
    for key in DEFAULTS:
        override = os.environ.get(key)
        if override is not None:
            values[key] = override
    return values


def load_config(path: Path = CONFIG_PATH_DEFAULT) -> Config:
    values = merged_values(path)
    try:
        network = ipaddress.IPv4Network(values["NETWORK"], strict=False)
        gateway = ipaddress.IPv4Address(values["GATEWAY_ADDRESS"])
        timeout = int(values["COMMAND_TIMEOUT"])
        socket_group = int(values["SOCKET_GROUP"])
        retention = int(values["BACKUP_RETENTION"])
    except ValueError as failure:
        raise AgentError(f"invalid agent configuration: {failure}") from failure
    if timeout < 1 or timeout > 60:
        raise AgentError("COMMAND_TIMEOUT must be between 1 and 60 seconds")
    if retention < 1:
        raise AgentError("BACKUP_RETENTION must be at least 1")
    if network.num_addresses < 3:
        raise AgentError("NETWORK must leave at least one client address")
    if gateway not in network:
        raise AgentError("GATEWAY_ADDRESS must belong to NETWORK")
    return Config(
        awg_bin=Path(values["AWG_BIN"]),
        ip_bin=Path(values["IP_BIN"]),
        fail2ban_bin=Path(values["FAIL2BAN_BIN"]),
        interface=values["INTERFACE"],
        network=network,
        gateway=str(gateway),
        interface_config=Path(values["INTERFACE_CONFIG"]),
        peers_dir=Path(values["PEERS_DIR"]),
        socket_path=Path(values["SOCKET_PATH"]),
        socket_group=socket_group,
        endpoint_dev=values["ENDPOINT_DEV"],
        public_endpoint=values["PUBLIC_ENDPOINT"],
        client_dns=values["CLIENT_DNS"],
        command_timeout=timeout,
        backup_source_db=Path(values["BACKUP_SOURCE_DB"]),
        backup_dir=Path(values["BACKUP_DIR"]),
        backup_key_file=Path(values["BACKUP_KEY_FILE"]),
        backup_retention=retention,
        hysteria_config=Path(values["HYSTERIA_CONFIG"]),
        hysteria_cert=Path(values["HYSTERIA_CERT"]),
        hysteria_service=values["HYSTERIA_SERVICE"],
        hysteria_sni=values["HYSTERIA_SNI"],
        hysteria_stats_url=values["HYSTERIA_STATS_URL"].strip(),
        hysteria_stats_secret=values["HYSTERIA_STATS_SECRET"].strip(),
        mtproto_api_url=values["MTPROTO_API_URL"].strip(),
        mtproto_api_token=values["MTPROTO_API_TOKEN"].strip(),
        mtproto_service=values["MTPROTO_SERVICE"].strip(),
        openssl_bin=Path(values["OPENSSL_BIN"]),
        systemctl_bin=Path(values["SYSTEMCTL_BIN"]),
    )


def require_name(value: object) -> str:
    if not isinstance(value, str) or not NAME_PATTERN.match(value):
        raise AgentError("peer name must be 1-32 characters of [A-Za-z0-9_-], starting with a letter or digit")
    return value


def require_key(value: object) -> str:
    if not isinstance(value, str) or not KEY_PATTERN.match(value):
        raise AgentError("peer public key is not a valid AmneziaWG key")
    return value


def require_jail(value: object) -> str:
    """Имя jail'а попадает в argv fail2ban-client, поэтому берём только то, что совпало с шаблоном."""
    if not isinstance(value, str) or not JAIL_PATTERN.match(value):
        raise AgentError("jail name must be 1-64 characters of [A-Za-z0-9_-]")
    return value


def require_address(value: object) -> str:
    """Один адрес, без маски и без пробелов: fail2ban-client принимает именно хост."""
    if not isinstance(value, str) or not value.strip():
        raise AgentError("address is required")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as failure:
        raise AgentError(f"{value!r} is not a single IP address") from failure


def require_domain(value: object) -> str:
    """Подменный домен уходит в [censorship] конфига движка и в ссылки клиентов."""
    if not isinstance(value, str) or not DOMAIN_PATTERN.match(value.strip()):
        raise AgentError("domain must be a lowercase or uppercase ASCII hostname with a dot, 1-253 characters")
    return value.strip().lower()


def peer_document(name: str, public_key: str, address: str) -> str:
    return (
        f"# awg-panel peer={name}\n"
        f"[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"AllowedIPs = {address}/32\n"
    )


def write_atomic(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def yaml_scalar(text: str, section: str, field: str) -> str | None:
    """Скаляр field внутри блока section (плоский YAML конфига hysteria, вложенность 1-2).

    Значение берётся целиком до конца строки и только потом снимаются кавычки:
    пароль obfs может содержать двоеточие, поэтому split(':') его бы обрезал.
    """
    block = re.search(rf"^[ \t]*{re.escape(section)}:\n(?:[ \t].*\n?)*", text, re.M)
    if not block:
        return None
    line = re.search(rf"^[ \t]+{re.escape(field)}:[ \t]*(.+?)[ \t]*$", block.group(0), re.M)
    if not line:
        return None
    return line.group(1).strip().strip("\"'")


class Agent:
    def __init__(self, config: Config, run=None) -> None:
        self.config = config
        self._run = run or self._subprocess_run

    def _subprocess_run(self, argv: list[str], stdin: str | None = None) -> str:
        try:
            completed = subprocess.run(
                argv,
                input=stdin,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.config.command_timeout,
            )
        except FileNotFoundError as failure:
            raise AgentError(f"{argv[0]} is not installed") from failure
        except subprocess.TimeoutExpired as failure:
            raise AgentError(f"{' '.join(argv[1:3])} timed out") from failure
        except subprocess.CalledProcessError as failure:
            detail = (failure.stderr or failure.stdout or "").strip()
            raise AgentError(f"{' '.join(argv[1:3])} failed: {detail[:200]}") from failure
        return completed.stdout.strip()

    # -- discovery ---------------------------------------------------------

    def interface_section(self) -> list[str]:
        text = self.config.interface_config.read_text(encoding="utf-8")
        lines = text.split("[Peer]", 1)[0].splitlines()
        return [
            line
            for line in lines
            if "=" in line and not line.lstrip().startswith(("Address", "ListenPort", "PrivateKey", "Post"))
        ]

    def managed_peers(self) -> list[dict[str, str]]:
        peers: list[dict[str, str]] = []
        if not self.config.peers_dir.is_dir():
            return peers
        for path in sorted(self.config.peers_dir.iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            disabled = path.name.endswith(".disabled")
            if not (path.name.endswith(".conf") or disabled):
                continue
            text = path.read_text(encoding="utf-8")
            key = PEER_KEY_LINE.search(text)
            address = PEER_ADDRESS_LINE.search(text)
            if not key or not address:
                continue
            stem = path.name[: -len(".disabled")] if disabled else path.name
            peers.append(
                {
                    "name": stem[: -len(".conf")] if stem.endswith(".conf") else stem,
                    "public_key": key.group("key"),
                    "address": address.group("address"),
                    "status": "disabled" if disabled else "active",
                    "path": str(path),
                }
            )
        return peers

    def find_peer(self, public_key: str) -> dict[str, str]:
        matches = [peer for peer in self.managed_peers() if peer["public_key"] == public_key]
        if not matches:
            raise AgentError("no peer managed by this panel has that key")
        return matches[0]

    def endpoint(self) -> str:
        if self.config.public_endpoint:
            return self.config.public_endpoint
        output = self._run(
            [str(self.config.ip_bin), "-4", "-o", "addr", "show", "dev", self.config.endpoint_dev, "scope", "global"]
        )
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[2] == "inet":
                return fields[3].split("/")[0]
        raise AgentError(f"no global IPv4 address on {self.config.endpoint_dev}")

    def runtime_addresses(self) -> set[str]:
        output = self._run([str(self.config.awg_bin), "show", self.config.interface, "allowed-ips"])
        taken = set()
        for line in output.splitlines():
            fields = line.split()
            if fields:
                taken.add(fields[-1].split("/")[0])
        return taken

    def reserved_addresses(self) -> set[str]:
        reserved: set[str] = set()
        reserved.update(peer["address"] for peer in self.managed_peers())
        reserved.update(self.runtime_addresses())
        try:
            for match in PEER_ADDRESS_LINE.finditer(self.config.interface_config.read_text(encoding="utf-8")):
                reserved.add(match.group("address"))
        except FileNotFoundError:
            pass
        reserved.add(self.config.gateway)
        return reserved

    def next_address(self) -> str:
        reserved = self.reserved_addresses()
        for host in self.config.network.hosts():
            if str(host) == self.config.gateway:
                continue
            if str(host) not in reserved:
                return str(host)
        raise AgentError(f"no free client address in {self.config.network}")

    def peer_name_taken(self, name: str) -> bool:
        directory = self.config.peers_dir
        return (directory / f"{name}.conf").exists() or (directory / f"{name}.conf.disabled").exists()

    # -- mutations ---------------------------------------------------------

    @contextmanager
    def mutate(self):
        """Hold an exclusive lock while the peer directory changes."""
        self.config.peers_dir.mkdir(parents=True, exist_ok=True)
        handle = (self.config.peers_dir / ".lock").open("a+")
        try:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()

    def add_runtime(self, path: Path) -> None:
        self._run([str(self.config.awg_bin), "addconf", self.config.interface, str(path)])

    def remove_runtime(self, public_key: str) -> None:
        try:
            self._run([str(self.config.awg_bin), "set", self.config.interface, "peer", public_key, "remove"])
        except AgentError as failure:
            if "No such peer" not in str(failure):
                raise

    def create(self, name: object) -> dict[str, object]:
        peer_name = require_name(name)
        self.config.peers_dir.mkdir(parents=True, exist_ok=True)
        with self.mutate():
            if self.peer_name_taken(peer_name):
                raise AgentError(f"peer {peer_name} already exists")
            private_key = self._run([str(self.config.awg_bin), "genkey"])
            public_key = self._run([str(self.config.awg_bin), "pubkey"], stdin=private_key)
            if not KEY_PATTERN.match(public_key):
                raise AgentError("amneziawg-tools returned an unusable public key")
            address = self.next_address()
            server_key = self._run([str(self.config.awg_bin), "show", self.config.interface, "public-key"])
            port = self._run([str(self.config.awg_bin), "show", self.config.interface, "listen-port"])
            endpoint = self.endpoint()
            target = self.config.peers_dir / f"{peer_name}.conf"
            write_atomic(target, peer_document(peer_name, public_key, address))
            try:
                self.add_runtime(target)
            except AgentError:
                target.unlink(missing_ok=True)
                raise
            client = "\n".join(
                [
                    "[Interface]",
                    f"PrivateKey = {private_key}",
                    f"Address = {address}/32",
                    f"DNS = {self.config.client_dns}",
                    *self.interface_section(),
                    "",
                    "[Peer]",
                    f"PublicKey = {server_key}",
                    # дословно строка из шаблона Amnezia: её клиент по любому другому AllowedIPs считает конфиг
                    # «уже с собственными маршрутами» и блокирует страницу раздельного туннелирования
                    "AllowedIPs = 0.0.0.0/0, ::/0",
                    f"Endpoint = {endpoint}:{port}",
                    "PersistentKeepalive = 25",
                    "",
                ]
            )
        return {"name": peer_name, "address": address, "public_key": public_key, "config": client}

    def enable(self, public_key: object) -> dict[str, object]:
        key = require_key(public_key)
        with self.mutate():
            peer = self.find_peer(key)
            if peer["status"] == "active":
                return {"name": peer["name"], "address": peer["address"], "status": "active"}
            target = Path(peer["path"]).with_name(f"{peer['name']}.conf")
            os.replace(peer["path"], target)
            try:
                self.add_runtime(target)
            except AgentError:
                os.replace(target, peer["path"])
                raise
        return {"name": peer["name"], "address": peer["address"], "status": "active"}

    def disable(self, public_key: object) -> dict[str, object]:
        key = require_key(public_key)
        with self.mutate():
            peer = self.find_peer(key)
            if peer["status"] == "disabled":
                return {"name": peer["name"], "address": peer["address"], "status": "disabled"}
            self.remove_runtime(key)
            os.replace(peer["path"], Path(peer["path"]).with_name(f"{peer['name']}.conf.disabled"))
        return {"name": peer["name"], "address": peer["address"], "status": "disabled"}

    def delete(self, public_key: object) -> dict[str, object]:
        key = require_key(public_key)
        with self.mutate():
            peer = self.find_peer(key)
            self.remove_runtime(key)
            Path(peer["path"]).unlink()
        return {"name": peer["name"], "address": peer["address"], "status": "deleted"}

    def migrate(self) -> dict[str, object]:
        """Move legacy `# panel-peer:` blocks out of the interface config."""
        if not self.config.interface_config.is_file():
            raise AgentError(f"{self.config.interface_config} is missing")
        self.config.peers_dir.mkdir(parents=True, exist_ok=True)
        with self.mutate():
            text = self.config.interface_config.read_text(encoding="utf-8")
            blocks = list(LEGACY_BLOCK.finditer(text))
            if not blocks:
                return {"migrated": [], "backup": None}
            moved: list[str] = []
            for block in blocks:
                name = require_name(block.group("name"))
                if self.peer_name_taken(name):
                    raise AgentError(f"drop-in for {name} already exists; refusing to migrate")
                write_atomic(
                    self.config.peers_dir / f"{name}.conf",
                    peer_document(name, block.group("key"), block.group("address")),
                )
                moved.append(name)
            stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
            backup = self.config.interface_config.with_name(f"{self.config.interface_config.name}.bak.{stamp}")
            shutil.copy2(self.config.interface_config, backup)
            write_atomic(self.config.interface_config, LEGACY_BLOCK.sub("", text))
        return {"migrated": moved, "backup": str(backup)}

    def apply_all(self) -> dict[str, object]:
        """Re-apply every active drop-in; used by the boot unit and by operators."""
        peers = self.managed_peers()
        active = [peer for peer in peers if peer["status"] == "active"]
        with self.mutate():
            for peer in active:
                self.add_runtime(Path(peer["path"]))
        return {
            "applied": [peer["name"] for peer in active],
            "skipped_disabled": [peer["name"] for peer in peers if peer["status"] == "disabled"],
        }

    # -- read-only surface -------------------------------------------------

    def status(self) -> dict[str, object]:
        managed = self.managed_peers()
        result: dict[str, object] = {
            "available": False,
            "interface": self.config.interface,
            "managed": len([peer for peer in managed if peer["status"] == "active"]),
            "disabled": len([peer for peer in managed if peer["status"] == "disabled"]),
        }
        try:
            result["version"] = self._run([str(self.config.awg_bin), "--version"])
            result["port"] = int(self._run([str(self.config.awg_bin), "show", self.config.interface, "listen-port"]))
            result["peers"] = len(self.runtime_addresses())
            result["available"] = True
        except (AgentError, ValueError):
            result["detail"] = "AmneziaWG interface is unavailable"
        return result

    def peer_runtime(self) -> list[dict[str, object]]:
        """Peer'ы интерфейса из ядра одной командой `awg show <iface> dump`.

        Строка интерфейса в dump тоже начинается с 44-символьного ключа, но это
        приватный ключ сервера, поэтому peer опознаётся по форме остальных полей
        (3-е — `адрес:порт` или `(none)`, 4-е — CIDR, 5-7-е — числа), и ни один
        ключ кроме публичного клиента наружу не уходит. Голый `awg show <iface>`
        не используется именно поэтому: он печатает приватный ключ и HPK.
        """
        output = self._run([str(self.config.awg_bin), "show", self.config.interface, "dump"])
        peers: list[dict[str, object]] = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 8 or not KEY_PATTERN.match(fields[0]):
                continue
            endpoint, allowed_ips, handshake, rx, tx = fields[2:7]
            if endpoint != "(none)" and not PEER_ENDPOINT.match(endpoint):
                continue
            if "/" not in allowed_ips or not (handshake.isdigit() and rx.isdigit() and tx.isdigit()):
                continue
            peers.append(
                {
                    "public_key": fields[0],
                    "endpoint": None if endpoint == "(none)" else endpoint,
                    "handshake_at": int(handshake),
                    "rx": int(rx),
                    "tx": int(tx),
                }
            )
        return peers

    def peers(self) -> dict[str, object]:
        """Кто из peer'ов AmneziaWG на связи: рукопожатие, адрес клиента, байты."""
        result: dict[str, object] = {"interface": self.config.interface, "peers": [], "error": None}
        try:
            result["peers"] = self.peer_runtime()
        except AgentError as failure:
            result["error"] = str(failure)
        return result

    def stats_fetch(self, path: str) -> dict:
        """Один запрос к Traffic Stats API hysteria2: secret уходит в Authorization как есть."""
        url = f"{self.config.hysteria_stats_url.rstrip('/')}{path}"
        headers = {"Authorization": self.config.hysteria_stats_secret} if self.config.hysteria_stats_secret else {}
        request = urlrequest.Request(url, headers=headers)
        with urlrequest.urlopen(request, timeout=self.config.command_timeout) as response:  # noqa: S310 - fixed config URL
            payload = json.loads(response.read(262144).decode("utf-8", "replace"))
        if not isinstance(payload, dict):
            raise AgentError(f"{path} ответил не объектом JSON")
        return payload

    def hy2_stats(self) -> dict[str, object]:
        """Онлайн и трафик клиентов hysteria2 по именам, которое вернул /authenticate.

        Счётчики живут в памяти сервера hysteria: после его рестарта map пустеет,
        живые клиенты возвращаются в /online сами в пределах keepalive (~30 с).
        """
        result: dict[str, object] = {"configured": False, "online": {}, "traffic": {}, "error": None}
        if not self.config.hysteria_stats_url:
            result["error"] = "HYSTERIA_STATS_URL пуст: trafficStats в конфиге hysteria2 не включён"
            return result
        result["configured"] = True
        try:
            online = self.stats_fetch("/online")
            traffic = self.stats_fetch("/traffic")
        except (AgentError, urlerror.URLError, OSError, ValueError) as failure:
            result["error"] = f"Traffic Stats API недоступен: {str(failure)[:200]}"
            return result
        result["online"] = {
            str(name): count
            for name, count in online.items()
            if str(name) and isinstance(count, int)
        }
        result["traffic"] = {
            str(name): {"tx": int(entry["tx"]), "rx": int(entry["rx"])}
            for name, entry in traffic.items()
            if isinstance(entry, dict) and isinstance(entry.get("tx"), int) and isinstance(entry.get("rx"), int)
        }
        return result

    def fail2ban(self) -> dict[str, object]:
        if not self.config.fail2ban_bin.exists() and not shutil.which(str(self.config.fail2ban_bin)):
            return {"installed": False, "running": False, "jails": []}
        try:
            ping = self._run([str(self.config.fail2ban_bin), "ping"])
        except AgentError:
            return {"installed": True, "running": False, "jails": []}
        try:
            listing = self._run([str(self.config.fail2ban_bin), "status"])
        except AgentError:
            names: list[str] = []
        else:
            # fail2ban answers with a tree: "Status", "|- Number of jail: 1", "`- Jail list: sshd".
            listed = JAIL_LIST.search(listing)
            names = listed.group(1).replace(",", " ").split() if listed else []
        jails: list[dict[str, object]] = []
        for name in names:
            jail: dict[str, object] = {"name": name, "failed": None, "banned": None, "total": None, "banned_ips": []}
            try:
                report = self._run([str(self.config.fail2ban_bin), "status", name])
            except AgentError:
                jails.append(jail)
                continue
            for label, value in JAIL_COUNTER.findall(report):
                jail[{"Currently failed": "failed", "Currently banned": "banned", "Total banned": "total"}[label]] = int(value)
            listed = JAIL_BANNED.search(report)
            if listed:
                jail["banned_ips"] = listed.group(1).split()
            jails.append(jail)
        return {"installed": True, "running": "pong" in ping, "jails": jails}

    def f2b(self, action: object, jail: object, address: object) -> dict[str, object]:
        """Ручной бан или разбан одного адреса — то же, что оператор делает в консоли.

        Имя jail'а сверяется со списком самого fail2ban: в argv не уходит то, чего сервис
        не знает. `bantime` при этом не обходится — `banip` живёт ровно столько, сколько
        настроено в jail'е, а `unbanip` чистит и счётчик неудач, то есть открывает новые попытки.
        """
        if not isinstance(action, str) or action not in F2B_ACTIONS:
            raise AgentError(f"unknown ban action {action!r}")
        name = require_jail(jail)
        host = require_address(address)
        report = self.fail2ban()
        if not report["installed"]:
            raise AgentError("fail2ban is not installed on this host")
        if not report["running"]:
            raise AgentError("fail2ban is not running")
        known = [str(entry["name"]) for entry in report["jails"]]
        if name not in known:
            raise AgentError(f"unknown jail {name!r}; known: {', '.join(known) or 'none'}")
        self._run([str(self.config.fail2ban_bin), "set", name, F2B_ACTIONS[action], host])
        after = next((entry for entry in self.fail2ban()["jails"] if entry["name"] == name), {})
        return {
            "action": action,
            "jail": name,
            "ip": host,
            "banned": after.get("banned"),
            "banned_ips": after.get("banned_ips", []),
        }

    def backups(self) -> dict[str, object]:
        """Read-only view of the encrypted archive directory."""
        directory = self.config.backup_dir
        archives = sorted(
            (path for path in directory.glob("*.tar.gz.enc") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        ) if directory.is_dir() else []
        listed = []
        for path in archives[:20]:
            info = path.stat()
            listed.append(
                {
                    "name": path.name,
                    "size": info.st_size,
                    "created": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(info.st_mtime)),
                }
            )
        return {
            "directory": str(directory),
            "exists": directory.is_dir(),
            "retention": self.config.backup_retention,
            "count": len(archives),
            "archives": listed,
            "source_db": str(self.config.backup_source_db),
            "source_present": self.config.backup_source_db.is_file(),
            "key_present": self.config.backup_key_file.is_file(),
        }

    def service_state(self, name: str) -> str | None:
        try:
            return self._run([str(self.config.systemctl_bin), "is-active", name]) or None
        except AgentError:
            return None

    def hysteria(self) -> dict[str, object]:
        """Параметры узла hysteria2 для сборки ссылок панели. Чтение, без перезаписи конфига."""
        result: dict[str, object] = {
            "installed": self.config.hysteria_config.is_file(),
            "config": str(self.config.hysteria_config),
            "port": None,
            "obfs": None,
            "pin_sha256": None,
            "sni": self.config.hysteria_sni or None,
            "auth_type": None,
            "service": self.config.hysteria_service,
            "state": None,
            "error": None,
        }
        if not self.config.hysteria_config.is_file():
            result["error"] = "конфиг hysteria2 не найден"
            return result
        text = self.config.hysteria_config.read_text(encoding="utf-8")
        listen = HYSTERIA_LISTEN.search(text)
        if listen:
            result["port"] = listen.group(1).rsplit(":", 1)[-1].strip("\"'")
        result["obfs"] = {
            "type": yaml_scalar(text, "obfs", "type"),
            "password": yaml_scalar(text, "salamander", "password"),
        }
        result["auth_type"] = yaml_scalar(text, "auth", "type")
        result["state"] = self.service_state(self.config.hysteria_service)
        if self.config.hysteria_cert.is_file():
            try:
                printed = self._run([str(self.config.openssl_bin), "x509", "-noout", "-fingerprint", "-sha256",
                                     "-in", str(self.config.hysteria_cert)])
            except AgentError as failure:
                result["error"] = str(failure)
            else:
                result["pin_sha256"] = printed.partition("=")[2].replace(":", "").strip()
        else:
            result["error"] = "сертификат hysteria2 не найден"
        return result

    # -- MTProto (telemt Control API) --------------------------------------

    def mt_error(self, failure: urlerror.HTTPError) -> str:
        """Код и текст ошибки движка — по ним оператор видит, что именно отказало."""
        detail = ""
        try:
            body = json.loads(failure.read(65536).decode("utf-8", "replace"))
        except (OSError, ValueError):
            body = None
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            code = str(body["error"].get("code") or "error")
            message = str(body["error"].get("message") or "")
            detail = f"{code}: {message}" if message else code
        if not detail:
            detail = f"http {failure.code} {failure.reason}"
        return detail[:240]

    def mt_api(self, method: str, path: str, body: dict | None = None,
               query: str = "", if_match: str | None = None) -> dict:
        """Один запрос к Control API telemt.

        Адрес берётся только из MTPROTO_API_URL, путь — только из жёсткого списка операций,
        имя клиента предварительно отсеяно регэкспом: passthrough произвольного запроса здесь
        не появляется никогда. Токен — значение `auth_header` из конфига движка.
        """
        if not self.config.mtproto_api_url:
            raise AgentError("MTPROTO_API_URL пуст: Control API движка не настроен")
        url = f"{self.config.mtproto_api_url.rstrip('/')}{path}"
        if query:
            url = f"{url}?{query}"
        headers = {"Accept": "application/json"}
        if self.config.mtproto_api_token:
            headers["Authorization"] = self.config.mtproto_api_token
        if if_match:
            headers["If-Match"] = if_match
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json; charset=utf-8"
        request = urlrequest.Request(url, data=payload, headers=headers, method=method)
        try:
            with urlrequest.urlopen(request, timeout=self.config.command_timeout) as response:  # noqa: S310
                text = response.read(1048576).decode("utf-8", "replace")
        except urlerror.HTTPError as failure:
            raise AgentError(f"telemt отверг запрос: {self.mt_error(failure)}") from failure
        except (urlerror.URLError, OSError) as failure:
            raise AgentError(f"Control API telemt не ответил: {str(failure)[:200]}") from failure
        try:
            envelope = json.loads(text)
        except ValueError as failure:
            raise AgentError("Control API telemt ответил не JSON") from failure
        if not isinstance(envelope, dict):
            raise AgentError("Control API telemt ответил не объектом JSON")
        if not envelope.get("ok"):
            error = envelope.get("error")
            if isinstance(error, dict):
                code = str(error.get("code") or "error")
                message = str(error.get("message") or "")
                raise AgentError((f"{code}: {message}" if message else code)[:240])
            raise AgentError("Control API telemt вернул ok=false без описания")
        return envelope

    def mt_users(self) -> list[dict]:
        rows = self.mt_api("GET", "/v1/users").get("data")
        if not isinstance(rows, list):
            raise AgentError("/v1/users вернул не список клиентов")
        # Клиент без username нельзя ни включить, ни удалить — для панели его не существует.
        return [row for row in rows if isinstance(row, dict) and str(row.get("username") or "")]

    @staticmethod
    def mt_user_row(row: dict, with_links: bool = False) -> dict[str, object]:
        """Проекция UserInfo: только то, что панель показывает, без секретов в лишнем месте.

        current_connections — авторитетное число живых соединений пользователя, оно не
        зависит от опциональной телеметрии и не обнуляется на границе генераций.
        """
        name = str(row.get("username") or "")
        links = row.get("links") if isinstance(row.get("links"), dict) else {}
        active_ips = [str(ip) for ip in (row.get("active_unique_ips_list") or []) if str(ip)]
        result: dict[str, object] = {
            "name": name,
            "enabled": bool(row.get("enabled", True)),
            "in_runtime": bool(row.get("in_runtime", False)),
            "connections": int(row.get("current_connections") or 0),
            "unique_ips": int(row.get("active_unique_ips") or len(active_ips)),
            "active_ips": active_ips,
            "octets": int(row.get("total_octets") or 0),
            "max_tcp_conns": row.get("max_tcp_conns"),
            "max_unique_ips": row.get("max_unique_ips"),
            "data_quota_bytes": row.get("data_quota_bytes"),
            "quota_period": row.get("quota_period"),
            "expires_at": row.get("expiration_rfc3339"),
        }
        if with_links:
            result["links"] = {
                "tls": [str(link) for link in (links.get("tls") or []) if str(link)],
                "secure": [str(link) for link in (links.get("secure") or []) if str(link)],
                "classic": [str(link) for link in (links.get("classic") or []) if str(link)],
                "tls_domains": [
                    {"domain": str(entry.get("domain") or ""), "link": str(entry.get("link") or "")}
                    for entry in (links.get("tls_domains") or [])
                    if isinstance(entry, dict) and str(entry.get("link") or "")
                ],
            }
        return result

    def mt_censorship(self) -> tuple[dict[str, object], str | None]:
        """[censorship] глазами движка плюс revision для оптимистичной записи."""
        envelope = self.mt_api("GET", "/v1/config")
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
        censorship = data.get("censorship") if isinstance(data.get("censorship"), dict) else {}
        domains = [str(domain) for domain in (censorship.get("tls_domains") or []) if str(domain)]
        return (
            {
                "tls_domain": str(censorship.get("tls_domain") or ""),
                "tls_domains": domains,
                "unknown_sni_action": str(censorship.get("unknown_sni_action") or ""),
                "mask": bool(censorship.get("mask", False)),
            },
            envelope.get("revision"),
        )

    def mt_reload_status(self, reload_id: object) -> dict[str, object]:
        """Догоняем терминальный статус перегрузки генерации, но не дольше MT_RELOAD_WAIT."""
        deadline = time.monotonic() + MT_RELOAD_WAIT
        status: dict[str, object] = {"state": "pending", "reload_id": reload_id}
        while True:
            try:
                data = self.mt_api("GET", f"/v1/system/reload/{reload_id}").get("data")
            except AgentError as failure:
                return {"state": "unknown", "reload_id": reload_id, "error": str(failure)}
            status = data if isinstance(data, dict) else {"state": "unknown"}
            status["reload_id"] = reload_id
            if str(status.get("state") or "") in MT_RELOAD_DONE or time.monotonic() >= deadline:
                return status
            time.sleep(MT_RELOAD_POLL)

    def mt_reload(self, patch: dict, revision: str | None) -> dict[str, object]:
        """PATCH /v1/config?reload=drain: живые сессии других клиентов не рвёт сразу."""
        envelope = self.mt_api(
            "PATCH",
            "/v1/config",
            patch,
            query=f"reload=drain&timeout_secs={MT_RELOAD_DRAIN}",
            if_match=revision,
        )
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
        accepted = data.get("reload") if isinstance(data.get("reload"), dict) else {}
        reload_id = accepted.get("reload_id", accepted.get("id"))
        # На live-движке 3.5.16 патч, совпадающий с действующим конфигом, не поднимает
        # вторую генерацию: reload_id отсутствует, а runtime_reload_required = false.
        # Ждать здесь терминального статуса нечего и «ещё идёт» было бы неправдой.
        status = {"state": "unchanged", "reload_id": None} if reload_id is None else self.mt_reload_status(reload_id)
        status["runtime_reload_required"] = bool(data.get("runtime_reload_required"))
        status["process_restart_required"] = bool(data.get("process_restart_required"))
        status["deferred_process_fields"] = list(data.get("deferred_process_fields") or [])
        status["revision"] = data.get("revision") or envelope.get("revision")
        return status

    def mtproto(self) -> dict[str, object]:
        """Снимок MTProto для раздела: клиенты со ссылками, подменные домены, версия движка."""
        result: dict[str, object] = {
            "configured": bool(self.config.mtproto_api_url),
            "reachable": False,
            "service": self.config.mtproto_service,
            "state": None,
            "users": [],
            "censorship": {},
            "version": None,
            "uptime_seconds": None,
            "error": None,
        }
        if not self.config.mtproto_api_url:
            result["error"] = "MTPROTO_API_URL пуст: раздел не обращается к движку telemt на узле"
            return result
        # Статус юнита нужен только там, где панель действительно говорит с движком.
        result["state"] = self.service_state(self.config.mtproto_service) if self.config.mtproto_service else None
        try:
            rows = self.mt_users()
            censorship, _ = self.mt_censorship()
            info = self.mt_api("GET", "/v1/system/info").get("data") or {}
        except AgentError as failure:
            result["error"] = str(failure)
            return result
        result["reachable"] = True
        result["users"] = [self.mt_user_row(row, with_links=True) for row in rows]
        result["censorship"] = censorship
        result["version"] = info.get("version")
        result["uptime_seconds"] = info.get("uptime_seconds")
        result["config_path"] = info.get("config_path")
        return result

    def mt_stats(self) -> dict[str, object]:
        """Только счётчики соединений по клиентам: дешёвый источник для фонового опроса."""
        result: dict[str, object] = {"configured": bool(self.config.mtproto_api_url), "users": [], "error": None}
        if not result["configured"]:
            result["error"] = "MTPROTO_API_URL пуст"
            return result
        try:
            rows = self.mt_users()
        except AgentError as failure:
            result["error"] = str(failure)
            return result
        result["users"] = [self.mt_user_row(row) for row in rows]
        return result

    def mtproto_create(self, name: object) -> dict[str, object]:
        """Новый клиент: секрет генерирует движок, панель его не придумывает и не хранит."""
        username = require_name(name)
        envelope = self.mt_api("POST", "/v1/users", {"username": username})
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
        row = data.get("user") if isinstance(data.get("user"), dict) else {}
        return {
            "user": self.mt_user_row(row or {"username": username}, with_links=True),
            "secret": str(data.get("secret") or ""),
            "revision": envelope.get("revision"),
        }

    def mtproto_action(self, name: object, action: object) -> dict[str, object]:
        """Включить, выключить, сменить секрет или удалить клиента.

        Отключение мгновенно меняет admit и рвёт активные сессии именно этого клиента,
        удаление последнего клиента движок запрещает (409 last_user_forbidden).
        """
        if not isinstance(action, str) or action not in MT_ACTIONS:
            raise AgentError(f"unknown mtproto action {action!r}")
        username = require_name(name)
        method, template = MT_ACTIONS[action]
        envelope = self.mt_api(method, template.format(name=username))
        data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
        row = data.get("user") if isinstance(data.get("user"), dict) else data
        return {
            "action": action,
            "name": username,
            "user": self.mt_user_row(row or {"username": username}, with_links=action == "rotate"),
            "revision": envelope.get("revision"),
        }

    def mtproto_domain(self, domain: object, keep_previous: object) -> dict[str, object]:
        """Смена подменного домена.

        Домен зашит в ee-ссылку, поэтому старые ссылки живы ровно постольку, поскольку
        прежний домен остался в tls_domains: keep_previous решает это за оператора.
        """
        host = require_domain(domain)
        keep = bool(keep_previous)
        censorship, revision = self.mt_censorship()
        current = censorship["tls_domain"]
        extras = list(censorship["tls_domains"])
        pool: list[str] = []
        if keep:
            for candidate in ([current] if current else []) + extras:
                if candidate and candidate != host and candidate not in pool:
                    pool.append(candidate)
        patch = {"censorship": {"tls_domain": host, "tls_domains": pool}}
        status = self.mt_reload(patch, revision)
        return {"domain": host, "previous": current, "pool": pool, "keep_previous": keep, "reload": status}

    def mtproto_pool(self, domains: object) -> dict[str, object]:
        """Явный список доменов, которые остаются действительными для старых ссылок."""
        if not isinstance(domains, (list, tuple)):
            raise AgentError("domains must be a list")
        pool: list[str] = []
        for entry in domains:
            host = require_domain(entry)
            if host not in pool:
                pool.append(host)
        censorship, revision = self.mt_censorship()
        if censorship["tls_domain"] and censorship["tls_domain"] in pool:
            pool.remove(censorship["tls_domain"])
        status = self.mt_reload({"censorship": {"tls_domains": pool}}, revision)
        return {"domain": censorship["tls_domain"], "pool": pool, "reload": status}

    def settings(self) -> dict[str, object]:
        """Non-secret view of agent.conf, so the operator can see what the host applies."""
        try:
            current_endpoint = self.endpoint()
        except AgentError as failure:
            current_endpoint = None
            endpoint_error = str(failure)
        else:
            endpoint_error = None
        return {
            "interface": self.config.interface,
            "network": str(self.config.network),
            "gateway": self.config.gateway,
            "awg_bin": str(self.config.awg_bin),
            "interface_config": str(self.config.interface_config),
            "interface_config_present": self.config.interface_config.is_file(),
            "peers_dir": str(self.config.peers_dir),
            "socket_path": str(self.config.socket_path),
            "socket_group": self.config.socket_group,
            "endpoint_dev": self.config.endpoint_dev,
            "public_endpoint": self.config.public_endpoint,
            "endpoint": current_endpoint,
            "endpoint_error": endpoint_error,
            "client_dns": self.config.client_dns,
            "hysteria_stats_url": self.config.hysteria_stats_url,
            "hysteria_stats_secret_present": bool(self.config.hysteria_stats_secret),
            "mtproto_api_url": self.config.mtproto_api_url,
            "mtproto_api_token_present": bool(self.config.mtproto_api_token),
            "mtproto_service": self.config.mtproto_service,
            "command_timeout": self.config.command_timeout,
            "backup_dir": str(self.config.backup_dir),
            "backup_key_file": str(self.config.backup_key_file),
            "backup_retention": self.config.backup_retention,
        }

    def handle(self, request: dict) -> dict:
        operation = request.get("operation")
        try:
            if operation == "status":
                return self.status()
            if operation == "peers":
                return self.peers()
            if operation == "hy2_stats":
                return self.hy2_stats()
            if operation == "create":
                return self.create(request.get("name"))
            if operation == "enable":
                return self.enable(request.get("public_key"))
            if operation == "disable":
                return self.disable(request.get("public_key"))
            if operation == "delete":
                return self.delete(request.get("public_key"))
            if operation == "hysteria":
                return self.hysteria()
            if operation == "mtproto":
                return self.mtproto()
            if operation == "mt_stats":
                return self.mt_stats()
            if operation == "mtproto_create":
                return self.mtproto_create(request.get("name"))
            if operation == "mtproto_action":
                return self.mtproto_action(request.get("name"), request.get("action"))
            if operation == "mtproto_domain":
                return self.mtproto_domain(request.get("domain"), request.get("keep_previous"))
            if operation == "mtproto_pool":
                return self.mtproto_pool(request.get("domains"))
            if operation == "fail2ban":
                return self.fail2ban()
            if operation == "f2b":
                return self.f2b(request.get("action"), request.get("jail"), request.get("ip"))
            if operation == "settings":
                return self.settings()
            if operation == "backups":
                return self.backups()
            return {"error": f"unsupported operation {operation!r}"}
        except AgentError as failure:
            return {"error": str(failure)}
        except (OSError, ValueError, RuntimeError) as failure:
            return {"error": f"adapter failure: {failure}"}

    # -- socket server -----------------------------------------------------

    def listen(self) -> None:
        self.config.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.config.peers_dir.mkdir(parents=True, exist_ok=True)
        self.config.socket_path.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.config.socket_path))
            if self.config.socket_group >= 0:
                try:
                    os.chown(self.config.socket_path, 0, self.config.socket_group)
                except (PermissionError, OSError):
                    pass
            self.config.socket_path.chmod(0o660)
            server.listen()
            while True:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(self.config.command_timeout)
                    try:
                        request = json.loads(connection.recv(4096).decode())
                        connection.sendall((json.dumps(self.handle(request)) + "\n").encode())
                    except (OSError, ValueError):
                        try:
                            connection.sendall((json.dumps({"error": "malformed request"}) + "\n").encode())
                        except OSError:
                            pass


def main(argv: list[str]) -> int:
    try:
        agent = Agent(load_config())
        if "--serve" in argv:
            agent.listen()
        elif "--migrate" in argv:
            print(json.dumps(agent.migrate(), ensure_ascii=False))
        elif "--apply" in argv:
            print(json.dumps(agent.apply_all(), ensure_ascii=False))
        else:
            print(json.dumps(agent.status(), ensure_ascii=False))
    except (AgentError, OSError, ValueError) as failure:
        print(json.dumps({"error": str(failure)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
