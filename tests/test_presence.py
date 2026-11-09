"""«Кто на связи»: пороги по рукопожатию, дельта принятых байтов и деградация без узла."""
from __future__ import annotations

import pytest

from app import presence as presence_module
from app.presence import BADGES, HANDSHAKE_TTL, STALE_AFTER, TRAFFIC_WINDOW, Presence, human_age, human_bytes


FIRST_KEY = "LeezOkX5ZDoMj4rl9My/osXJZRLvoihZAfLerFiyhy8="
SECOND_KEY = "aB3dE6fH9iK2lM5nP8qR1sT4vW7xY0zA3bC6dE9fG1h="


class Clock:
    """Одни часы для monotonic и wall clock: окна и возраст задаются шагами теста."""

    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def monotonic(self) -> float:
        return self.now

    def time(self) -> float:
        return self.now


class FakeHost:
    """Двойник адаптера: рантайм AWG, Traffic Stats API и клиенты движка меняются между снимками."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.runtime: dict[str, dict] = {}
        self.peers_error: str | None = None
        self.hy2_configured = True
        self.hy2_error: str | None = None
        self.online: dict[str, int] = {}
        self.traffic: dict[str, dict] = {}
        self.mt_configured = True
        self.mt_error: str | None = None
        self.mt_users: dict[str, dict] = {}
        self.calls: list[str] = []

    def peer(self, key, *, endpoint="198.51.100.20:49204", handshake_ago=None, rx=0, tx=0) -> None:
        """handshake_ago=None — рукопожатия не было вовсе, то есть 0 в выводе dump."""
        self.runtime[key] = {
            "endpoint": endpoint,
            "handshake_at": 0 if handshake_ago is None else int(self.clock.now - handshake_ago),
            "rx": rx,
            "tx": tx,
        }

    def mt_client(self, name, *, connections=0, enabled=True, octets=0, active_ips=()) -> None:
        self.mt_users[name] = {
            "name": name,
            "connections": connections,
            "enabled": enabled,
            "unique_ips": len(active_ips),
            "octets": octets,
            "active_ips": list(active_ips),
        }

    def request(self, operation: str, **payload) -> dict:
        self.calls.append(operation)
        if operation == "peers":
            if self.peers_error:
                return {"interface": "awg0", "peers": [], "error": self.peers_error}
            rows = [{"public_key": key, **dict(row)} for key, row in self.runtime.items()]
            return {"interface": "awg0", "peers": rows, "error": None}
        if operation == "hy2_stats":
            return {
                "configured": self.hy2_configured,
                "online": dict(self.online),
                "traffic": {name: dict(entry) for name, entry in self.traffic.items()},
                "error": self.hy2_error,
            }
        if operation == "mt_stats":
            return {
                "configured": self.mt_configured,
                "users": [dict(row) for row in self.mt_users.values()],
                "error": self.mt_error,
            }
        raise AssertionError(f"неожиданная операция {operation!r}")


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def host(clock: Clock, monkeypatch) -> FakeHost:
    instance = FakeHost(clock)
    monkeypatch.setattr(presence_module, "time", clock)
    return instance


@pytest.fixture
def presence(host: FakeHost) -> Presence:
    return Presence(host)


def test_fresh_handshake_is_online(presence: Presence, host: FakeHost) -> None:
    host.peer(FIRST_KEY, handshake_ago=40, rx=5 * 1024**2, tx=3 * 1024**3)
    presence.sample()

    state = presence.awg_state(FIRST_KEY)
    assert state["badge"] == BADGES["online"]
    assert "40 с назад" in state["detail"]
    assert "клиент 198.51.100.20:49204" in state["detail"]
    assert "↓ 3 ГБ · ↑ 5 МБ" in state["detail"]


def test_stale_handshake_with_growing_rx_is_online(presence: Presence, host: FakeHost, clock: Clock) -> None:
    stale = HANDSHAKE_TTL + 600
    host.peer(FIRST_KEY, handshake_ago=stale, rx=1000)
    presence.sample()
    assert presence.awg_state(FIRST_KEY)["badge"] == BADGES["offline"]

    host.peer(FIRST_KEY, handshake_ago=stale + 5, rx=1500)
    clock.advance(5)
    presence.sample()
    assert presence.awg_state(FIRST_KEY)["badge"] == BADGES["online"]


def test_keepalive_growth_holds_online_until_the_window_closes(
    presence: Presence, host: FakeHost, clock: Clock
) -> None:
    host.peer(FIRST_KEY, handshake_ago=10_000, rx=1000)
    presence.sample()
    host.peer(FIRST_KEY, handshake_ago=10_005, rx=1024)
    clock.advance(5)
    presence.sample()

    clock.advance(TRAFFIC_WINDOW - 5)
    assert presence.awg_state(FIRST_KEY)["state"] == "online"
    clock.advance(10)
    assert presence.awg_state(FIRST_KEY)["state"] == "offline"


def test_peer_without_a_handshake_is_never_online(presence: Presence, host: FakeHost) -> None:
    host.peer(SECOND_KEY, endpoint=None)
    presence.sample()

    state = presence.awg_state(SECOND_KEY)
    assert state["badge"] == BADGES["never"]
    assert "рукопожатия не было" in state["detail"]
    assert "адрес клиента не известен" in state["detail"]


def test_peer_missing_from_the_runtime_is_absent(presence: Presence, host: FakeHost) -> None:
    host.peer(FIRST_KEY, handshake_ago=5)
    presence.sample()
    host.runtime.clear()
    presence.sample()

    assert presence.awg_state(FIRST_KEY)["badge"] == BADGES["absent"]


def test_counters_reset_by_readding_a_peer_are_not_growth(presence: Presence, host: FakeHost, clock: Clock) -> None:
    host.peer(FIRST_KEY, handshake_ago=5, rx=9000)
    presence.sample()
    clock.advance(400)
    host.peer(FIRST_KEY, handshake_ago=400, rx=100)
    presence.sample()

    assert presence.awg_state(FIRST_KEY)["state"] == "offline"


def test_interface_failure_hides_statuses_until_the_node_answers(presence: Presence, host: FakeHost) -> None:
    host.peer(FIRST_KEY, handshake_ago=5)
    host.peers_error = "Cannot find device 'awg0'"
    presence.sample()

    state = presence.awg_state(FIRST_KEY)
    assert state["badge"] == BADGES["unknown"]
    assert "Cannot find device" in state["detail"]
    assert presence.errors["awg"]

    host.peers_error = None
    presence.sample()
    assert presence.awg_state(FIRST_KEY)["state"] == "online"
    assert "awg" not in presence.errors


def test_hy2_counts_connections_with_russian_plurals(presence: Presence, host: FakeHost) -> None:
    host.online = {"anna": 1, "boris": 2, "vitja": 7, "olga": 0}
    host.traffic = {"anna": {"tx": 1024, "rx": 2048}}
    presence.sample()

    assert presence.hy2_state("anna")["detail"] == "1 соединение · ↓ 1 КБ · ↑ 2 КБ"
    assert "2 соединения" in presence.hy2_state("boris")["detail"]
    assert "7 соединений" in presence.hy2_state("vitja")["detail"]
    assert presence.hy2_state("boris")["state"] == "online"
    assert presence.hy2_state("olga")["badge"] == BADGES["offline"]
    assert presence.hy2_state("olga")["detail"] == "нет соединений"
    assert presence.hy2_state("нет-такого-клиента")["badge"] == BADGES["offline"]


def test_hy2_without_traffic_stats_is_not_called_offline(presence: Presence, host: FakeHost) -> None:
    host.hy2_configured = False
    host.hy2_error = "HYSTERIA_STATS_URL пуст: trafficStats в конфиге hysteria2 не включён"
    presence.sample()

    state = presence.hy2_state("anna")
    assert state["badge"] == BADGES["unknown"]
    assert "trafficStats" in state["detail"]


def test_hy2_error_clears_when_the_api_answers(presence: Presence, host: FakeHost) -> None:
    host.hy2_error = "Traffic Stats API недоступен: HTTP Error 401"
    presence.sample()
    assert "hy2" in presence.errors

    host.hy2_error = None
    host.online = {"anna": 3}
    presence.sample()
    assert "hy2" not in presence.errors
    assert presence.hy2_state("anna")["state"] == "online"


def test_snapshot_refreshes_only_when_stale(presence: Presence, host: FakeHost, clock: Clock) -> None:
    presence.refresh_if_stale()
    assert host.calls == ["peers", "hy2_stats", "mt_stats"]
    presence.refresh_if_stale()
    assert len(host.calls) == 3

    clock.advance(STALE_AFTER)
    presence.refresh_if_stale()
    assert len(host.calls) == 6
    assert presence.taken_at == clock.now


def test_mt_online_counts_the_engines_own_connections(presence: Presence, host: FakeHost) -> None:
    host.mt_client("anna", connections=1, octets=1024, active_ips=["198.51.100.20"])
    host.mt_client("boris", connections=7)
    host.mt_client("olga", connections=0)
    presence.sample()

    assert presence.mt_state("anna")["detail"] == "1 соединение · клиент 198.51.100.20 · трафик 1 КБ"
    assert "7 соединений" in presence.mt_state("boris")["detail"]
    assert presence.mt_state("boris")["state"] == "online"
    assert presence.mt_state("olga")["badge"] == BADGES["offline"]
    assert presence.mt_state("olga")["detail"] == "нет соединений"


def test_mt_disabled_client_is_offline_not_absent(presence: Presence, host: FakeHost) -> None:
    host.mt_client("anna", connections=2, active_ips=["198.51.100.20"])
    presence.sample()
    assert presence.mt_state("anna")["state"] == "online"

    host.mt_client("anna", connections=0, enabled=False)
    presence.sample()
    state = presence.mt_state("anna")
    assert state["badge"] == BADGES["offline"]
    assert state["detail"] == "клиент выключен"


def test_mt_client_missing_from_the_engine_config_is_absent(presence: Presence, host: FakeHost) -> None:
    host.mt_client("anna", connections=1)
    presence.sample()
    host.mt_users.clear()
    presence.sample()

    state = presence.mt_state("anna")
    assert state["badge"] == BADGES["absent"]
    assert "конфиге движка" in state["detail"]


def test_mt_without_control_api_is_not_called_offline(presence: Presence, host: FakeHost) -> None:
    host.mt_configured = False
    host.mt_error = "MTPROTO_API_URL пуст"
    presence.sample()

    state = presence.mt_state("anna")
    assert state["badge"] == BADGES["unknown"]
    assert "MTPROTO_API_URL" in state["detail"]


def test_mt_error_clears_when_the_engine_answers(presence: Presence, host: FakeHost) -> None:
    host.mt_error = "Control API: HTTP Error 401 unauthorized"
    presence.sample()
    assert "mtproto" in presence.errors
    assert presence.mt_state("anna")["badge"] == BADGES["unknown"]

    host.mt_error = None
    host.mt_client("anna", connections=3)
    presence.sample()
    assert "mtproto" not in presence.errors
    assert presence.mt_state("anna")["state"] == "online"


@pytest.mark.parametrize(
    ("value", "text"),
    [(0, "0 Б"), (999, "999 Б"), (1024, "1 КБ"), (1536, "1,5 КБ"), (1024**2, "1 МБ"), (1024**3, "1 ГБ"),
     (-1, "—"), ("нет", "—")],
)
def test_human_bytes(value: object, text: str) -> None:
    assert human_bytes(value) == text


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(0, "только что"), (20, "20 с назад"), (120, "2 мин назад"), (7200, "2 ч назад"), (300000, "3 сут назад"),
     (-5, "только что")],
)
def test_human_age(seconds: object, text: str) -> None:
    assert human_age(seconds) == text
