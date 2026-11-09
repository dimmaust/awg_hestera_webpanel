"""MTProto в панели: контракт Control API telemt, раздел /mtproto и смена подменного домена."""
from __future__ import annotations

import dataclasses
import io
import json
from pathlib import Path
import time
from urllib import error as urlerror
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

import host_agent
from app.config import Settings
from app.main import create_app
from host_agent import Agent, AgentError

from test_agent import FakeHost, config, host  # noqa: F401 — двойник узла и конфиг хост-агента
from test_app import (  # noqa: F401 — фикстура harness нужна сборке
    EE_NEW,
    EE_OLD,
    MT_SECRET,
    PASSWORD,
    csrf_token,
    harness,
    mt_user,
    signed_in_client,
)


PEER_KEY = "LeezOkX5ZDoMj4rl9My/osXJZRLvoihZAfLerFiyhy8="
HOST = "192.0.2.10"
LINK = f"tg://proxy?server={HOST}&port=443&secret="


# -- двойник Control API ------------------------------------------------------

def header(request, name: str):
    """urllib хранит заголовки в форме capitalize() — читаем так же, как он их кладёт."""
    return request.get_header(name.capitalize())


class ControlApi:
    """Двойник Control API telemt: отвечает на пару (method, path) и помнит запросы."""

    def __init__(self, routes: dict[tuple[str, str], object]) -> None:
        self.routes = routes
        self.calls: list[dict] = []

    def __call__(self, request, timeout=None):
        parts = urlsplit(request.full_url)
        self.calls.append({
            "method": request.get_method(),
            "path": parts.path,
            "query": parts.query,
            "body": json.loads(request.data) if request.data else None,
            "if_match": header(request, "If-Match"),
            "auth": header(request, "Authorization"),
            "content_type": header(request, "Content-Type"),
            "timeout": timeout,
        })
        key = (request.get_method(), parts.path)
        if key not in self.routes:
            raise AssertionError(f"неожиданный запрос к Control API: {key}")
        reply = self.routes[key]
        if isinstance(reply, BaseException):
            raise reply
        if isinstance(reply, RawResponse):
            return reply
        return FakeResponse(reply)

    def of(self, method: str, path: str) -> list[dict]:
        return [call for call in self.calls if (call["method"], call["path"]) == (method, path)]

    @property
    def paths(self) -> list[str]:
        return [f"{call['method']} {call['path']}" for call in self.calls]


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload, ensure_ascii=False).encode()

    def read(self, _limit: int) -> bytes:
        return self.body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args) -> bool:
        return False


class RawResponse(FakeResponse):
    """Ответ не-JSON: так выглядит API за обратным прокси или на заглушке порта."""

    def __init__(self, text: str) -> None:
        self.body = text.encode()


class ReloadClock:
    """Часы перегрузки генерации: sleep двигает время, тест не ждёт по-настоящему."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def __getattr__(self, name):
        return getattr(time, name)


def http_error(path: str, code: int, reason: str, envelope: dict) -> urlerror.HTTPError:
    body = io.BytesIO(json.dumps(envelope, ensure_ascii=False).encode())
    return urlerror.HTTPError(f"http://127.0.0.1:9091{path}", code, reason, {}, body)


@pytest.fixture
def node(config) -> object:
    """Тот же узел, что и в тестах AWG, но с включённым MTPROTO_API_URL."""
    return dataclasses.replace(
        config, mtproto_api_url="http://127.0.0.1:9091/", mtproto_api_token="mt-api-token", mtproto_service="telemt",
    )


def user_row(name="anna", **changes) -> dict:
    row = {
        "username": name,
        "enabled": True,
        "in_runtime": True,
        "current_connections": 2,
        "active_unique_ips": 1,
        "active_unique_ips_list": ["198.51.100.20"],
        "total_octets": 1048576,
        "max_unique_ips": 3,
        "expiration_rfc3339": "2026-12-31T00:00:00Z",
        "links": {
            "classic": [f"{LINK}{MT_SECRET}"],
            "secure": [f"{LINK}dd{MT_SECRET}"],
            "tls": [f"{LINK}{EE_NEW}"],
            "tls_domains": [
                {"domain": "new.example.com", "link": f"{LINK}{EE_NEW}"},
                {"domain": "old.example.com", "link": f"{LINK}{EE_OLD}"},
                {"domain": "old.example.com", "link": ""},
            ],
        },
    }
    for key, value in changes.items():
        row[{"connections": "current_connections", "enabled": "enabled"}.get(key, key)] = value
    return row


CENSORSHIP = {
    "censorship": {
        "tls_domain": "new.example.com",
        "tls_domains": ["old.example.com"],
        "unknown_sni_action": "reject",
        "mask": True,
    }
}

SYSTEM_INFO = {"ok": True, "data": {"version": "telemt 3.3.0", "uptime_seconds": 120,
                                    "config_path": "/etc/telemt/telemt.toml"}}


def control(monkeypatch, routes: dict) -> ControlApi:
    fake = ControlApi(routes)
    monkeypatch.setattr(host_agent.urlrequest, "urlopen", fake)
    return fake


# -- хост-агент: снимок -------------------------------------------------------

def test_mtproto_snapshots_users_censorship_and_version(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {
        ("GET", "/v1/users"): {"ok": True, "data": [user_row(), user_row("boris", enabled=False,
                                                                          current_connections=0, in_runtime=False)]},
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("GET", "/v1/system/info"): SYSTEM_INFO,
    })
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert report["configured"] and report["reachable"]
    assert report["version"] == "telemt 3.3.0" and report["config_path"] == "/etc/telemt/telemt.toml"
    assert report["service"] == "telemt" and report["state"] == "inactive"
    anna = report["users"][0]
    assert anna["connections"] == 2 and anna["unique_ips"] == 1 and anna["octets"] == 1048576
    assert anna["active_ips"] == ["198.51.100.20"] and anna["expires_at"] == "2026-12-31T00:00:00Z"
    assert anna["links"]["tls_domains"] == [
        {"domain": "new.example.com", "link": f"{LINK}{EE_NEW}"},
        {"domain": "old.example.com", "link": f"{LINK}{EE_OLD}"},
    ]
    assert report["censorship"]["tls_domain"] == "new.example.com"
    assert report["censorship"]["tls_domains"] == ["old.example.com"]
    assert report["censorship"]["mask"] is True
    assert fake.paths == ["GET /v1/users", "GET /v1/config", "GET /v1/system/info"]
    assert all(call["auth"] == "mt-api-token" for call in fake.calls)
    assert all(call["timeout"] == node.command_timeout for call in fake.calls)
    assert "mt-api-token" not in json.dumps(report)


def test_mt_stats_carries_counters_without_links(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {("GET", "/v1/users"): {"ok": True, "data": [user_row()]}})
    report = Agent(node, run=host).handle({"operation": "mt_stats"})

    assert report["configured"] is True and report["error"] is None
    assert report["users"][0]["connections"] == 2
    assert "links" not in report["users"][0]
    assert MT_SECRET not in json.dumps(report)
    assert fake.paths == ["GET /v1/users"]


def test_mtproto_without_configuration_opens_nothing(config, host, monkeypatch) -> None:
    def never(request, timeout=None):
        raise AssertionError("без MTPROTO_API_URL запросов к движку не бывает")

    monkeypatch.setattr(host_agent.urlrequest, "urlopen", never)
    report = Agent(config, run=host).handle({"operation": "mtproto"})

    assert report["configured"] is False and report["reachable"] is False
    assert report["users"] == [] and report["censorship"] == {}
    assert "MTPROTO_API_URL" in report["error"]
    assert host.calls == []


def test_mtproto_maps_the_error_envelope(node, host, monkeypatch) -> None:
    control(monkeypatch, {("GET", "/v1/users"): {"ok": False,
                                                 "error": {"code": "api_disabled", "message": "Control API выключен"}}})
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert report["reachable"] is False
    assert "api_disabled" in report["error"] and "Control API выключен" in report["error"]


def test_mtproto_reports_http_status_with_the_engine_code(node, host, monkeypatch) -> None:
    refusal = http_error("/v1/users", 401, "Unauthorized", {"ok": False, "error": {"code": "unauthorized"}})
    control(monkeypatch, {("GET", "/v1/users"): refusal})
    report = Agent(node, run=host).handle({"operation": "mt_stats"})

    assert "unauthorized" in report["error"]
    assert "mt-api-token" not in json.dumps(report)


def test_mtproto_falls_back_to_the_http_status_without_an_error_body(node, host, monkeypatch) -> None:
    refusal = urlerror.HTTPError("http://127.0.0.1:9091/v1/config", 503, "Service Unavailable", {}, None)
    control(monkeypatch, {
        ("GET", "/v1/users"): {"ok": True, "data": []},
        ("GET", "/v1/config"): refusal,
    })
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert "http 503 Service Unavailable" in report["error"]


def test_mtproto_rejects_a_non_json_reply(node, host, monkeypatch) -> None:
    control(monkeypatch, {("GET", "/v1/users"): RawResponse("<html>502 Bad Gateway</html>")})
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert "не JSON" in report["error"]


def test_mtproto_rejects_a_json_array_as_envelope(node, host, monkeypatch) -> None:
    control(monkeypatch, {("GET", "/v1/users"): [1, 2, 3]})
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert "не объектом JSON" in report["error"]


def test_mtproto_survives_a_broken_user_list(node, host, monkeypatch) -> None:
    control(monkeypatch, {
        ("GET", "/v1/users"): {"ok": True, "data": [user_row(), "не объект", {"links": {}}]},
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP},
        ("GET", "/v1/system/info"): {"ok": True, "data": {"version": "telemt 3.3.0"}},
    })
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert [row["name"] for row in report["users"]] == ["anna"]


def test_mtproto_reports_a_socket_failure(node, host, monkeypatch) -> None:
    def refused(request, timeout=None):
        raise urlerror.URLError("Connection refused")

    monkeypatch.setattr(host_agent.urlrequest, "urlopen", refused)
    report = Agent(node, run=host).handle({"operation": "mtproto"})

    assert "не ответил" in report["error"] and "Connection refused" in report["error"]


# -- хост-агент: клиенты ------------------------------------------------------

def test_mtproto_create_returns_the_secret_the_engine_generated(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {
        ("POST", "/v1/users"): {"ok": True, "data": {"user": user_row(), "secret": MT_SECRET}, "revision": "r-8"},
    })
    report = Agent(node, run=host).handle({"operation": "mtproto_create", "name": "anna"})

    assert report["secret"] == MT_SECRET and report["revision"] == "r-8"
    assert report["user"]["links"]["tls"] == [f"{LINK}{EE_NEW}"]
    assert fake.calls[0]["body"] == {"username": "anna"}
    assert fake.calls[0]["method"] == "POST"


@pytest.mark.parametrize("name", ["", "инна", "anna smith", "../etc", "a" * 33])
def test_mtproto_create_rejects_a_bad_name(node, host, name: str) -> None:
    report = Agent(node, run=host).handle({"operation": "mtproto_create", "name": name})

    assert "peer name must be" in report["error"]


def test_mtproto_actions_use_the_documented_paths(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {
        # enable/disable отдают UserInfo, rotate-secret — CreateUserResponse, delete — DeleteUserResponse.
        ("POST", "/v1/users/anna/enable"): {"ok": True, "data": user_row(), "revision": "r-9"},
        ("POST", "/v1/users/anna/disable"): {
            "ok": True, "data": user_row(enabled=False, current_connections=0, in_runtime=False), "revision": "r-9"},
        ("POST", "/v1/users/anna/rotate-secret"): {
            "ok": True, "data": {"user": user_row(), "secret": "Bb" + "b" * 30}, "revision": "r-10"},
        ("DELETE", "/v1/users/anna"): {"ok": True, "data": {"username": "anna", "in_runtime": False},
                                       "revision": "r-11"},
    })
    agent = Agent(node, run=host)

    enabled = agent.handle({"operation": "mtproto_action", "name": "anna", "action": "enable"})
    disabled = agent.handle({"operation": "mtproto_action", "name": "anna", "action": "disable"})
    rotated = agent.handle({"operation": "mtproto_action", "name": "anna", "action": "rotate"})
    deleted = agent.handle({"operation": "mtproto_action", "name": "anna", "action": "delete"})

    assert fake.paths == [
        "POST /v1/users/anna/enable",
        "POST /v1/users/anna/disable",
        "POST /v1/users/anna/rotate-secret",
        "DELETE /v1/users/anna",
    ]
    assert enabled["user"]["enabled"] is True and enabled["user"]["name"] == "anna"
    assert disabled["user"]["enabled"] is False and disabled["user"]["connections"] == 0
    assert disabled["revision"] == "r-9"
    assert "links" not in disabled["user"]  # ссылки приносит только rotate
    assert rotated["user"]["links"]["secure"]
    assert deleted["user"]["name"] == "anna" and deleted["user"]["in_runtime"] is False
    assert deleted["revision"] == "r-11"


@pytest.mark.parametrize("action", ["purge", "restart", "", None])
def test_mtproto_rejects_an_unknown_action(node, host, action: object) -> None:
    report = Agent(node, run=host).handle({"operation": "mtproto_action", "name": "anna", "action": action})

    assert "unknown mtproto action" in report["error"]


def test_mtproto_cannot_delete_the_last_client(node, host, monkeypatch) -> None:
    refusal = http_error("/v1/users/anna", 409, "Conflict",
                         {"ok": False, "error": {"code": "last_user_forbidden", "message": "клиентов не останется"}})
    control(monkeypatch, {("DELETE", "/v1/users/anna"): refusal})
    report = Agent(node, run=host).handle({"operation": "mtproto_action", "name": "anna", "action": "delete"})

    assert "last_user_forbidden" in report["error"]
    assert "клиентов не останется" in report["error"]


def test_mtproto_rename_is_not_an_operation_the_panel_offers(node, host) -> None:
    with pytest.raises(AgentError):
        Agent(node, run=host).mtproto_action("anna", "rename")


# -- хост-агент: подменный домен ----------------------------------------------

def domain_routes(reload_reply: dict, status_reply: dict) -> dict:
    return {
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("PATCH", "/v1/config"): reload_reply,
        ("GET", "/v1/system/reload/gen-9"): {"ok": True, "data": status_reply},
    }


def test_mtproto_domain_keeps_previous_domains_in_the_pool(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, domain_routes(
        {"ok": True, "data": {"reload": {"reload_id": "gen-9"}, "revision": "r-8"}},
        {"state": "succeeded", "reload_id": "gen-9"},
    ))
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": "OTHER.example.com", "keep_previous": True}
    )

    assert report["domain"] == "other.example.com" and report["previous"] == "new.example.com"
    assert report["pool"] == ["new.example.com", "old.example.com"]
    assert report["reload"]["state"] == "succeeded"
    patch = fake.of("PATCH", "/v1/config")[0]
    assert patch["body"] == {"censorship": {"tls_domain": "other.example.com",
                                            "tls_domains": ["new.example.com", "old.example.com"]}}
    assert patch["if_match"] == "r-7"
    assert patch["query"] == "reload=drain&timeout_secs=30"
    assert report["reload"]["revision"] == "r-8"


def test_mtproto_domain_without_keep_previous_drops_the_pool(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("PATCH", "/v1/config"): {"ok": True, "data": {"reload": {"id": "gen-9"}}},
        ("GET", "/v1/system/reload/gen-9"): {"ok": True, "data": {"state": "rolled_back"}},
    })
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": "other.example.com", "keep_previous": False}
    )

    assert report["pool"] == []
    assert fake.of("PATCH", "/v1/config")[0]["body"] == {"censorship": {"tls_domain": "other.example.com",
                                                                        "tls_domains": []}}
    assert report["reload"]["state"] == "rolled_back"


def test_mtproto_domain_no_op_patch_is_not_reported_as_a_running_reload(node, host, monkeypatch) -> None:
    """Ответ живого telemt 3.5.16, когда патч совпал с действующим конфигом: генерации нет."""
    fake = control(monkeypatch, {
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("PATCH", "/v1/config"): {"ok": True, "data": {"reload": {"state": "pending", "reload_id": None},
                                                       "runtime_reload_required": False,
                                                       "process_restart_required": False,
                                                       "revision": "r-7"}},
    })
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": "new.example.com", "keep_previous": True}
    )

    assert report["reload"]["state"] == "unchanged"
    assert report["reload"]["runtime_reload_required"] is False
    assert fake.paths == ["GET /v1/config", "PATCH /v1/config"]


@pytest.mark.parametrize("domain", ["", "example", "example.com/path", "-bad.example.com", "не-домен.com",
                                    "a" * 254 + ".com", "example.com:443", "two..dots.com"])
def test_mtproto_domain_rejects_a_bad_hostname(node, host, domain: str) -> None:
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": domain, "keep_previous": True}
    )

    assert "hostname" in report["error"]


def test_mtproto_domain_waits_out_a_pending_reload(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, domain_routes(
        {"ok": True, "data": {"reload": {"reload_id": "gen-9"}, "runtime_reload_required": True,
                              "process_restart_required": False, "deferred_process_fields": ["log.level"]}},
        {"state": "pending"},
    ))
    monkeypatch.setattr(host_agent, "time", ReloadClock())
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": "other.example.com", "keep_previous": True}
    )

    reload = report["reload"]
    assert reload["state"] == "pending" and reload["reload_id"] == "gen-9"
    assert reload["runtime_reload_required"] is True and reload["process_restart_required"] is False
    assert reload["deferred_process_fields"] == ["log.level"]
    # бюджет ожидания исчерпан шагами по MT_RELOAD_POLL: агент опрашивает перегрузку, но не вечно
    assert 1 < len(fake.of("GET", "/v1/system/reload/gen-9")) < 20


def test_mtproto_domain_survives_a_lost_reload_status(node, host, monkeypatch) -> None:
    control(monkeypatch, {
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("PATCH", "/v1/config"): {"ok": True, "data": {"reload": {"reload_id": "gen-9"}}},
        ("GET", "/v1/system/reload/gen-9"): http_error("/v1/system/reload/gen-9", 404, "Not Found",
                                                       {"ok": False, "error": {"code": "not_found"}}),
    })
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": "other.example.com", "keep_previous": True}
    )

    assert report["domain"] == "other.example.com"
    assert report["reload"]["state"] == "unknown" and "not_found" in report["reload"]["error"]


def test_mtproto_domain_refuses_a_conflicting_revision(node, host, monkeypatch) -> None:
    control(monkeypatch, {
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("PATCH", "/v1/config"): http_error("/v1/config", 409, "Conflict",
                                            {"ok": False, "error": {"code": "revision_conflict"}}),
    })
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_domain", "domain": "other.example.com", "keep_previous": True}
    )

    assert "revision_conflict" in report["error"]


def test_mtproto_pool_replaces_the_pool_and_drops_the_primary(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {
        ("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"},
        ("PATCH", "/v1/config"): {"ok": True, "data": {"reload": None, "revision": "r-13"}},
    })
    report = Agent(node, run=host).handle(
        {"operation": "mtproto_pool", "domains": ["new.example.com", "OLD.example.com", "old.example.com"]}
    )

    assert report["pool"] == ["old.example.com"] and report["domain"] == "new.example.com"
    assert fake.of("PATCH", "/v1/config")[0]["body"] == {"censorship": {"tls_domains": ["old.example.com"]}}
    assert report["reload"]["state"] == "unchanged" and report["reload"]["reload_id"] is None


def test_mtproto_pool_rejects_a_string_of_domains(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"}})
    report = Agent(node, run=host).handle({"operation": "mtproto_pool", "domains": "old.example.com"})

    assert "must be a list" in report["error"]
    assert fake.calls == []


def test_mtproto_pool_rejects_a_bad_entry_without_writing(node, host, monkeypatch) -> None:
    fake = control(monkeypatch, {("GET", "/v1/config"): {"ok": True, "data": CENSORSHIP, "revision": "r-7"}})
    report = Agent(node, run=host).handle({"operation": "mtproto_pool", "domains": ["old.example.com", "плохой.com"]})

    assert "hostname" in report["error"]
    assert fake.calls == []


def test_settings_never_prints_the_api_token(node, host) -> None:
    report = Agent(node, run=host).handle({"operation": "settings"})

    assert report["mtproto_api_url"] == "http://127.0.0.1:9091/"
    assert report["mtproto_service"] == "telemt"
    assert report["mtproto_api_token_present"] is True
    assert "mt-api-token" not in json.dumps(report)


# -- веб-слой: страница -------------------------------------------------------

@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(tmp_path / "panel.sqlite3", "x" * 32, "admin", PASSWORD)


@pytest.fixture
def client(settings, harness) -> TestClient:
    return signed_in_client(settings)


def test_mtproto_page_lists_links_by_domain(client, harness) -> None:
    harness.add_mt_user()
    harness.add_mt_user(name="boris", enabled=False, connections=0, active_ips=[], links={})
    with client:
        page = client.get("/mtproto")

    assert page.status_code == 200
    assert "telemt 3.3.0" in page.text and "192.0.2.10" in page.text
    # амперсанды в ссылке страница экранирует, поэтому проверяем только секрет с доменом
    assert f"secret={EE_NEW}" in page.text and f"secret={EE_OLD}" in page.text
    assert f"secret=dd{MT_SECRET}" in page.text
    assert "new.example.com" in page.text and "old.example.com" in page.text
    assert "boris" in page.text and "Ссылок нет" in page.text
    assert "presence-online" in page.text and "presence-offline" in page.text
    assert 'action="/mtproto/domain"' in page.text and 'action="/mtproto/pool"' in page.text


def test_mtproto_page_names_the_primary_domain_first(client, harness) -> None:
    harness.add_mt_user()
    with client:
        body = client.get("/mtproto").text

    assert body.index("QR · new.example.com") < body.index("QR · old.example.com")


def test_mtproto_page_explains_an_unconfigured_engine(client, harness) -> None:
    harness.mtproto_payload = {"configured": False, "reachable": False, "users": [], "censorship": {},
                               "error": "MTPROTO_API_URL пуст: телемет на узле не управляется панелью"}
    harness.mt_stats_payload = {"configured": False, "users": [], "error": "MTPROTO_API_URL пуст"}
    with client:
        body = client.get("/mtproto").text

    assert "MTPROTO_API_URL" in body and "agent.conf" in body
    assert 'action="/mtproto/domain"' not in body


def test_mtproto_page_does_not_invent_statuses_when_the_poll_fails(client, harness) -> None:
    harness.add_mt_user()
    harness.mt_stats_payload = {"configured": True, "users": [],
                                "error": "telemt отверг запрос: api_disabled"}
    with client:
        body = client.get("/mtproto").text

    assert "ОПРОС ОНЛАЙНА НЕ УДАЛСЯ" in body and "api_disabled" in body
    assert "presence-unknown" in body
    assert "presence-online" not in body and "presence-offline" not in body


def test_mtproto_page_does_not_claim_a_missing_host_agent(client, harness) -> None:
    """Раздел без WG-интерфейса не имеет права писать «БЕЗ ХОСТ-АГЕНТА»: агент там как раз отвечает."""
    harness.add_mt_user()
    with client:
        body = client.get("/mtproto").text

    assert "ХОСТ: агент отвечает" in body
    assert "БЕЗ ХОСТ-АГЕНТА" not in body


def test_mtproto_page_names_the_dead_host_agent(client, harness) -> None:
    harness.mtproto_payload = {"error": "host-side adapter is unavailable"}
    harness.mt_stats_payload = {"error": "host-side adapter is unavailable"}
    with client:
        body = client.get("/mtproto").text

    assert "ХОСТ: агент не ответил" in body and "БЕЗ ХОСТ-АГЕНТА" not in body


# -- веб-слой: клиенты --------------------------------------------------------

def test_creating_an_mtproto_client_asks_the_engine(client, harness) -> None:
    with client:
        response = client.post("/mtproto", data={"name": "galya", "csrf_token": csrf_token(client)},
                              follow_redirects=False)
        body = client.get("/mtproto").text

    assert response.status_code == 303 and response.headers["location"] == "/mtproto"
    assert harness.operations("mtproto_create") == [{"name": "galya"}]
    assert "Клиент galya создан" in body


@pytest.mark.parametrize("name", ["инна", "anna smith", "x" * 33])
def test_bad_mtproto_names_never_reach_the_engine(client, harness, name: str) -> None:
    with client:
        client.post("/mtproto", data={"name": name, "csrf_token": csrf_token(client)}, follow_redirects=False)

    assert harness.operations("mtproto_create") == []


def test_mtproto_name_conflicts_with_a_peer_or_another_client(client, settings, harness) -> None:
    with client:
        csrf = csrf_token(client)
        client.post("/users", data={"name": "sergei", "expires_at": "", "csrf_token": csrf}, follow_redirects=False)
        client.post("/mtproto", data={"name": "sergei", "csrf_token": csrf_token(client)}, follow_redirects=False)
        occupied_by_peer = client.get("/mtproto").text
        harness.add_mt_user(name="den")
        client.post("/mtproto", data={"name": "den", "csrf_token": csrf_token(client)}, follow_redirects=False)
        occupied_by_engine = client.get("/mtproto").text

    assert "уже занято" in occupied_by_peer
    assert harness.operations("mtproto_create") == []
    assert "уже занято" in occupied_by_engine


def test_engine_rejection_is_reported_and_stores_nothing(client, harness) -> None:
    # last_user_forbidden — код про удаление; на создании он не должен получить перевод про
    # «последнего клиента», иначе панель начнёт врать про операцию, которой не было.
    harness.mt_error = "last_user_forbidden"
    with client:
        client.post("/mtproto", data={"name": "galya", "csrf_token": csrf_token(client)}, follow_redirects=False)
        body = client.get("/mtproto").text

    assert "Движок не выполнил создание клиента galya" in body
    assert "последний в конфиге" not in body
    assert harness.operations("mtproto_create") == [{"name": "galya"}]


def test_creating_an_existing_name_explains_the_engine_code(client, harness) -> None:
    harness.mt_error = "409: user_exists"
    with client:
        client.post("/mtproto", data={"name": "galya", "csrf_token": csrf_token(client)}, follow_redirects=False)
        body = client.get("/mtproto").text

    assert "уже есть в конфиге движка" in body and "user_exists" in body


@pytest.mark.parametrize(("action", "phrase"), [
    ("disable", "выключен"),
    ("enable", "снова принимается"),
    ("rotate", "Секрет anna заменён"),
    ("delete", "удалён из конфига движка"),
])
def test_mtproto_actions_forward_the_name(client, harness, action: str, phrase: str) -> None:
    harness.add_mt_user()
    with client:
        response = client.post(f"/mtproto/anna/{action}", data={"csrf_token": csrf_token(client)},
                              follow_redirects=False)
        body = client.get("/mtproto").text

    assert response.status_code == 303
    assert harness.operations("mtproto_action")[-1] == {"name": "anna", "action": action}
    assert phrase in body


def test_mtproto_route_rejects_an_action_the_panel_does_not_know(client, harness) -> None:
    with client:
        response = client.post("/mtproto/anna/rename", data={"csrf_token": csrf_token(client)})

    assert response.status_code == 404
    assert harness.operations("mtproto_action") == []


def test_mtproto_action_errors_reach_the_operator(client, harness) -> None:
    harness.add_mt_user()
    harness.mt_error = "last_user_forbidden: клиентов не останется"
    with client:
        client.post("/mtproto/anna/delete", data={"csrf_token": csrf_token(client)}, follow_redirects=False)
        body = client.get("/mtproto").text

    assert "Клиент anna — последний в конфиге движка" in body
    assert "last_user_forbidden" in body and "Движок не выполнил" not in body


def test_deleting_the_last_client_is_not_offered_as_a_button(client, harness) -> None:
    """Один клиент в конфиге — кнопки «Удалить» на странице нет: движок откажет, а оператор
    будет жать её трижды, как и было на живом узле 08.11 (аудит 14:32:32/43/48)."""
    harness.add_mt_user()
    with client:
        body = client.get("/mtproto").text

    assert 'action="/mtproto/anna/delete"' not in body
    assert "Удалить нельзя: это последний клиент" in body
    assert 'action="/mtproto/anna/rotate"' in body and 'action="/mtproto/anna/disable"' in body


def test_deleting_is_offered_while_clients_are_not_alone(client, harness) -> None:
    harness.add_mt_user()
    harness.add_mt_user(name="boris")
    with client:
        body = client.get("/mtproto").text

    assert 'action="/mtproto/anna/delete"' in body and 'action="/mtproto/boris/delete"' in body
    assert "Удалить нельзя" not in body


# -- веб-слой: домены ---------------------------------------------------------

def test_domain_switch_forwards_the_keep_previous_flag(client, harness) -> None:
    with client:
        kept = client.post("/mtproto/domain",
                          data={"domain": "other.example.com", "keep_previous": "on", "csrf_token": csrf_token(client)},
                          follow_redirects=False)
        dropped = client.post("/mtproto/domain", data={"domain": "third.example.com",
                                                       "csrf_token": csrf_token(client)}, follow_redirects=False)

    assert kept.status_code == 303 and dropped.status_code == 303
    assert harness.operations("mtproto_domain") == [
        {"domain": "other.example.com", "keep_previous": True},
        {"domain": "third.example.com", "keep_previous": False},
    ]


def test_domain_flash_explains_the_reload_and_the_remaining_pool(client, harness) -> None:
    with client:
        client.post("/mtproto/domain", data={"domain": "other.example.com", "keep_previous": "on",
                                             "csrf_token": csrf_token(client)}, follow_redirects=False)
        body = client.get("/mtproto").text

    assert "перегрузка генерации завершена" in body
    assert "В пуле остались прежние" in body and "new.example.com" in body


def test_domain_flash_warns_when_old_links_die(client, harness) -> None:
    harness.mtproto_domain_payload = {"domain": "other.example.com", "previous": "new.example.com", "pool": [],
                                      "keep_previous": False, "reload": {"state": "rolled_back"}}
    with client:
        client.post("/mtproto/domain", data={"domain": "other.example.com", "csrf_token": csrf_token(client)},
                    follow_redirects=False)
        body = client.get("/mtproto").text

    assert "откатил перегрузку" in body and "старые ee-ссылки" in body


def test_domain_flash_says_nothing_changed_when_the_engine_skipped_reload(client, harness) -> None:
    harness.mtproto_domain_payload = {"domain": "new.example.com", "previous": "new.example.com", "pool": [],
                                      "keep_previous": True, "reload": {"state": "unchanged", "reload_id": None}}
    with client:
        client.post("/mtproto/domain", data={"domain": "new.example.com", "keep_previous": "on",
                                             "csrf_token": csrf_token(client)}, follow_redirects=False)
        body = client.get("/mtproto").text

    assert "ничего не изменилось" in body
    assert "перегрузка генерации ещё идёт" not in body


def test_pool_form_sends_only_the_checked_domains(client, harness) -> None:
    with client:
        response = client.post("/mtproto/pool", data={"domains": ["old.example.com", "third.example.com"],
                                                     "csrf_token": csrf_token(client)}, follow_redirects=False)
        body = client.get("/mtproto").text

    assert response.status_code == 303
    assert harness.operations("mtproto_pool")[-1] == {"domains": ["old.example.com", "third.example.com"]}
    assert "В пуле: old.example.com" in body


def test_pool_errors_are_shown_without_a_partial_write(client, harness) -> None:
    harness.mt_error = "hostname must be"
    with client:
        client.post("/mtproto/pool", data={"domains": ["плохой.com"], "csrf_token": csrf_token(client)},
                    follow_redirects=False)
        body = client.get("/mtproto").text

    assert "Пул доменов не изменён" in body


# -- веб-слой: QR, другие страницы и CSRF ------------------------------------

def test_qr_route_prefers_the_requested_domain(client, harness) -> None:
    harness.add_mt_user()
    with client:
        for query in ("", f"?domain=old.example.com", f"?domain=NEW.example.com"):
            response = client.get(f"/mtproto/anna/qr{query}")
            assert response.status_code == 200
            assert response.headers["content-type"] == "image/png"
            assert len(response.content) > 100


def test_qr_route_falls_back_to_the_domainless_link(client, harness) -> None:
    harness.add_mt_user(name="boris", links={"secure": [f"{LINK}dd{MT_SECRET}"]})
    with client:
        assert client.get("/mtproto/boris/qr").status_code == 200


def test_qr_route_reports_a_missing_client_or_link(client, harness) -> None:
    harness.add_mt_user()
    with client:
        assert client.get("/mtproto/kto/qr").status_code == 404
        harness.add_mt_user(name="boris", links={})
        assert client.get("/mtproto/boris/qr").status_code == 404


def test_dashboard_and_services_show_the_engine(client, harness) -> None:
    harness.add_mt_user(name="galya")
    harness.add_mt_user(name="den", connections=0)
    with client:
        dashboard = client.get("/").text
        services = client.get("/services").text

    assert "MTPROTO / TELEMT" in dashboard and "1 НА СВЯЗИ" in dashboard
    assert "MTProto 1 из 2" in dashboard
    assert "telemt 3.3.0" in services and "new.example.com" in services


def test_settings_page_shows_the_api_url_but_never_the_token(client, harness) -> None:
    harness.settings_payload["mtproto_api_token"] = "mt-api-token"
    with client:
        body = client.get("/settings").text

    assert "http://127.0.0.1:9091" in body
    assert "токен задан" in body
    assert "mt-api-token" not in body


@pytest.mark.parametrize(("path", "data"), [
    ("/mtproto", {"name": "galya"}),
    ("/mtproto/anna/disable", {}),
    ("/mtproto/domain", {"domain": "other.example.com"}),
    ("/mtproto/pool", {"domains": ["old.example.com"]}),
])
def test_mtproto_posts_need_a_csrf_token(client, harness, path: str, data: dict) -> None:
    with client:
        response = client.post(path, data={**data, "csrf_token": "wrong"})

    assert response.status_code == 400
    assert [operation for operation, _ in harness.log if operation.startswith("mtproto")] == []
