from datetime import date, timedelta
from pathlib import Path
import time

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.awg import AwgAdapter, AwgStatus
from app.config import Settings
from app.db import connect
from app.main import create_app
from app.security import hash_password


PASSWORD = "correct horse battery staple"
# Панель обязывает заменить пароль установщика при первом входе, поэтому почти все тесты
# работают уже с заменённым.
CHANGED_PASSWORD = "rotated horse battery staple"
FIRST_KEY = "LeezOkX5ZDoMj4rl9My/osXJZRLvoihZAfLerFiyhy8="
SECOND_KEY = "aB3dE6fH9iK2lM5nP8qR1sT4vW7xY0zA3bC6dE9fG1h="
MT_SECRET = "Aa" * 16
# ee-ссылка несёт домен в hex: панель отдаёт её как есть, а меняет только пул доменов.
EE_NEW = MT_SECRET + "6e65772e6578616d706c652e636f6d"
EE_OLD = MT_SECRET + "6f6c642e6578616d706c652e636f6d"
MT_OPERATIONS = {"mtproto", "mt_stats", "mtproto_create", "mtproto_action", "mtproto_domain", "mtproto_pool"}


def mt_user(name: str = "anna", **changes) -> dict:
    """Строка клиента такой, её возвращает хост-агент: проекция UserInfo из telemt."""
    link = f"tg://proxy?server=192.0.2.10&port=443&secret="
    row = {
        "name": name,
        "enabled": True,
        "in_runtime": True,
        "connections": 2,
        "unique_ips": 1,
        "active_ips": ["198.51.100.20"],
        "octets": 1048576,
        "max_tcp_conns": None,
        "max_unique_ips": 3,
        "data_quota_bytes": None,
        "quota_period": None,
        "expires_at": None,
        "links": {
            "tls": [f"{link}{EE_NEW}"],
            "secure": [f"{link}dd{MT_SECRET}"],
            "classic": [f"{link}{MT_SECRET}"],
            "tls_domains": [
                {"domain": "new.example.com", "link": f"{link}{EE_NEW}"},
                {"domain": "old.example.com", "link": f"{link}{EE_OLD}"},
            ],
        },
    }
    row.update(changes)
    return row


class Harness:
    """Stands in for the Unix-socket adapter so routes are tested without a host."""

    def __init__(self) -> None:
        self.log: list[tuple[str, dict]] = []
        self.keys = iter([FIRST_KEY, SECOND_KEY])
        self.addresses = iter(["10.66.0.2", "10.66.0.3"])
        self.key_override: str | None = None
        self.create_error: str | None = None
        self.action_error: str | None = None
        self.f2b_error: str | None = None
        self.status_payload = AwgStatus(True, "awg0", "amneziawg-tools v3.1-test", None, 1234, 1, 1, 0)
        self.fail2ban_payload: dict = {
            "installed": True,
            "running": True,
            "jails": [
                {"name": "sshd", "failed": 0, "banned": 2, "total": 7, "banned_ips": ["203.0.113.9", "198.51.100.4"]}
            ],
        }
        self.settings_payload: dict = {
            "interface": "awg0",
            "network": "10.66.0.0/24",
            "gateway": "10.66.0.1",
            "awg_bin": "/usr/bin/awg",
            "interface_config": "/etc/amnezia/amneziawg/awg0.conf",
            "interface_config_present": True,
            "peers_dir": "/etc/amnezia/amneziawg/panel-peers",
            "socket_path": "/run/awg-panel/agent.sock",
            "socket_group": 10001,
            "endpoint_dev": "ens3",
            "public_endpoint": "",
            "endpoint": "192.0.2.10",
            "endpoint_error": None,
            "client_dns": "1.1.1.1",
            "command_timeout": 5,
            "mtproto_api_url": "http://127.0.0.1:9091",
            "mtproto_api_token_present": True,
            "mtproto_service": "telemt",
            "backup_dir": "/var/backups/awg-panel",
            "backup_key_file": "/etc/awg-panel/backup.key",
            "backup_retention": 7,
        }
        self.backups_payload: dict = {
            "directory": "/var/backups/awg-panel",
            "exists": True,
            "retention": 7,
            "count": 1,
            "archives": [
                {"name": "awg-panel-20261105-033000.tar.gz.enc", "size": 40960, "created": "2026-11-05 03:30 UTC"}
            ],
            "source_db": "/opt/awg-panel/data/panel.sqlite3",
            "source_present": True,
            "key_present": True,
        }
        self.peers_payload: dict = {"interface": "awg0", "peers": [], "error": None}
        self.hy2_stats_payload: dict = {"configured": True, "online": {}, "traffic": {}, "error": None}
        self.mtproto_payload: dict = {
            "configured": True,
            "reachable": True,
            "service": "telemt",
            "state": "active",
            "version": "telemt 3.3.0",
            "uptime_seconds": 120,
            "config_path": "/etc/telemt/telemt.toml",
            "error": None,
            "censorship": {
                "tls_domain": "new.example.com",
                "tls_domains": ["old.example.com"],
                "unknown_sni_action": "reject",
                "mask": True,
            },
            "users": [],
        }
        self.mt_stats_payload: dict = {"configured": True, "error": None, "users": []}
        self.mtproto_create_payload: dict = {"user": mt_user(), "secret": MT_SECRET, "revision": "r-8"}
        self.mtproto_action_payload: dict = {"action": "disable", "name": "anna", "revision": "r-9",
                                             "user": mt_user()}
        self.mtproto_domain_payload: dict = {
            "domain": "other.example.com",
            "previous": "new.example.com",
            "pool": ["new.example.com", "old.example.com"],
            "keep_previous": True,
            "reload": {"state": "succeeded", "reload_id": "gen-9", "revision": "r-10"},
        }
        self.mtproto_pool_payload: dict = {"domain": "new.example.com", "pool": ["old.example.com"],
                                           "reload": {"state": "pending", "reload_id": "gen-11"}}
        self.mt_error: str | None = None
        self.hysteria_payload: dict = {
            "installed": True,
            "config": "/etc/hysteria/config.yaml",
            "port": "43522",
            "obfs": {"type": "salamander", "password": "ObfsSecret"},
            "pin_sha256": "0310A1582FF0EE6AFF70A546F2EFB6175ABD6418D2AC3013BE4DA7C100B90DAC",
            "sni": "www.bing.com",
            "auth_type": "http",
            "service": "hysteria-server",
            "state": "active",
            "error": None,
        }

    def add_mt_user(self, **changes) -> dict:
        """Клиент движка появляется в обоих ответах: список на странице и опрос онлайна."""
        row = mt_user(**changes)
        self.mtproto_payload["users"].append(row)
        self.mt_stats_payload["users"].append({key: value for key, value in row.items() if key != "links"})
        return row

    def operations(self, name: str) -> list[dict]:
        return [payload for operation, payload in self.log if operation == name]

    def status(self) -> AwgStatus:
        self.log.append(("status", {}))
        return self.status_payload

    def request(self, operation: str, **payload) -> dict:
        self.log.append((operation, payload))
        if operation in MT_OPERATIONS:
            reply = dict(getattr(self, f"{operation}_payload"))
            if self.mt_error:
                reply["error"] = self.mt_error
            return reply
        if operation in {"fail2ban", "settings", "backups", "hysteria", "peers", "hy2_stats"}:
            return getattr(self, f"{operation}_payload")
        if operation == "f2b":
            if self.f2b_error:
                return {"error": self.f2b_error}
            return {
                "action": payload["action"],
                "jail": payload["jail"],
                "ip": payload["ip"],
                "banned": 3 if payload["action"] == "ban" else 1,
                "banned_ips": ["203.0.113.9", "198.51.100.4", payload["ip"]],
            }
        if operation == "create":
            if self.create_error:
                return {"error": self.create_error}
            return {
                "name": payload["name"],
                "public_key": self.key_override or next(self.keys),
                "address": next(self.addresses),
                "config": "[Interface]\nPrivateKey = FAKE=\nAddress = 10.66.0.2/32\nJc = 6\n",
            }
        if operation in {"enable", "disable", "delete"}:
            if self.action_error:
                return {"error": self.action_error}
            return {"status": {"enable": "active", "disable": "disabled", "delete": "deleted"}[operation]}
        return {"error": f"unsupported operation {operation!r}"}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(tmp_path / "panel.sqlite3", "x" * 32, "admin", PASSWORD)


@pytest.fixture
def harness(monkeypatch) -> Harness:
    instance = Harness()
    monkeypatch.setattr(main_module, "AwgAdapter", lambda socket_path, timeout: instance)
    return instance


def sign_in(client: TestClient, password: str) -> str:
    """Вход без перехода по редиректу: возвращает адрес, на который панель отправила после логина."""
    csrf = client.get("/login").text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        "/login", data={"login": "admin", "password": password, "csrf_token": csrf}, follow_redirects=False
    )
    assert response.status_code == 303
    return response.headers["location"]


def submit_password_change(client: TestClient, current: str, new: str, path: str = "/password") -> str:
    """Форма смены пароля на /settings и /password одинаковы по полям и по поведению."""
    csrf = client.get(path).text.split('name="csrf_token" value="')[1].split('"')[0]
    response = client.post(
        path,
        data={"current_password": current, "new_password": new, "csrf_token": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response.headers["location"]


def signed_in_client(settings, app=None, peer=("testclient", 50000)) -> TestClient:
    client = TestClient(app or create_app(settings), client=peer)
    with client:
        # пароль из установщика действует ровно до первого входа, поэтому тест здесь проходит
        # через обязательную замену и дальше работает с CHANGED_PASSWORD
        if sign_in(client, PASSWORD) == "/password":
            submit_password_change(client, PASSWORD, CHANGED_PASSWORD)
            sign_in(client, CHANGED_PASSWORD)
    return client


def csrf_token(client: TestClient, path: str = "/users") -> str:
    return client.get(path).text.split('name="csrf_token" value="')[1].split('"')[0]


def test_healthz_and_login_page(settings, harness) -> None:
    with TestClient(create_app(settings)) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert "csrf_token" in client.get("/login").text


def test_protected_pages_redirect_when_signed_out(settings, harness) -> None:
    with TestClient(create_app(settings)) as client:
        for path in ("/", "/users", "/users/config", "/services", "/backups", "/settings"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 303
            assert response.headers["location"] == "/login"


def test_invalid_csrf_is_rejected(settings, harness) -> None:
    with TestClient(create_app(settings)) as client:
        client.get("/login")
        response = client.post("/login", data={"login": "admin", "password": PASSWORD, "csrf_token": "wrong"})
    assert response.status_code == 400


def test_wrong_password_is_rejected_and_recorded(settings, harness) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        page = client.get("/login")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        response = client.post("/login", data={"login": "admin", "password": "nope", "csrf_token": csrf})
        assert response.status_code == 401
        with connect(settings.database_path) as conn:
            attempts = conn.execute("SELECT successful FROM login_attempt").fetchall()
    assert [row["successful"] for row in attempts] == [0]


def test_login_throttles_after_five_failures(settings, harness) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        for _ in range(5):
            page = client.get("/login")
            csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
            client.post("/login", data={"login": "admin", "password": "nope", "csrf_token": csrf})
        page = client.get("/login")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        locked = client.post("/login", data={"login": "admin", "password": PASSWORD, "csrf_token": csrf})
    assert locked.status_code == 401
    assert "15 минут" in locked.text


def test_dashboard_reports_host_state(settings, harness) -> None:
    harness.fail2ban_payload["running"] = False
    client = signed_in_client(settings)
    with client:
        body = client.get("/").text
    assert "ОБНАРУЖЕН" in body
    assert "awg0" in body and "1234" in body
    assert "МТПРОКСИМАКС" not in body and "MTProxyMax" not in body  # интеграция снесена: узел её не имеет
    assert "ОСТАНОВЛЕН" in body  # fail2ban installed but not running


def test_creating_user_stores_the_peer_and_offers_the_config_once(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        token = csrf_token(client)
        response = client.post("/users", data={"name": "anna", "expires_at": "", "csrf_token": token}, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == "/users/config"
        assert harness.operations("create") == [{"name": "anna"}]

        config_page = client.get("/users/config")
        assert "anna" in config_page.text or "Jc = 6" in config_page.text

        download = client.get("/users/config/download", follow_redirects=False)
        assert download.headers["content-type"].startswith("application/x-wireguard-profile")
        assert "filename=\"anna.conf\"" in download.headers["content-disposition"]
        assert client.get("/users/config/download", follow_redirects=False).status_code == 303

        with connect(settings.database_path) as conn:
            row = conn.execute("SELECT name, public_key, address, status FROM vpn_user").fetchone()
    assert tuple(row) == ("anna", FIRST_KEY, "10.66.0.2", "active")


def test_qr_endpoint_returns_a_png(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "qr", "expires_at": "", "csrf_token": csrf_token(client)})
        image = client.get("/users/config/qr")
    assert image.status_code == 200
    assert image.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_duplicate_name_never_reaches_the_host(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "dup", "expires_at": "", "csrf_token": csrf_token(client)})
        token = csrf_token(client)
        response = client.post("/users", data={"name": "dup", "expires_at": "", "csrf_token": token}, follow_redirects=False)
        body = client.get("/users").text
    assert response.status_code == 303
    assert len(harness.operations("create")) == 1
    assert "занято" in body


@pytest.mark.parametrize("name", ["bad name", "-lead", "x" * 33, "кириллица"])
def test_unusable_names_are_rejected_before_the_host(settings, harness, name) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": name, "expires_at": "", "csrf_token": csrf_token(client)})
    assert harness.operations("create") == []


def test_broken_date_is_rejected_before_the_host(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "sane", "expires_at": "31.12.2030", "csrf_token": csrf_token(client)})
    assert harness.operations("create") == []


def test_adapter_failure_is_shown_and_nothing_is_stored(settings, harness) -> None:
    harness.create_error = "AmneziaWG interface is unavailable"
    client = signed_in_client(settings)
    with client:
        page = client.post("/users", data={"name": "fail", "expires_at": "", "csrf_token": csrf_token(client)})
        with connect(settings.database_path) as conn:
            count = conn.execute("SELECT count(*) FROM vpn_user").fetchone()[0]
    assert "Сервер не создал peer" in page.text
    assert count == 0


def test_failed_insert_compensates_by_deleting_the_peer(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "first", "expires_at": "", "csrf_token": csrf_token(client)})
        harness.key_override = FIRST_KEY
        client.post("/users", data={"name": "second", "expires_at": "", "csrf_token": csrf_token(client)}, follow_redirects=False)
        deletes = harness.operations("delete")
        with connect(settings.database_path) as conn:
            names = [row["name"] for row in conn.execute("SELECT name FROM vpn_user")]
    assert deletes == [{"public_key": FIRST_KEY}]
    assert names == ["first"]


def test_enable_disable_delete_update_database(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "flow", "expires_at": "", "csrf_token": csrf_token(client)})
        with connect(settings.database_path) as conn:
            user_id = conn.execute("SELECT id FROM vpn_user").fetchone()["id"]
        token = csrf_token(client)
        client.post(f"/users/{user_id}/disable", data={"csrf_token": token})
        assert harness.operations("disable") == [{"public_key": FIRST_KEY}]
        with connect(settings.database_path) as conn:
            assert conn.execute("SELECT status FROM vpn_user").fetchone()["status"] == "disabled"
        client.post(f"/users/{user_id}/enable", data={"csrf_token": csrf_token(client)})
        with connect(settings.database_path) as conn:
            assert conn.execute("SELECT status FROM vpn_user").fetchone()["status"] == "active"
        client.post(f"/users/{user_id}/delete", data={"csrf_token": csrf_token(client)})
        with connect(settings.database_path) as conn:
            assert conn.execute("SELECT count(*) FROM vpn_user").fetchone()[0] == 0


def test_action_errors_keep_the_database_unchanged(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "stale", "expires_at": "", "csrf_token": csrf_token(client)})
        with connect(settings.database_path) as conn:
            user_id = conn.execute("SELECT id FROM vpn_user").fetchone()["id"]
        harness.action_error = "no peer managed by this panel has that key"
        page = client.post(f"/users/{user_id}/disable", data={"csrf_token": csrf_token(client)})
        with connect(settings.database_path) as conn:
            status = conn.execute("SELECT status FROM vpn_user").fetchone()["status"]
    assert "Сервер не выполнил disable" in page.text
    assert status == "active"


def test_unknown_user_and_action_are_not_found(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        token = csrf_token(client)
        assert client.post("/users/4242/disable", data={"csrf_token": token}).status_code == 404
        assert client.post("/users/1/rotate", data={"csrf_token": token}).status_code == 404


def test_expired_access_is_disabled_on_the_host(settings, harness) -> None:
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "expired", "expires_at": yesterday, "csrf_token": csrf_token(client)})
        client.get("/users")
        disables = harness.operations("disable")
        with connect(settings.database_path) as conn:
            status = conn.execute("SELECT status FROM vpn_user").fetchone()["status"]
    assert disables == [{"public_key": FIRST_KEY}]
    assert status == "disabled"


def test_password_change_requires_current_password_and_length(settings, harness) -> None:
    app = create_app(settings)
    client = signed_in_client(settings, app)
    with client:
        token = csrf_token(client, "/settings")
        assert client.post(
            "/settings",
            data={"current_password": "wrong", "new_password": "a much longer secret", "csrf_token": token},
            follow_redirects=False,
        ).status_code == 303
        assert "Текущий пароль неверен" in client.get("/settings").text
        assert client.post(
            "/settings",
            data={"current_password": CHANGED_PASSWORD, "new_password": "short", "csrf_token": token},
            follow_redirects=False,
        ).status_code == 303
        assert "короче 12 символов" in client.get("/settings").text
        response = client.post(
            "/settings",
            data={"current_password": CHANGED_PASSWORD, "new_password": "a much longer secret", "csrf_token": token},
            follow_redirects=False,
        )
        assert response.headers["location"] == "/login"
        assert client.get("/").status_code == 200  # сессию смена пароля сбрасывает
    with TestClient(app) as fresh:
        page = fresh.get("/login")
        csrf = page.text.split('name="csrf_token" value="')[1].split('"')[0]
        assert fresh.post(
            "/login", data={"login": "admin", "password": "a much longer secret", "csrf_token": csrf}, follow_redirects=False
        ).status_code == 303


def test_first_login_blocks_every_section_until_password_is_replaced(settings, harness) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        assert sign_in(client, PASSWORD) == "/password"
        page = client.get("/password")
        assert "ТРЕБУЕТ ЗАМЕНЫ" in page.text
        blocked_without_agent = len(harness.log)
        for path in ("/", "/users", "/users/config", "/mtproto", "/services", "/backups", "/settings"):
            blocked = client.get(path, follow_redirects=False)
            assert (blocked.status_code, blocked.headers["location"]) == (303, "/password"), path
        # POST тоже: создание клиента должно быть недоступно, пока действует пароль установщика
        assert (
            client.post(
                "/users", data={"name": "anna", "csrf_token": csrf_token(client, "/password")}, follow_redirects=False
            ).headers["location"]
            == "/password"
        )
        assert len(harness.log) == blocked_without_agent  # ни один заблокированный запрос не трогал узел
        with connect(settings.database_path) as conn:
            assert conn.execute("SELECT count(*) FROM vpn_user").fetchone()[0] == 0
        assert client.get("/static/styles.css").status_code == 200
        assert submit_password_change(client, PASSWORD, CHANGED_PASSWORD) == "/login"
        assert sign_in(client, CHANGED_PASSWORD) == "/"
        assert client.get("/users").status_code == 200
        # страница остаётся доступной и после разблокировки — это тот же самый путь смены пароля
        assert client.get("/password").status_code == 200
    with connect(settings.database_path) as conn:
        assert conn.execute("SELECT must_change FROM administrator WHERE id = 1").fetchone()[0] == 0


def test_forced_change_refuses_to_reuse_the_installer_password(settings, harness) -> None:
    with TestClient(create_app(settings)) as client:
        assert sign_in(client, PASSWORD) == "/password"
        assert submit_password_change(client, PASSWORD, PASSWORD) == "/password"
        assert "совпадает с текущим" in client.get("/password").text
        with connect(settings.database_path) as conn:
            assert conn.execute("SELECT must_change FROM administrator WHERE id = 1").fetchone()[0] == 1
        assert sign_in(client, PASSWORD) == "/password"


def test_upgraded_node_does_not_demand_a_password_change(tmp_path, harness) -> None:
    # живая БД до правки: таблицы без must_change и оператор, чей пароль выбирали вне установщика
    database = tmp_path / "panel.sqlite3"
    with connect(database) as conn:
        conn.execute(
            "CREATE TABLE administrator (id INTEGER PRIMARY KEY CHECK (id = 1), login TEXT NOT NULL UNIQUE,"
            " password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute(
            "INSERT INTO administrator (id, login, password_hash) VALUES (1, 'admin', ?)", (hash_password(PASSWORD),)
        )
    settings = Settings(database, "x" * 32, "admin", PASSWORD)
    with TestClient(create_app(settings)) as client:
        assert sign_in(client, PASSWORD) == "/"
        assert client.get("/users").status_code == 200
        with connect(database) as conn:
            assert conn.execute("SELECT must_change FROM administrator WHERE id = 1").fetchone()[0] == 0


def test_every_section_carries_the_navigation(settings, harness) -> None:
    client = signed_in_client(settings)
    sections = {
        "/": "Состояние сервера",
        "/users": "Пользователи",
        "/mtproto": "Клиенты MTProto",
        "/services": "AmneziaWG, прокси и Fail2ban",
        "/backups": "Бэкапы панели",
        "/settings": "Настройки",
    }
    with client:
        for path, heading in sections.items():
            page = client.get(path)
            assert page.status_code == 200
            assert heading in page.text
            for href in sections:
                assert f'href="{href}"' in page.text
            assert page.text.count('class="active"') == 1


def test_secondary_sections_link_back(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        assert 'class="back"' not in client.get("/").text
        for path in ("/users", "/mtproto", "/services", "/backups", "/settings"):
            assert "На главную" in client.get(path).text


def test_config_page_links_back_to_users(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "anna", "expires_at": "", "csrf_token": csrf_token(client)}, follow_redirects=False)
        page = client.get("/users/config")
        assert "Назад к пользователям" in page.text
        assert 'href="/users/config/download"' in page.text


def test_services_page_shows_jail_counters(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        page = client.get("/services")
    assert "203.0.113.9" in page.text
    assert "198.51.100.4" in page.text
    assert "Всего забанено" in page.text
    assert "Работает, jail: 1" in page.text
    assert "telemt 3.3.0" in page.text  # карточка MTProto: движок настроен и отвечает
    assert "МТПРОКСИМАКС" not in page.text and "PROXY_STATUS_URL" not in page.text
    assert len(harness.operations("fail2ban")) == 1

    harness.fail2ban_payload["running"] = False
    with client:
        stopped = client.get("/services").text
    assert "Сервис остановлен" in stopped
    assert "203.0.113.9" not in stopped

    harness.fail2ban_payload["installed"] = False
    with client:
        assert "Пакета нет на узле" in client.get("/services").text


def test_banned_list_opens_behind_disclosure_not_in_the_row(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        page = client.get("/services").text

    assert '<details class="banlist">' in page
    block = page.split('<details class="banlist">')[1].split("</details>")[0]
    assert "<summary>Показать (2)</summary>" in page
    assert "203.0.113.9" in block and "198.51.100.4" in block
    assert "Разбанить" in block


def test_manual_ban_and_unban_reach_the_agent(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        token = csrf_token(client, "/services")
        banned = client.post(
            "/fail2ban",
            data={"action": "ban", "jail": "awg-hy2", "ip": "203.0.113.77", "csrf_token": token},
            follow_redirects=False,
        )
        assert banned.status_code == 303
        assert banned.headers["location"] == "/services"
        ban_page = client.get("/services").text
        unbanned = client.post(
            "/fail2ban",
            data={"action": "unban", "jail": "sshd", "ip": "203.0.113.9", "csrf_token": token},
            follow_redirects=False,
        )
        assert unbanned.status_code == 303
        unban_page = client.get("/services").text

    assert harness.operations("f2b") == [
        {"action": "ban", "jail": "awg-hy2", "ip": "203.0.113.77"},
        {"action": "unban", "jail": "sshd", "ip": "203.0.113.9"},
    ]
    assert "203.0.113.77 забанен в jail awg-hy2" in ban_page
    assert "всего в бане 3" in ban_page
    assert "Бан по 203.0.113.9 снят в jail sshd" in unban_page


def test_fail2ban_route_gates_the_request_before_the_agent(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        token = csrf_token(client, "/services")
        base = {"jail": "sshd", "ip": "203.0.113.77"}
        assert client.post(
            "/fail2ban", data={**base, "action": "ban", "csrf_token": "bogus"}, follow_redirects=False
        ).status_code == 400
        for action in ("stop", "reload", ""):
            response = client.post(
                "/fail2ban", data={**base, "action": action, "csrf_token": token}, follow_redirects=False
            )
            assert response.status_code == 404, action
    assert harness.operations("f2b") == []

    anonymous = TestClient(create_app(settings))
    with anonymous:
        anonymous.get("/login")
        response = anonymous.post(
            "/fail2ban", data={**base, "action": "ban", "csrf_token": token}, follow_redirects=False
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
    assert harness.operations("f2b") == []


def test_fail2ban_agent_failure_becomes_a_notice(settings, harness) -> None:
    harness.f2b_error = "unknown jail 'awg-hy2'; known: sshd"
    client = signed_in_client(settings)
    with client:
        client.post(
            "/fail2ban",
            data={"action": "ban", "jail": "awg-hy2", "ip": "203.0.113.77", "csrf_token": csrf_token(client, "/services")},
            follow_redirects=False,
        )
        page = client.get("/services")
    assert page.status_code == 200
    assert "Fail2ban не выполнил команду по 203.0.113.77" in page.text
    assert "unknown jail" in page.text


def test_backups_page_shows_archives_and_warnings(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        page = client.get("/backups")
        assert "awg-panel-20261105-033000.tar.gz.enc" in page.text
        assert "40.0 KiB" in page.text
        assert "не открыть" not in page.text
        harness.backups_payload = {**harness.backups_payload, "key_present": False, "source_present": False}
        warned = client.get("/backups")
    assert "не открыть" in warned.text
    assert "БД НЕ НАЙДЕНА" in warned.text


def test_settings_page_shows_host_configuration(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        page = client.get("/settings")
    assert "192.0.2.10" in page.text
    assert "10.66.0.0/24" in page.text
    assert "/etc/amnezia/amneziawg/panel-peers" in page.text
    assert "http://127.0.0.1:9091" in page.text  # Control API движка MTProto
    assert "MTProxyMax" not in page.text and "PROXY_STATUS_URL" not in page.text


def test_logout_requires_a_valid_token(settings, harness) -> None:
    client = signed_in_client(settings)
    with client:
        assert client.post("/logout", data={"csrf_token": "bogus"}, follow_redirects=False).status_code == 303
        assert client.get("/", follow_redirects=False).status_code == 200
        client.post("/logout", data={"csrf_token": csrf_token(client)}, follow_redirects=False)
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_adapter_reports_absent_socket_as_unavailable(tmp_path: Path) -> None:
    host = AwgAdapter(tmp_path / "absent.sock", timeout=1)
    result = host.request("status")
    assert result == {"error": "host-side adapter is unavailable"}
    assert host.status().available is False


def test_routes_degrade_without_host_adapter(tmp_path: Path) -> None:
    settings = Settings(
        tmp_path / "panel.sqlite3",
        "x" * 32,
        "admin",
        PASSWORD,
        agent_socket=tmp_path / "absent.sock",
        agent_timeout=1,
    )
    client = signed_in_client(settings)
    with client:
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "НЕ НАЙДЕН" in dashboard.text
        assert "host-side adapter is unavailable" in dashboard.text
        for path in ("/users", "/mtproto", "/services", "/backups", "/settings"):
            page = client.get(path)
            assert page.status_code == 200, path
            assert "host-side adapter is unavailable" in page.text, path
        created = client.post(
            "/users",
            data={"name": "anna", "expires_at": "", "csrf_token": csrf_token(client)},
            follow_redirects=False,
        )
        assert created.status_code == 303
        users = client.get("/users")
        assert "Сервер не создал peer" in users.text
    with connect(settings.database_path) as conn:
        assert conn.execute("SELECT count(*) FROM vpn_user").fetchone()[0] == 0


def peer(public_key: str, *, endpoint: str | None = None, age: float | None = None, rx: int = 0, tx: int = 0) -> dict:
    """Строка рантайма AWG в той форме, которую отдаёт операция peers."""
    return {
        "public_key": public_key,
        "endpoint": endpoint,
        "handshake_at": 0 if age is None else int(time.time() - age),
        "rx": rx,
        "tx": tx,
    }


def test_users_page_marks_who_is_connected_now(settings, harness) -> None:
    harness.peers_payload = {
        "interface": "awg0",
        "peers": [
            peer(FIRST_KEY, endpoint="198.51.100.20:49204", age=40, rx=319_182_316, tx=3_198_020_731),
            peer(SECOND_KEY),
        ],
        "error": None,
    }
    harness.hy2_stats_payload = {
        "configured": True,
        "online": {"galya": 2},
        "traffic": {"galya": {"tx": 40_000_000, "rx": 1_000_000}},
        "error": None,
    }
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "sergei", "expires_at": "", "csrf_token": csrf_token(client)})
        client.post("/users", data={"name": "ivan", "expires_at": "", "csrf_token": csrf_token(client)})
        client.post("/hysteria", data={"name": "galya", "password": "", "expires_at": "", "csrf_token": csrf_token(client)})
        body = client.get("/users").text

    assert "presence-online" in body and "presence-never" in body
    assert ">В СЕТИ<" in body and "НЕ БЫЛО РУКОПОЖАТИЯ" in body
    assert "клиент 198.51.100.20:49204" in body
    assert "2 соединения" in body
    assert "в сети 1 из 2 AWG и 1 из 1 Hysteria2" in body


def test_users_page_warns_when_the_node_stops_answering(settings, harness) -> None:
    harness.peers_payload = {"interface": "awg0", "peers": [], "error": "Cannot find device 'awg0'"}
    harness.hy2_stats_payload = {
        "configured": True,
        "online": {},
        "traffic": {},
        "error": "Traffic Stats API недоступен: HTTP Error 401",
    }
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "sergei", "expires_at": "", "csrf_token": csrf_token(client)})
        body = client.get("/users").text

    assert "ИСТОЧНИК AWG НЕ ОТВЕТИЛ" in body and "ИСТОЧНИК HY2 НЕ ОТВЕТИЛ" in body
    assert "Cannot find device" in body and "401" in body
    assert ">В СЕТИ<" not in body and "НЕТ В СЕТИ" not in body
    assert "УЗЕЛ НЕ ОТВЕТИЛ" in body


def test_users_page_explains_a_node_without_traffic_stats(settings, harness) -> None:
    harness.peers_payload = {
        "interface": "awg0",
        "peers": [peer(FIRST_KEY, endpoint="198.51.100.20:49204", age=10)],
        "error": None,
    }
    harness.hy2_stats_payload = {
        "configured": False,
        "online": {},
        "traffic": {},
        "error": "HYSTERIA_STATS_URL пуст: trafficStats в конфиге hysteria2 не включён",
    }
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "sergei", "expires_at": "", "csrf_token": csrf_token(client)})
        client.post("/hysteria", data={"name": "galya", "password": "", "expires_at": "", "csrf_token": csrf_token(client)})
        body = client.get("/users").text

    assert "trafficStats" in body
    assert "НЕТ В СЕТИ" not in body
    assert ">В СЕТИ<" in body  # AmneziaWG считается, даже если hysteria2 молчит


def test_dashboard_counts_clients_on_the_line(settings, harness) -> None:
    harness.peers_payload = {
        "interface": "awg0",
        "peers": [peer(FIRST_KEY, endpoint="198.51.100.20:49204", age=40), peer(SECOND_KEY, age=4000)],
        "error": None,
    }
    harness.hy2_stats_payload = {"configured": True, "online": {"galya": 1}, "traffic": {}, "error": None}
    client = signed_in_client(settings)
    with client:
        client.post("/users", data={"name": "sergei", "expires_at": "", "csrf_token": csrf_token(client)})
        client.post("/users", data={"name": "ivan", "expires_at": "", "csrf_token": csrf_token(client)})
        client.post("/hysteria", data={"name": "galya", "password": "", "expires_at": "", "csrf_token": csrf_token(client)})
        body = client.get("/").text
        assert "В СЕТИ СЕЙЧАС" in body
        assert "AWG 1 из 2 · Hysteria2 1 из 1" in body

        with connect(settings.database_path) as conn:
            user_id = conn.execute("SELECT id FROM vpn_user WHERE name = 'sergei'").fetchone()["id"]
        client.post(f"/users/{user_id}/disable", data={"csrf_token": csrf_token(client)})
        after = client.get("/").text

    assert "AWG 0 из 1 · Hysteria2 1 из 1" in after
