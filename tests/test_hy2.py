"""Hysteria2 в панели: ссылки, auth-контракт сервера и политика доступа."""
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import connect
from app.hy2 import link, new_password
from app.main import create_app

from test_app import PASSWORD, csrf_token, harness, signed_in_client  # noqa: F401 — фикстура harness нужна сборке

PIN = "0310A1582FF0EE6AFF70A546F2EFB6175ABD6418D2AC3013BE4DA7C100B90DAC"
ENDPOINT = "192.0.2.10"
# hysteria2 живёт на узле и зовёт панель через опубликованный порт, поэтому его
# запрос приходит с docker-моста. Наружу /authenticate закрыт отдельным тестом.
HY2_LOCAL_CALLER = ("172.18.0.1", 51000)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(tmp_path / "panel.sqlite3", "x" * 32, "admin", PASSWORD)


@pytest.fixture
def client(settings, harness) -> TestClient:
    return signed_in_client(settings, peer=HY2_LOCAL_CALLER)


def users(settings: Settings, name: str = "") -> list[dict]:
    query = "SELECT * FROM hysteria_user"
    args: tuple = ()
    if name:
        query += " WHERE name = ?"
        args = (name,)
    with connect(settings.database_path) as conn:
        return [dict(row) for row in conn.execute(query + " ORDER BY id", args)]


def authenticate(client: TestClient, password: str, addr: str = "203.0.113.7:52000") -> dict:
    response = client.post("/authenticate", json={"auth": password, "addr": addr, "name": "", "sni": ""})
    assert response.status_code == 200
    return response.json()


def create(client: TestClient, name: str, password: str = "", expires: str = "") -> None:
    response = client.post(
        "/hysteria",
        data={"name": name, "password": password, "expires_at": expires, "csrf_token": csrf_token(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def action(client: TestClient, user_id: int, name: str) -> None:
    client.post(f"/hysteria/{user_id}/{name}", data={"csrf_token": csrf_token(client)}, follow_redirects=False)


def test_link_builds_the_pinned_insecure_form() -> None:
    uri = link("pa/ss:w0rd", ENDPOINT, "43522", PIN, "www.bing.com", {"type": "salamander", "password": "ObfsSecret"})
    assert uri.startswith(f"hysteria2://pa%2Fss%3Aw0rd@{ENDPOINT}:43522/?")
    assert f"pinSHA256={PIN}" in uri
    assert "insecure=1" in uri
    assert "obfs=salamander" in uri and "obfs-password=ObfsSecret" in uri
    assert "sni=www.bing.com" in uri


def test_link_omits_options_the_node_did_not_report() -> None:
    assert link("secret", ENDPOINT, 43522, None, None, {"type": None, "password": None}) == (
        f"hysteria2://secret@{ENDPOINT}:43522/?insecure=1"
    )


def test_generated_password_avoids_ambiguous_characters() -> None:
    for _ in range(20):
        assert not set(new_password()) & set("0O1lI")


def test_created_link_is_listed_with_pin_and_obfs(client, settings) -> None:
    create(client, "anna")
    assert len(users(settings, "anna")) == 1
    page = client.get("/users").text
    assert f"@{ENDPOINT}:43522/" in page
    assert f"pinSHA256={PIN}" in page
    assert "obfs=salamander" in page
    assert "QR-код" in page


def test_created_client_authenticates_and_marks_last_used(client, settings) -> None:
    create(client, "boris")
    password = users(settings, "boris")[0]["password"]
    assert authenticate(client, password) == {"ok": True, "id": "boris"}
    assert users(settings, "boris")[0]["last_used_at"]


def test_authentication_needs_no_admin_session(settings, harness) -> None:
    with TestClient(create_app(settings), client=HY2_LOCAL_CALLER) as anon:
        assert authenticate(anon, "nau-gde-net-takogo") == {"ok": False}


def test_disabled_expired_and_deleted_links_are_denied(client, settings) -> None:
    create(client, "cara")
    create(client, "dan", expires=(date.today() - timedelta(days=1)).isoformat())
    cara, dan = users(settings, "cara")[0], users(settings, "dan")[0]
    assert authenticate(client, dan["password"]) == {"ok": False}
    action(client, cara["id"], "disable")
    assert authenticate(client, cara["password"]) == {"ok": False}
    action(client, cara["id"], "enable")
    assert authenticate(client, cara["password"]) == {"ok": True, "id": "cara"}
    action(client, cara["id"], "delete")
    assert authenticate(client, cara["password"]) == {"ok": False}


def test_rotate_replaces_the_password_of_the_same_name(client, settings) -> None:
    create(client, "ella", password="first-password")
    before = users(settings, "ella")[0]
    action(client, before["id"], "rotate")
    after = users(settings, "ella")[0]
    assert after["password"] != "first-password"
    assert authenticate(client, "first-password") == {"ok": False}
    assert authenticate(client, after["password"]) == {"ok": True, "id": "ella"}


def test_name_is_unique_across_both_protocols(client, settings) -> None:
    client.post("/users", data={"name": "fedor", "expires_at": "", "csrf_token": csrf_token(client)},
               follow_redirects=False)
    create(client, "fedor")
    assert users(settings, "fedor") == []
    assert "уже занято" in client.get("/users").text


def test_form_rejects_bad_name_short_password_and_bad_date(client, settings) -> None:
    csrf = csrf_token(client)
    for payload in ({"name": "ёжик"}, {"name": "ok", "password": "short"}, {"name": "ok2", "expires_at": "31.12.2026"}):
        response = client.post(
            "/hysteria", data={"password": "", "expires_at": "", **payload, "csrf_token": csrf},
            follow_redirects=False)
        assert response.status_code == 303
        assert users(settings) == []


def test_post_hysteria_requires_csrf(client, settings) -> None:
    response = client.post("/hysteria", data={"name": "ghost", "password": "", "expires_at": "", "csrf_token": "wrong"})
    assert response.status_code == 400
    assert users(settings) == []


def test_page_warns_when_node_has_no_hysteria(client, harness, settings) -> None:
    harness.hysteria_payload = {
        "installed": False, "config": "/etc/hysteria/config.yaml", "port": None, "obfs": None,
        "pin_sha256": None, "sni": None, "auth_type": None, "service": "hysteria-server",
        "state": None, "error": "конфиг hysteria2 не найден",
    }
    create(client, "gina")
    page = client.get("/users").text
    assert "конфиг hysteria2 не найден" in page
    assert "ссылка недоступна" in page
    assert len(users(settings, "gina")) == 1


def test_denied_authentication_is_logged_for_fail2ban(tmp_path: Path, settings, harness) -> None:
    """Два jail'а читают один файл: событие должно однозначно указывать точку входа."""
    logged = tmp_path / "var" / "log" / "panel.log"
    with_password = Settings(
        settings.database_path, settings.session_secret, settings.admin_login, settings.admin_password,
        audit_log=str(logged),
    )
    with TestClient(create_app(with_password), client=HY2_LOCAL_CALLER) as anon:
        authenticate(anon, "net-takogo", addr="198.51.100.9:44123")
        authenticate(anon, "net-takogo", addr="[2001:db8::9]:44123")
        anon.post(
            "/login",
            data={"login": "admin", "password": "ne tot", "csrf_token": csrf_token(anon)},
        )
    lines = logged.read_text().splitlines()
    assert "HY2_AUTH_FAIL ip=198.51.100.9 user=" in lines[0]
    assert "HY2_AUTH_FAIL ip=2001:db8::9 user=" in lines[1]
    assert "FAILED_LOGIN ip=" in lines[2]


def test_forged_addr_from_internet_cannot_choose_ban_target(tmp_path: Path, settings, harness) -> None:
    """addr в payload пишет hysteria, а hysteria — локальный вызов. Снаружи этот
    путь отдаёт отказ по настоящему источнику: иначе любой, кто знает порт
    панели, выписывает бан чужому адресу чужими руками."""
    logged = tmp_path / "var" / "log" / "panel.log"
    with_password = Settings(
        settings.database_path, settings.session_secret, settings.admin_login, settings.admin_password,
        audit_log=str(logged),
    )
    with TestClient(create_app(with_password), client=("203.0.113.33", 40000)) as attacker:
        response = attacker.post("/authenticate", json={"auth": "net-takogo", "addr": "198.51.100.7:5555"})
    assert response.status_code == 403
    line = logged.read_text()
    assert "HY2_AUTH_FAIL ip=203.0.113.33" in line
    assert "198.51.100.7" not in line

