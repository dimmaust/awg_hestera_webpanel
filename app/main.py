from contextlib import asynccontextmanager
import asyncio
from collections.abc import Awaitable, Callable
from datetime import date, datetime, timezone
from io import BytesIO
from pathlib import Path
import re
import sqlite3
import time

from fastapi import Body, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import audit
from .awg import AwgAdapter, AwgStatus
from .config import Settings, load_settings
from .db import connect, initialize
from .hy2 import client_address, is_local_auth_source
from .presence import HANDSHAKE_TTL, POLL_SECONDS, TRAFFIC_WINDOW, Presence, human_bytes
from .hy2 import link as hy2_link
from .hy2 import new_password
from .security import hash_password, new_csrf_token, verify_password


ROOT = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(ROOT / "templates"))
PEER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
HOME_BACK = {"href": "/", "label": "← На главную"}
USERS_BACK = {"href": "/users", "label": "← Назад к пользователям"}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def csrf_is_valid(request: Request, csrf_token: str) -> bool:
    return bool(request.session.get("csrf")) and request.session["csrf"] == csrf_token


def signed_in(request: Request) -> bool:
    return request.session.get("admin_id") == 1


def password_change_required(request: Request) -> bool:
    """Флаг ставится при входе из строки администратора и снимается сменой пароля.

    Читается из сессии, а не из БД: гейт должен работать и на разделах, которые к БД
    вообще не обращаются, и в middleware, где лишний запрос дороже одной записанной строки.
    """
    return bool(request.session.get("force_password"))


def apply_password_change(settings: Settings, current: str, new: str) -> str | None:
    """Смена пароля администратора: текст отказа или None, если пароль заменён.

    Снимает и must_change: установка сделана так, чтобы дефолтный пароль, показанный
    установщиком в консоли, жил ровно до первого успешного входа с заменой.
    """
    if len(new) < 12:
        return "Новый пароль короче 12 символов."
    with connect(settings.database_path) as conn:
        row = conn.execute("SELECT password_hash FROM administrator WHERE id = 1").fetchone()
        if not row or not verify_password(current, row["password_hash"]):
            return "Текущий пароль неверен."
        if new == current:
            return "Новый пароль совпадает с текущим — придумайте другой."
        conn.execute(
            "UPDATE administrator SET password_hash = ?, must_change = 0 WHERE id = 1", (hash_password(new),)
        )
    return None


def redirect_login() -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)


def adapter(settings: Settings) -> AwgAdapter:
    return AwgAdapter(settings.agent_socket, settings.agent_timeout)


def host_note(reply: dict) -> str:
    """Подпись в шапке: отвечал ли хост-агент, а не есть ли у узла WG-интерфейс.

    Разделы без AmneziaWG (/mtproto, /backups) не знают имени интерфейса, и прежняя
    подпись «БЕЗ ХОСТ-АГЕНТА» на них была неправдой: агент как раз отвечал.
    """
    failure = str(reply.get("error") or "")
    return "ХОСТ: агент не ответил" if failure.startswith("host-side adapter") else "ХОСТ: агент отвечает"


MT_ACTION_WORDS = {
    "enable": "включение",
    "disable": "выключение",
    "delete": "удаление",
    "rotate": "замену секрета",
    "create": "создание",
}

# Коды отказа telemt, которые оператор обязан понять без чтения исходников движка. Ключ — пара
# (действие, код): тот же last_user_forbidden вне удаления ничего не значит, и вставить ему
# перевод по одному только коду значило бы врать про создание клиента.
MT_REFUSALS = {
    ("delete", "last_user_forbidden"): (
        "Клиент {name} — последний в конфиге движка. Без хотя бы одной записи telemt не стартует "
        "после перезагрузки, поэтому удаление запрещено (409 last_user_forbidden). Его можно выключить "
        "или заменить ему секрет."
    ),
    ("create", "user_exists"): (
        "Клиент {name} уже есть в конфиге движка — имя не должно повторяться даже среди выключенных "
        "(409 user_exists)."
    ),
}


def mt_failure_note(action: str, name: str, failure: str) -> str:
    """Отказ движка по-русски: голый код вроде last_user_forbidden оператору ни о чём не говорит."""
    for (known_action, code), note in MT_REFUSALS.items():
        if action == known_action and code in failure:
            return note.format(name=name)
    return f"Движок не выполнил {MT_ACTION_WORDS.get(action, action)} клиента {name}: {failure}"


def flash(request: Request, message: str) -> None:
    request.session["flash"] = message


def live_context(presence: Presence, awg_keys: list, hy2_names: list, mt_names: list | None = None) -> dict:
    """Сводка «кто на связи» для заголовка раздела.

    Ключ peer'а и имя клиента — то, чем узел сам описывает соединение, поэтому
    сводка считает ровно тех же клиентов, что и карточки под ней.
    """
    awg_states = [presence.awg_state(key) for key in awg_keys]
    hy2_states = [presence.hy2_state(name) for name in hy2_names]
    mt_states = [presence.mt_state(name) for name in (mt_names or [])]
    return {
        "awg_online": sum(1 for state in awg_states if state["state"] == "online"),
        "awg_total": len(awg_states),
        "hy2_online": sum(1 for state in hy2_states if state["state"] == "online"),
        "hy2_total": len(hy2_states),
        "mt_online": sum(1 for state in mt_states if state["state"] == "online"),
        "mt_total": len(mt_states),
        "taken_at": time.strftime("%H:%M:%S", time.localtime(presence.taken_at)) if presence.taken_at else "—",
        "handshake_ttl": HANDSHAKE_TTL,
        "traffic_window": TRAFFIC_WINDOW,
        "poll_seconds": POLL_SECONDS,
        "errors": dict(presence.errors),
        "hy2_configured": presence.hy2_configured,
        "mt_configured": presence.mt_configured,
    }


def taken_names(conn: sqlite3.Connection, name: str, mt_names: tuple = ()) -> bool:
    """Имя должно быть свободно во всех трёх протоколах: одинаковые ярлыки путают оператора.

    Для MTProto имя принадлежит движку, поэтому проверка по кэшу опроса — вежливость:
    настоящий отказ делает сам telemt кодом 409 user_exists.
    """
    for table in ("vpn_user", "hysteria_user"):
        if conn.execute(f"SELECT 1 FROM {table} WHERE name = ?", (name,)).fetchone() is not None:
            return True
    return name in mt_names


def user_stamp(value: object) -> str:
    """UTC из SQLite CURRENT_TIMESTAMP в местное время для списка пользователей."""
    if not value:
        return "—"
    try:
        moment = datetime.strptime(value[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return str(value)
    return moment.astimezone().strftime("%d.%m.%Y %H:%M")


def expire_users(settings: Settings) -> int:
    """Disable peers whose access date has passed. Returns how many were disabled."""
    today = date.today().isoformat()
    disabled = 0
    with connect(settings.database_path) as conn:
        rows = conn.execute(
            "SELECT id, public_key FROM vpn_user"
            " WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?",
            (today,),
        ).fetchall()
        for row in rows:
            if not row["public_key"]:
                conn.execute("UPDATE vpn_user SET status = 'disabled' WHERE id = ?", (row["id"],))
                disabled += 1
                continue
            result = adapter(settings).request("disable", public_key=row["public_key"])
            if not result.get("error"):
                conn.execute("UPDATE vpn_user SET status = 'disabled' WHERE id = ?", (row["id"],))
                disabled += 1
        # Ссылка hysteria2 живёт только в этой БД: истёкшую достаточно пометить,
        # сервера для отказа больше не будет (auth проверяет status при каждом handshake).
        expired = conn.execute(
            "UPDATE hysteria_user SET status = 'disabled'"
            " WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < ?",
            (today,),
        )
        disabled += expired.rowcount or 0
    return disabled


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    presence = Presence(adapter(settings))

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        audit.setup(settings.audit_log)
        password_hash = hash_password(settings.admin_password) if settings.admin_password else None
        initialize(settings.database_path, settings.admin_login, password_hash)

        async def expiry_loop() -> None:
            while True:
                await asyncio.sleep(60)
                expire_users(settings)

        async def presence_loop() -> None:
            """Дельта принятого требует двух замеров, поэтому узел опрошен и без открытой страницы."""
            while True:
                await asyncio.sleep(POLL_SECONDS)
                presence.sample()

        expire_users(settings)
        presence.sample()
        task = asyncio.create_task(expiry_loop())
        poller = asyncio.create_task(presence_loop())
        try:
            yield
        finally:
            task.cancel()
            poller.cancel()

    app = FastAPI(title="AmneziaWG Panel", docs_url=None, redoc_url=None, lifespan=lifespan)

    # add_middleware вставляет в начало списка, поэтому зарегистрированный раньше оказывается ниже
    # по стеку: гейт должен стоять до SessionMiddleware, иначе request.session ещё не заполнен.
    # Пока установлен must_change, оператору доступна только форма смены пароля: любой раздел
    # панели показывает живое состояние узла, а «дефолтный пароль ещё действует» — то, что не
    # должно висеть в чужом браузере, пока оператор не придумал свой.
    @app.middleware("http")
    async def force_password_change(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.session.get("admin_id") == 1 and password_change_required(request):
            path = request.url.path
            if path != "/password" and not path.startswith("/static") and path not in {"/logout", "/favicon.ico"}:
                return RedirectResponse("/password", status_code=303)
        return await call_next(request)

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="awg_panel_session",
        https_only=False,  # Plain HTTP по решению оператора: доступ по IP:Port из интернета.
        same_site="strict",
        max_age=60 * 60 * 8,
    )
    app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> HTMLResponse:
        if signed_in(request):
            return RedirectResponse("/", status_code=303)
        request.session["csrf"] = new_csrf_token()
        return templates.TemplateResponse(request, "login.html", {"csrf": request.session["csrf"], "error": None})

    @app.post("/login", response_class=HTMLResponse, response_model=None)
    async def login(
        request: Request,
        login: str = Form(),
        password: str = Form(),
        csrf_token: str = Form(),
    ) -> HTMLResponse | RedirectResponse:
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        ip = client_ip(request)
        cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - 15 * 60))
        with connect(settings.database_path) as conn:
            failures = conn.execute(
                "SELECT count(*) FROM login_attempt WHERE source_ip = ? AND successful = 0 AND attempted_at > ?",
                (ip, cutoff),
            ).fetchone()[0]
            row = conn.execute("SELECT id, login, password_hash, must_change FROM administrator WHERE id = 1").fetchone()
            valid = failures < 5 and row and login == row["login"] and verify_password(password, row["password_hash"])
            conn.execute("INSERT INTO login_attempt (source_ip, successful) VALUES (?, ?)", (ip, int(bool(valid))))
        audit.record("LOGIN_OK" if valid else "FAILED_LOGIN", ip, user=login)
        if not valid:
            request.session["csrf"] = new_csrf_token()
            message = "Неверный логин или пароль." if failures < 5 else "Слишком много попыток. Повторите через 15 минут."
            return templates.TemplateResponse(
                request, "login.html", {"csrf": request.session["csrf"], "error": message}, status_code=401
            )
        request.session.clear()
        forced = bool(row["must_change"])
        request.session.update({"admin_id": 1, "csrf": new_csrf_token(), "force_password": forced})
        return RedirectResponse("/password" if forced else "/", status_code=303)

    @app.post("/logout")
    async def logout(request: Request, csrf_token: str = Form()) -> RedirectResponse:
        if not csrf_is_valid(request, csrf_token):
            return RedirectResponse("/", status_code=303)
        request.session.clear()
        return redirect_login()

    @app.get("/settings", response_class=HTMLResponse, response_model=None)
    async def settings_page(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        host = adapter(settings)
        node = host.request("settings")
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "csrf": request.session["csrf"],
                "section": "settings",
                "back": HOME_BACK,
                "interface": node.get("interface"),
                "node": node,
                "error": request.session.pop("flash", None),
            },
        )

    @app.post("/settings", response_class=HTMLResponse, response_model=None)
    async def change_password(
        request: Request, current_password: str = Form(), new_password: str = Form(), csrf_token: str = Form()
    ) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        failure = apply_password_change(settings, current_password, new_password)
        if failure:
            request.session["flash"] = failure
            return RedirectResponse("/settings", status_code=303)
        audit.record("PASSWORD_CHANGED", client_ip(request))
        request.session.clear()
        request.session["flash"] = "Пароль обновлён. Войдите заново."
        return RedirectResponse("/login", status_code=303)

    @app.get("/password", response_class=HTMLResponse, response_model=None)
    async def password_page(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        return templates.TemplateResponse(
            request,
            "password.html",
            {
                "csrf": request.session["csrf"],
                "forced": password_change_required(request),
                "error": request.session.pop("flash", None),
            },
        )

    @app.post("/password", response_class=HTMLResponse, response_model=None)
    async def password_change(
        request: Request, current_password: str = Form(), new_password: str = Form(), csrf_token: str = Form()
    ) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        failure = apply_password_change(settings, current_password, new_password)
        if failure:
            request.session["flash"] = failure
            return RedirectResponse("/password", status_code=303)
        audit.record("PASSWORD_CHANGED", client_ip(request))
        request.session.clear()
        request.session["flash"] = "Пароль обновлён. Войдите заново."
        return RedirectResponse("/login", status_code=303)

    @app.get("/", response_class=HTMLResponse, response_model=None)
    async def dashboard(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        expire_users(settings)
        presence.refresh_if_stale()
        host = adapter(settings)
        status: AwgStatus = host.status()
        fail2ban = host.request("fail2ban")
        with connect(settings.database_path) as conn:
            users = conn.execute(
                "SELECT count(*) AS total, sum(status = 'active') AS active FROM vpn_user"
            ).fetchone()
            awg_keys = [row["public_key"] for row in conn.execute(
                "SELECT public_key FROM vpn_user WHERE status = 'active' AND public_key IS NOT NULL"
            )]
            hy2_names = [row["name"] for row in conn.execute(
                "SELECT name FROM hysteria_user WHERE status = 'active'"
            )]
        # Список MTProto принадлежит движку, поэтому имена берутся из кэша опроса:
        # карточка обзора не должна платить три HTTP-запроса к API за каждый заход.
        mt_names_present = [name for name, record in presence.mt_clients.items() if record["enabled"]]
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "csrf": request.session["csrf"],
                "section": "overview",
                "interface": status.interface,
                "awg": status,
                "fail2ban": fail2ban,
                "users": users["total"] or 0,
                "active": users["active"] or 0,
                "mt": {
                    "configured": presence.mt_configured,
                    "clients": len(presence.mt_clients),
                    "error": presence.errors.get("mtproto"),
                },
                "live": live_context(presence, awg_keys, hy2_names, mt_names_present),
            },
        )

    def hysteria_view() -> tuple[list[dict], dict]:
        """Строки hysteria2 плюс параметры узла для ссылок. Панель — владелец паролей."""
        host = adapter(settings)
        node = host.request("settings")
        info = host.request("hysteria")
        endpoint = node.get("endpoint") if not node.get("error") else None
        rows = []
        with connect(settings.database_path) as conn:
            for row in conn.execute(
                "SELECT id, name, password, status, expires_at, created_at, last_used_at"
                " FROM hysteria_user ORDER BY id DESC"
            ):
                uri = ""
                if endpoint and info.get("port"):
                    uri = hy2_link(
                        row["password"], endpoint, info["port"],
                        info.get("pin_sha256"), info.get("sni"), info.get("obfs"),
                    )
                item = dict(row)
                item["link"] = uri
                item["created"] = user_stamp(row["created_at"])
                item["used"] = user_stamp(row["last_used_at"])
                rows.append(item)
        return rows, {"info": info, "endpoint": endpoint}

    @app.get("/users", response_class=HTMLResponse, response_model=None)
    async def users_page(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        expire_users(settings)
        presence.refresh_if_stale()
        status = adapter(settings).status()
        with connect(settings.database_path) as conn:
            rows = conn.execute(
                "SELECT id,name,status,expires_at,created_at,public_key FROM vpn_user ORDER BY id DESC"
            ).fetchall()
        users = [{**dict(row), "live": presence.awg_state(row["public_key"])} for row in rows]
        links, hy2 = hysteria_view()
        for link in links:
            link["live"] = presence.hy2_state(link["name"])
        return templates.TemplateResponse(
            request,
            "users.html",
            {
                "csrf": request.session["csrf"],
                "section": "users",
                "back": HOME_BACK,
                "interface": status.interface,
                "awg": status,
                "users": users,
                "links": links,
                "hy2": hy2,
                "live": live_context(
                    presence,
                    [row["public_key"] for row in rows if row["status"] == "active" and row["public_key"]],
                    [link["name"] for link in links if link["status"] == "active"],
                ),
                "error": request.session.pop("flash", None),
            },
        )

    @app.get("/services", response_class=HTMLResponse, response_model=None)
    async def services_page(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        host = adapter(settings)
        status = host.status()
        return templates.TemplateResponse(
            request,
            "services.html",
            {
                "csrf": request.session["csrf"],
                "section": "services",
                "back": HOME_BACK,
                "interface": status.interface,
                "awg": status,
                "mt": host.request("mtproto"),
                "fail2ban": host.request("fail2ban"),
                "error": request.session.pop("flash", None),
            },
        )

    @app.post("/fail2ban", response_model=None)
    async def fail2ban_action(
        request: Request,
        action: str = Form(),
        jail: str = Form(),
        ip: str = Form(),
        csrf_token: str = Form(),
    ) -> RedirectResponse | HTMLResponse:
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        if action not in {"ban", "unban"}:
            return HTMLResponse("Unsupported action", status_code=404)
        result = adapter(settings).request("f2b", action=action, jail=jail, ip=ip)
        failure = result.get("error")
        audit.record(
            "F2B_BAN" if action == "ban" else "F2B_UNBAN",
            client_ip(request),
            jail=jail,
            target=ip,
            result="error" if failure else "ok",
        )
        if failure:
            flash(request, f"Fail2ban не выполнил команду по {ip}: {failure}")
        elif action == "ban":
            flash(request, f"{ip} забанен в jail {jail}, всего в бане {result.get('banned')}.")
        else:
            flash(request, f"Бан по {ip} снят в jail {jail}; неудачные попытки этого адреса обнулены.")
        return RedirectResponse("/services", status_code=303)

    @app.get("/backups", response_class=HTMLResponse, response_model=None)
    async def backups_page(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        host = adapter(settings)
        backups = host.request("backups")
        return templates.TemplateResponse(
            request,
            "backups.html",
            {
                "csrf": request.session["csrf"],
                "section": "backups",
                "back": HOME_BACK,
                "interface": None,
                "host_status": host_note(backups),
                "backups": backups,
                "error": request.session.pop("flash", None),
            },
        )

    @app.post("/users", response_model=None)
    async def create_user(request: Request, name: str = Form(), expires_at: str = Form(""), csrf_token: str = Form()):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        name = name.strip()
        if not PEER_NAME.match(name):
            flash(request, "Имя peer недоступно: 1-32 символа [A-Za-z0-9_-], начинается с буквы или цифры.")
            return RedirectResponse("/users", status_code=303)
        if expires_at.strip():
            try:
                expires_at = date.fromisoformat(expires_at.strip()).isoformat()
            except ValueError:
                flash(request, "Дата окончания доступа указана в неверном формате.")
                return RedirectResponse("/users", status_code=303)
        else:
            expires_at = None
        with connect(settings.database_path) as conn:
            if taken_names(conn, name, tuple(presence.mt_clients)):
                flash(request, f"Имя {name} уже занято.")
                return RedirectResponse("/users", status_code=303)
        host = adapter(settings)
        result = host.request("create", name=name)
        if result.get("error"):
            flash(request, f"Сервер не создал peer: {result['error']}")
            return RedirectResponse("/users", status_code=303)
        try:
            with connect(settings.database_path) as conn:
                conn.execute(
                    "INSERT INTO vpn_user (name, status, expires_at, public_key, address) VALUES (?, 'active', ?, ?, ?)",
                    (result["name"], expires_at, result["public_key"], result["address"]),
                )
        except sqlite3.Error as failure:
            # The peer exists on the host but is unusable without a record; undo it.
            host.request("delete", public_key=result["public_key"])
            flash(request, f"Не удалось сохранить пользователя: {failure}")
            return RedirectResponse("/users", status_code=303)
        request.session["new_config"] = result["config"]
        request.session["new_config_name"] = result["name"]
        return RedirectResponse("/users/config", status_code=303)

    @app.get("/users/config", response_class=HTMLResponse)
    async def new_config(request: Request):
        if not signed_in(request):
            return redirect_login()
        return templates.TemplateResponse(
            request,
            "config.html",
            {
                "csrf": request.session["csrf"],
                "section": "users",
                "back": USERS_BACK,
                "interface": None,
                "host_status": "хост-агент здесь не опрашивался",
                "config": request.session.get("new_config"),
            },
        )

    @app.get("/users/config/download", response_model=None)
    async def download_new_config(request: Request) -> Response | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        config = request.session.pop("new_config", None)
        name = request.session.pop("new_config_name", "amneziawg")
        if not config:
            return RedirectResponse("/users/config", status_code=303)
        return Response(
            config,
            media_type="application/x-wireguard-profile",
            headers={"Content-Disposition": f'attachment; filename="{name}.conf"'},
        )

    @app.get("/users/config/qr", response_model=None)
    async def config_qr(request: Request):
        if not signed_in(request):
            return redirect_login()
        config = request.session.get("new_config")
        if not config:
            return RedirectResponse("/users/config", status_code=303)
        import qrcode

        image = qrcode.make(config)
        payload = BytesIO()
        image.save(payload, format="PNG")
        payload.seek(0)
        return StreamingResponse(payload, media_type="image/png", headers={"Cache-Control": "no-store"})

    @app.post("/users/{user_id}/{action}", response_model=None)
    async def user_action(request: Request, user_id: int, action: str, csrf_token: str = Form()):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        if action not in {"enable", "disable", "delete"}:
            return HTMLResponse("Unsupported action", status_code=404)
        with connect(settings.database_path) as conn:
            user = conn.execute("SELECT public_key FROM vpn_user WHERE id = ?", (user_id,)).fetchone()
        if not user or not user["public_key"]:
            return HTMLResponse("User not found", status_code=404)
        result = adapter(settings).request(action, public_key=user["public_key"])
        if result.get("error"):
            flash(request, f"Сервер не выполнил {action}: {result['error']}")
            return RedirectResponse("/users", status_code=303)
        with connect(settings.database_path) as conn:
            if action == "delete":
                conn.execute("DELETE FROM vpn_user WHERE id = ?", (user_id,))
            else:
                conn.execute("UPDATE vpn_user SET status = ? WHERE id = ?", ("active" if action == "enable" else "disabled", user_id))
        return RedirectResponse("/users", status_code=303)

    @app.post("/hysteria", response_model=None)
    async def create_hy2(
        request: Request,
        name: str = Form(),
        password: str = Form(""),
        expires_at: str = Form(""),
        csrf_token: str = Form(),
    ):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        name = name.strip()
        password = password.strip()
        if not PEER_NAME.match(name):
            flash(request, "Имя недоступно: 1-32 символа [A-Za-z0-9_-], начинается с буквы или цифры.")
            return RedirectResponse("/users", status_code=303)
        if password and len(password) < 8:
            flash(request, "Пароль ссылки короче 8 символов — оставьте поле пустым, чтобы сгенерировать.")
            return RedirectResponse("/users", status_code=303)
        if expires_at.strip():
            try:
                expires_at = date.fromisoformat(expires_at.strip()).isoformat()
            except ValueError:
                flash(request, "Дата окончания доступа указана в неверном формате.")
                return RedirectResponse("/users", status_code=303)
        else:
            expires_at = None
        with connect(settings.database_path) as conn:
            if taken_names(conn, name, tuple(presence.mt_clients)):
                flash(request, f"Имя {name} уже занято — оно используется в другом протоколе.")
                return RedirectResponse("/users", status_code=303)
            try:
                conn.execute(
                    "INSERT INTO hysteria_user (name, password, status, expires_at) VALUES (?, ?, 'active', ?)",
                    (name, password or new_password(), expires_at),
                )
            except sqlite3.IntegrityError:
                flash(request, "Такая ссылка уже есть — пароль повторяется с другим клиентом.")
                return RedirectResponse("/users", status_code=303)
        return RedirectResponse("/users", status_code=303)

    @app.post("/hysteria/{user_id}/{action}", response_model=None)
    async def hy2_action(request: Request, user_id: int, action: str, csrf_token: str = Form()):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        if action not in {"enable", "disable", "delete", "rotate"}:
            return HTMLResponse("Unsupported action", status_code=404)
        with connect(settings.database_path) as conn:
            if not conn.execute("SELECT 1 FROM hysteria_user WHERE id = ?", (user_id,)).fetchone():
                return HTMLResponse("User not found", status_code=404)
            if action == "delete":
                conn.execute("DELETE FROM hysteria_user WHERE id = ?", (user_id,))
            elif action == "rotate":
                conn.execute(
                    "UPDATE hysteria_user SET password = ?, status = 'active', last_used_at = NULL WHERE id = ?",
                    (new_password(), user_id),
                )
            else:
                conn.execute(
                    "UPDATE hysteria_user SET status = ? WHERE id = ?",
                    ("active" if action == "enable" else "disabled", user_id),
                )
        # Отключённый или удалённый клиент перестаёт проходить с следующего
        # handshake; активные соединение досидит до переподключения.
        return RedirectResponse("/users", status_code=303)

    @app.get("/hysteria/{user_id}/qr", response_model=None)
    async def hy2_qr(request: Request, user_id: int):
        if not signed_in(request):
            return redirect_login()
        rows, _ = hysteria_view()
        match = [row for row in rows if row["id"] == user_id and row["link"]]
        if not match:
            return HTMLResponse("Link not available", status_code=404)
        import qrcode

        image = qrcode.make(match[0]["link"])
        payload = BytesIO()
        image.save(payload, format="PNG")
        payload.seek(0)
        return StreamingResponse(payload, media_type="image/png", headers={"Cache-Control": "no-store"})

    def mtproto_view() -> dict:
        """Снимок MTProto глазами движка.

        Клиенты, секреты и подменные домены живут в конфиге telemt: панель ничего не
        дублирует у себя, иначе два источника правды разъехались бы при первом же
        изменении, сделанном не через веб.
        """
        snapshot = adapter(settings).request("mtproto")
        censorship = snapshot.get("censorship") or {}
        primary = str(censorship.get("tls_domain") or "")
        for row in snapshot.get("users") or []:
            links = row.get("links") or {}
            tls = list(links.get("tls") or [])
            domains = [{"domain": primary or "домен не настроен", "link": tls[0]}] if tls else []
            domains += [
                {"domain": entry["domain"], "link": entry["link"]}
                for entry in (links.get("tls_domains") or [])
                if entry.get("link") and entry["link"] not in [item["link"] for item in domains]
            ]
            row["domains"] = domains
            row["dd_links"] = list(links.get("secure") or [])
            row["link"] = domains[0]["link"] if domains else (row["dd_links"][0] if row["dd_links"] else "")
            row["traffic"] = human_bytes(row.get("octets"))
            row["quota"] = human_bytes(row.get("data_quota_bytes"))
        return snapshot

    def mt_names() -> tuple:
        rows = adapter(settings).request("mt_stats").get("users") or []
        return tuple(str(row.get("name") or "") for row in rows)

    def reload_note(status: dict) -> str:
        state = str(status.get("state") or "unknown")
        if state == "succeeded":
            return "перегрузка генерации завершена"
        if state == "pending":
            return "перегрузка генерации ещё идёт — обновите страницу через несколько секунд"
        if state == "unchanged":
            return "движок не стал поднимать новую генерацию: в конфиге ничего не изменилось"
        if state == "rolled_back":
            return "движок откатил перегрузку, работает прежняя конфигурация"
        if state == "failed":
            return f"движок не применил перегрузку: {status.get('error') or 'без описания'}"
        return f"состояние перегрузки: {state}"

    @app.get("/mtproto", response_class=HTMLResponse, response_model=None)
    async def mtproto_page(request: Request) -> HTMLResponse | RedirectResponse:
        if not signed_in(request):
            return redirect_login()
        presence.refresh_if_stale()
        snapshot = mtproto_view()
        rows = snapshot.get("users") or []
        for row in rows:
            row["live"] = presence.mt_state(row.get("name"))
        return templates.TemplateResponse(
            request,
            "mtproto.html",
            {
                "csrf": request.session["csrf"],
                "section": "mtproto",
                "back": HOME_BACK,
                "interface": None,
                "host_status": host_note(snapshot),
                "mt": snapshot,
                "users": rows,
                "live": live_context(presence, [], [], [row["name"] for row in rows if row["enabled"]]),
                "error": request.session.pop("flash", None),
            },
        )

    @app.post("/mtproto", response_model=None)
    async def create_mt(request: Request, name: str = Form(), csrf_token: str = Form()):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        name = name.strip()
        if not PEER_NAME.match(name):
            flash(request, "Имя недоступно: 1-32 символа [A-Za-z0-9_-], начинается с буквы или цифры.")
            return RedirectResponse("/mtproto", status_code=303)
        with connect(settings.database_path) as conn:
            if taken_names(conn, name, mt_names()):
                flash(request, f"Имя {name} уже занято в другом протоколе.")
                return RedirectResponse("/mtproto", status_code=303)
        result = adapter(settings).request("mtproto_create", name=name)
        failure = result.get("error")
        audit.record("MT_USER_ADD", client_ip(request), user=name, result="error" if failure else "ok")
        if failure:
            flash(request, mt_failure_note("create", name, str(failure)))
            return RedirectResponse("/mtproto", status_code=303)
        flash(request, f"Клиент {name} создан и добавлен в конфиг движка.")
        return RedirectResponse("/mtproto", status_code=303)

    @app.post("/mtproto/{name}/{action}", response_model=None)
    async def mt_action(request: Request, name: str, action: str, csrf_token: str = Form()):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        if action not in {"enable", "disable", "delete", "rotate"}:
            return HTMLResponse("Unsupported action", status_code=404)
        result = adapter(settings).request("mtproto_action", name=name, action=action)
        failure = result.get("error")
        audit.record(
            {"enable": "MT_USER_ENABLE", "disable": "MT_USER_DISABLE",
             "delete": "MT_USER_DELETE", "rotate": "MT_USER_ROTATE"}[action],
            client_ip(request), user=name, result="error" if failure else "ok",
        )
        if failure:
            flash(request, mt_failure_note(action, name, str(failure)))
        elif action == "disable":
            flash(request, f"{name} выключен: новые соединения отвергаются, живые сессии движок оборвал.")
        elif action == "enable":
            flash(request, f"{name} снова принимается узлом.")
        elif action == "rotate":
            flash(request, f"Секрет {name} заменён — прежняя ссылка больше не работает, выдайте новую.")
        else:
            flash(request, f"{name} удалён из конфига движка вместе с его адресами в квотах.")
        return RedirectResponse("/mtproto", status_code=303)

    @app.post("/mtproto/domain", response_model=None)
    async def mt_domain(request: Request, domain: str = Form(),
                        keep_previous: str = Form(""), csrf_token: str = Form()):
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        keep = keep_previous == "on"
        result = adapter(settings).request("mtproto_domain", domain=domain.strip(), keep_previous=keep)
        failure = result.get("error")
        audit.record("MT_DOMAIN", client_ip(request), domain=domain.strip(), result="error" if failure else "ok")
        if failure:
            flash(request, f"Подменный домен не применён: {failure}")
            return RedirectResponse("/mtproto", status_code=303)
        pool = result.get("pool") or []
        flash(
            request,
            f"Домен {result['domain']} записан в конфиг движка, {reload_note(result.get('reload') or {})}."
            + (f" В пуле остались прежние: {', '.join(pool)} — ссылки на них продолжают работать."
               if pool else " Прежние домены из пула сняты: старые ee-ссылки больше не примут."),
        )
        return RedirectResponse("/mtproto", status_code=303)

    @app.post("/mtproto/pool", response_model=None)
    async def mt_pool(request: Request, domains: list[str] = Form(), csrf_token: str = Form()):
        """Явный список доменов, которые ещё считаются действительными для старых ссылок."""
        if not signed_in(request):
            return redirect_login()
        if not csrf_is_valid(request, csrf_token):
            return HTMLResponse("Invalid request", status_code=400)
        wanted = [entry.strip().lower() for entry in domains if entry.strip()]
        result = adapter(settings).request("mtproto_pool", domains=wanted)
        failure = result.get("error")
        audit.record("MT_POOL", client_ip(request), domains=",".join(wanted), result="error" if failure else "ok")
        if failure:
            flash(request, f"Пул доменов не изменён: {failure}")
        else:
            pool = result.get("pool") or []
            flash(
                request,
                ("В пуле: " + ", ".join(pool)) if pool else "Пул очищен — действителен только основной домен.",
            )
        return RedirectResponse("/mtproto", status_code=303)

    @app.get("/mtproto/{name}/qr", response_model=None)
    async def mt_qr(request: Request, name: str, domain: str = ""):
        if not signed_in(request):
            return redirect_login()
        rows = mtproto_view().get("users") or []
        match = [row for row in rows if row.get("name") == name]
        if not match:
            return HTMLResponse("Client not found", status_code=404)
        wanted = domain.strip().lower()
        candidates = [item for item in (match[0].get("domains") or []) if item.get("link")]
        link = ""
        for item in candidates:
            if not wanted or item["domain"] == wanted:
                link = item["link"]
                break
        if not link and match[0].get("dd_links"):
            link = match[0]["dd_links"][0]
        if not link:
            return HTMLResponse("Link not available", status_code=404)
        import qrcode

        image = qrcode.make(link)
        payload = BytesIO()
        image.save(payload, format="PNG")
        payload.seek(0)
        return StreamingResponse(payload, media_type="image/png", headers={"Cache-Control": "no-store"})

    @app.post("/authenticate", response_model=None)
    async def hy2_authenticate(request: Request, payload: dict = Body()) -> JSONResponse:
        """Контракт auth.type=http сервера hysteria2: 200 и {"ok": true, "id": имя} либо {"ok": false}.

        В БД пишет только last_used_at. Адрес клиента из payload принимается,
        только когда запрос пришёл от hysteria на самом узле: панель опубликована
        в интернет, и без этой проверки любой прислал бы чужой адрес и получил
        бан жертвы чужими руками. Отказ уходит в аудит и его разбирает fail2ban.
        """
        source = client_ip(request)
        if not is_local_auth_source(source):
            audit.record("HY2_AUTH_FAIL", source, user="hy2")
            return JSONResponse({"ok": False}, status_code=403)
        auth = payload.get("auth") if isinstance(payload, dict) else None
        if not isinstance(auth, str) or not auth:
            return JSONResponse({"ok": False}, status_code=200)
        peer = client_address(payload, source)
        today = date.today().isoformat()
        name = None
        with connect(settings.database_path) as conn:
            row = conn.execute(
                "SELECT id, name FROM hysteria_user"
                " WHERE password = ? AND status = 'active' AND (expires_at IS NULL OR expires_at >= ?)",
                (auth, today),
            ).fetchone()
            if row:
                name = row["name"]
                conn.execute("UPDATE hysteria_user SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        if not name:
            audit.record("HY2_AUTH_FAIL", peer, user="hy2")
            return JSONResponse({"ok": False}, status_code=200)
        audit.record("HY2_AUTH_OK", peer, user=name)
        return JSONResponse({"ok": True, "id": name}, status_code=200)

    return app
