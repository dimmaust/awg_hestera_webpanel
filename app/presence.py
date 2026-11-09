"""Кто из клиентов подключён к узлу прямо сейчас.

У AmneziaWG в ядре нет поля «соединение живо»: есть только возраст рукопожатия и
счётчики байт. Рукопожатие не обновляется, пока туннель молчит (keepalive — это
не rekey), поэтому одного порога по времени хватает лишь для активного клиента:
молчащий, но поднятый туннель выглядел бы брошенным. Панельный профиль идёт с
`PersistentKeepalive = 25`, и он двигает счётчик принятого, так что онлайн
считается как «свежее рукопожатие ИЛИ прирост принятого за последнее окно».

Для Hysteria2 источник — Traffic Stats API самого сервера (`GET /online`): там
соединения уже сведены по именам, которые вернул `/authenticate`.

Для MTProto источник — Control API движка telemt (`GET /v1/users`): `current_connections`
считает живые соединения по каждому секрету, дельты байт для этого не нужны.
"""
from __future__ import annotations

import time

POLL_SECONDS = 30       # окно фонового опроса узла
HANDSHAKE_TTL = 180     # секунды: рукопожатие старее — туннель считается брошенным
TRAFFIC_WINDOW = 90     # секунды: прирост принятого, услышанный в этом окне, = клиент жив
STALE_AFTER = 20        # секунды: снимок старше этого возраста страница обновляет сама

BADGES = {
    "online": "В СЕТИ",
    "offline": "НЕТ В СЕТИ",
    "never": "НЕ БЫЛО РУКОПОЖАТИЯ",
    "absent": "НЕ В РАНТАЙМЕ",
    "unknown": "УЗЕЛ НЕ ОТВЕТИЛ",
}
UNITS = ("Б", "КБ", "МБ", "ГБ", "ТБ")


def human_bytes(value: object) -> str:
    """Счётчики узла — байты, и 3198020731 в карточке не читается."""
    try:
        size = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "—"
    if size < 0:
        return "—"
    for unit in UNITS:
        if size < 1024 or unit == UNITS[-1]:
            if unit == "Б":
                return f"{int(size)} Б"
            return f"{_rounded(size)} {unit}"
        size /= 1024
    return "—"


def _rounded(size: float) -> str:
    """Один знак после запятой, но не «10.0 КБ»: десятичную запятую съедает rstrip."""
    text = f"{size:.1f}"
    return text[:-2] if text.endswith(".0") else text.replace(".", ",")


def human_age(seconds: object) -> str:
    """Возраст события по-русски; отрицательное (часы разъехались) — «только что»."""
    try:
        gap = float(seconds)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "—"
    if gap < 0:
        gap = 0.0
    if gap < 45:
        return "только что" if gap < 5 else f"{int(gap)} с назад"
    if gap < 5400:
        return f"{int(round(gap / 60))} мин назад"
    if gap < 172_800:
        return f"{int(round(gap / 3600))} ч назад"
    return f"{int(round(gap / 86_400))} сут назад"


class Presence:
    """Кэш снимков рантайма узла и выводы «подключён сейчас» по каждому клиенту.

    Опрос живёт в панели, а не на странице: дельта счётчика требует двух замеров,
    и иначе она была бы доступна только тому, кто обновил страницу дважды.
    """

    def __init__(self, host) -> None:
        self.host = host
        self.awg_peers: dict[str, dict] = {}
        self.hy2_clients: dict[str, dict] = {}
        self.hy2_configured = False
        self.mt_clients: dict[str, dict] = {}
        self.mt_configured = False
        self.errors: dict[str, str] = {}
        self.taken_at = 0.0

    def sample(self) -> None:
        """Опросить узел и обновить кэш; сбой узла не превращает клиентов в офлайн."""
        moment = time.monotonic()
        peers = self.host.request("peers")
        if peers.get("error"):
            self.errors["awg"] = str(peers["error"])
        else:
            self.errors.pop("awg", None)
            previous = self.awg_peers
            current: dict[str, dict] = {}
            for row in peers.get("peers", []) or []:
                key = str(row.get("public_key") or "")
                if not key:
                    continue
                before = previous.get(key)
                rx = int(row.get("rx") or 0)
                grew = bool(before) and rx > int(before["rx"])
                current[key] = {
                    "endpoint": row.get("endpoint"),
                    "handshake_at": int(row.get("handshake_at") or 0),
                    "rx": rx,
                    "tx": int(row.get("tx") or 0),
                    # Счётчик обнуляется при remove/add peer, и тогда рост — не признак жизни.
                    "alive_at": moment if grew else (before or {}).get("alive_at"),
                }
            self.awg_peers = current

        stats = self.host.request("hy2_stats")
        self.hy2_configured = bool(stats.get("configured"))
        if stats.get("error"):
            self.errors["hy2"] = str(stats["error"])
        else:
            self.errors.pop("hy2", None)
            online = stats.get("online") or {}
            traffic = stats.get("traffic") or {}
            names = {str(name) for name in online} | {str(name) for name in traffic}
            self.hy2_clients = {
                name: {
                    "connections": int(online.get(name, 0) or 0),
                    "tx": int((traffic.get(name) or {}).get("tx") or 0),
                    "rx": int((traffic.get(name) or {}).get("rx") or 0),
                }
                for name in names
            }
        self.sample_mt()
        self.taken_at = time.time()

    def sample_mt(self) -> None:
        """MTProto: движок сам считает живые соединения по клиентам, дельта не нужна.

        current_connections — авторитетное число, оно не обнуляется на границе
        перегрузки генерации и не зависит от опциональной пер-юзер телеметрии.
        """
        snapshot = self.host.request("mt_stats")
        self.mt_configured = bool(snapshot.get("configured"))
        if snapshot.get("error"):
            self.errors["mtproto"] = str(snapshot["error"])
            return
        self.errors.pop("mtproto", None)
        self.mt_clients = {
            str(row.get("name") or ""): {
                "connections": int(row.get("connections") or 0),
                "enabled": bool(row.get("enabled", True)),
                "unique_ips": int(row.get("unique_ips") or 0),
                "octets": int(row.get("octets") or 0),
                "active_ips": [str(ip) for ip in (row.get("active_ips") or [])],
            }
            for row in (snapshot.get("users") or [])
            if str(row.get("name") or "")
        }

    def refresh_if_stale(self) -> None:
        if not self.taken_at or time.time() - self.taken_at >= STALE_AFTER:
            self.sample()

    def awg_state(self, public_key: object) -> dict:
        """Состояние peer'а AmneziaWG: {state, badge, detail}."""
        key = str(public_key or "")
        if "awg" in self.errors:
            return {"state": "unknown", "badge": BADGES["unknown"], "detail": self.errors["awg"]}
        record = self.awg_peers.get(key)
        if record is None:
            return {"state": "absent", "badge": BADGES["absent"], "detail": "peer не в ядре узла"}
        handshake_at = record["handshake_at"]
        alive_at = record["alive_at"]
        fresh_traffic = bool(alive_at) and time.monotonic() - alive_at <= TRAFFIC_WINDOW
        if not handshake_at and not fresh_traffic:
            return {"state": "never", "badge": BADGES["never"], "detail": self._awg_detail(record)}
        age = time.time() - handshake_at if handshake_at else None
        if (age is not None and age <= HANDSHAKE_TTL) or fresh_traffic:
            return {"state": "online", "badge": BADGES["online"], "detail": self._awg_detail(record, age)}
        return {"state": "offline", "badge": BADGES["offline"], "detail": self._awg_detail(record, age)}

    @staticmethod
    def _awg_detail(record: dict, age: float | None = None) -> str:
        parts = [
            f"рукопожатие {human_age(age)}" if age is not None else "рукопожатия не было",
            f"клиент {record['endpoint']}" if record["endpoint"] else "адрес клиента не известен",
            f"↓ {human_bytes(record['tx'])} · ↑ {human_bytes(record['rx'])}",
        ]
        return " · ".join(parts)

    def hy2_state(self, name: object) -> dict:
        """Состояние клиента Hysteria2 по карте соединений сервера."""
        key = str(name or "")
        if not self.hy2_configured:
            return {"state": "unknown", "badge": BADGES["unknown"], "detail": self.errors.get("hy2", "нет Traffic Stats API")}
        if "hy2" in self.errors:
            return {"state": "unknown", "badge": BADGES["unknown"], "detail": self.errors["hy2"]}
        record = self.hy2_clients.get(key)
        connections = record["connections"] if record else 0
        traffic = ""
        if record and (record["tx"] or record["rx"]):
            traffic = f" · ↓ {human_bytes(record['tx'])} · ↑ {human_bytes(record['rx'])}"
        if connections > 0:
            plural = "соединение" if connections == 1 else "соединения" if connections < 5 else "соединений"
            return {"state": "online", "badge": BADGES["online"], "detail": f"{connections} {plural}{traffic}"}
        return {"state": "offline", "badge": BADGES["offline"], "detail": f"нет соединений{traffic}"}

    def mt_state(self, name: object) -> dict:
        """Состояние клиента MTProto по живой карте соединений движка.

        Клиента нет в ответе — значит его удалили из [access.users], а не что он молчит;
        выключенный клиент не пускают к авторизации, поэтому соединения у него нулевые
        всегда и «НЕТ В СЕТИ» для него честный ответ, а не «не в рантайме».
        """
        key = str(name or "")
        if not self.mt_configured:
            return {"state": "unknown", "badge": BADGES["unknown"],
                    "detail": self.errors.get("mtproto", "Control API движка не настроен")}
        if "mtproto" in self.errors:
            return {"state": "unknown", "badge": BADGES["unknown"], "detail": self.errors["mtproto"]}
        record = self.mt_clients.get(key)
        if record is None:
            return {"state": "absent", "badge": BADGES["absent"], "detail": "клиента нет в конфиге движка"}
        connections = record["connections"]
        plural = "соединение" if connections == 1 else "соединения" if connections < 5 else "соединений"
        traffic = f" · трафик {human_bytes(record['octets'])}" if record["octets"] else ""
        origin = f" · клиент {record['active_ips'][0]}" if record["active_ips"] else ""
        if connections > 0:
            return {"state": "online", "badge": BADGES["online"],
                    "detail": f"{connections} {plural}{origin}{traffic}"}
        if not record["enabled"]:
            return {"state": "offline", "badge": BADGES["offline"], "detail": f"клиент выключен{traffic}"}
        return {"state": "offline", "badge": BADGES["offline"], "detail": f"нет соединений{traffic}"}
