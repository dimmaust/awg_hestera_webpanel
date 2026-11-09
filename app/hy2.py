"""Ссылки Hysteria2 и пароли клиентов.

Пароль клиента — это его учётные данные: панель отдаёт ссылку повторно, поэтому
пароль хранится в БД открытым текстом. Файл БД
читают только root и пользователь контейнера панели, архивы бэкапов шифруются.
"""
from __future__ import annotations

import ipaddress
import secrets
from urllib.parse import quote, urlencode

# Без символов, которые легко спутать: нет 0/O/1/l/I.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

# /authenticate обязан вызывать только hysteria2 со samego узла: loopback и сеть
# docker-моста, с которой узел приходит к опубликованному порту панели. Наружу
# этот путь закрыт проверкой источника — иначе любой, кто знает порт панели,
# прислал бы чужой адрес в payload и получил бы бан жертвы чужими руками.
LOCAL_AUTH_NETS = tuple(ipaddress.ip_network(cidr) for cidr in ("127.0.0.0/8", "::1/128", "172.16.0.0/12"))


def is_local_auth_source(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in LOCAL_AUTH_NETS)


def client_address(payload: dict, peer_ip: str) -> str:
    """IP клиента hysteria из поля addr вида `IP:port` (IPv6 — в скобках).

    Значение `addr` пишет сам сервер hysteria, поэтому вызывать функцию можно
    только для локального запроса: снаружи доверять ей нельзя. Если addr не
    похож на адрес, берётся настоящий источник соединения.
    """
    raw = str(payload.get("addr") or "").strip()
    if raw.startswith("["):
        raw = raw.partition("]")[0].lstrip("[")
    elif raw.count(":") == 1:
        raw = raw.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return peer_ip
    return raw


def new_password(length: int = 20) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def link(password: str, host: str, port: object, pin_sha256: str | None = None,
         sni: str | None = None, obfs: dict | None = None) -> str:
    options: dict[str, str] = {}
    # сертификат self-signed: CA-цепочку проверить нельзя, но пин по отпечатку
    # обязателен — иначе MITM между клиентом и узлом подменит сервер.
    options["insecure"] = "1"
    if pin_sha256:
        options["pinSHA256"] = pin_sha256
    if sni:
        options["sni"] = sni
    if obfs and obfs.get("type") and obfs.get("password"):
        options["obfs"] = str(obfs["type"])
        options["obfs-password"] = str(obfs["password"])
    return f"hysteria2://{quote(password, safe='')}@{host}:{port}/?{urlencode(options)}"
