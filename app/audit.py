"""Аудит точек входа: одна строка на событие, файл читает fail2ban.

Строка оканчивается парой `key=value`, чтобы регулярное правило фильтра не
зависело от формата даты и имени хоста.
"""
from __future__ import annotations

import logging
import os
import time
from logging.handlers import WatchedFileHandler

EVENT = logging.getLogger("panel.audit")


def setup(path: str) -> None:
    """Один обработчик на файл: при смене пути прежний закрывается."""
    if not path:
        return
    EVENT.propagate = False
    current = EVENT.handlers
    if len(current) == 1 and getattr(current[0], "baseFilename", "") == os.path.abspath(path):
        return
    for handler in list(current):
        EVENT.removeHandler(handler)
        handler.close()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handler = WatchedFileHandler(path)
    handler.setFormatter(logging.Formatter("%(message)s"))
    EVENT.addHandler(handler)
    EVENT.setLevel(logging.INFO)


def record(event: str, ip: str, **fields: object) -> None:
    if not EVENT.handlers:
        return
    extras = " ".join(f"{key}={str(value)[:40] or '-'}" for key, value in fields.items())
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    EVENT.info("%s %s ip=%s%s", stamp, event, ip or "unknown", f" {extras}" if extras else "")
