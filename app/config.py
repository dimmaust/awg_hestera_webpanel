from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_path: Path
    session_secret: str
    admin_login: str
    admin_password: str | None
    agent_socket: Path = Path("/run/awg-panel/agent.sock")
    agent_timeout: int = 5
    audit_log: str = ""


def positive_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError as failure:
        raise RuntimeError(f"{name} must be an integer") from failure
    if not 1 <= value <= 60:
        raise RuntimeError(f"{name} must be between 1 and 60")
    return value


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("DATA_DIR", "/var/lib/awg-panel"))
    secret = os.environ.get("SESSION_SECRET", "")
    password = os.environ.get("ADMIN_PASSWORD")
    if len(secret) < 32:
        raise RuntimeError("SESSION_SECRET must be at least 32 characters")
    database_path = data_dir / "panel.sqlite3"
    if not password and not database_path.exists():
        raise RuntimeError("ADMIN_PASSWORD must be set on first startup")
    return Settings(
        database_path=database_path,
        session_secret=secret,
        admin_login=os.environ.get("ADMIN_LOGIN", "admin"),
        admin_password=password,
        agent_socket=Path(os.environ.get("AGENT_SOCKET", "/run/awg-panel/agent.sock")),
        agent_timeout=positive_int("AGENT_TIMEOUT", 5),
        audit_log=os.environ.get("AUDIT_LOG", ""),
    )
