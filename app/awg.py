"""Client for the host-side AmneziaWG adapter over a Unix socket.

The adapter process owns every privileged command. This module only frames JSON
requests, so no shell string and no host path ever reaches the web container.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import socket


@dataclass(frozen=True)
class AwgStatus:
    available: bool
    interface: str | None = None
    version: str | None = None
    detail: str | None = None
    port: int | None = None
    peers: int | None = None
    managed: int = 0
    disabled: int = 0

    @property
    def summary(self) -> str:
        if not self.available:
            return self.detail or "adapter unavailable"
        return self.version or "available"


class AwgAdapter:
    def __init__(self, socket_path: Path, timeout: int = 5) -> None:
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def request(self, operation: str, **payload: str) -> dict:
        if not hasattr(socket, "AF_UNIX"):
            return {"error": "host-side adapter is unavailable"}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(str(self.socket_path))
                client.sendall((json.dumps({"operation": operation, **payload}) + "\n").encode())
                data = client.recv(262144).decode()
        except (OSError, ValueError):
            return {"error": "host-side adapter is unavailable"}
        try:
            return json.loads(data)
        except ValueError:
            return {"error": "host-side adapter returned a malformed reply"}

    def status(self) -> AwgStatus:
        data = self.request("status")
        if data.get("error"):
            return AwgStatus(False, detail=data["error"])
        return AwgStatus(
            available=bool(data.get("available")),
            interface=data.get("interface"),
            version=data.get("version"),
            detail=data.get("detail"),
            port=data.get("port"),
            peers=data.get("peers"),
            managed=data.get("managed", 0),
            disabled=data.get("disabled", 0),
        )
