"""Make the hyphenated host-agent directory importable as `host_agent`."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent


def load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "host-agent" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


host_agent = load("host_agent", "agent.py")
host_backup = load("host_backup", "backup.py")
