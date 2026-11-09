"""ASGI entrypoint: builds the app from environment settings."""
from .main import create_app


app = create_app()
