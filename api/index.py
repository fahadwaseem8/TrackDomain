# Vercel ASGI entry point.
# Vercel's Python runtime looks for an `app` object in api/index.py.
from app.main import app  # noqa: F401
