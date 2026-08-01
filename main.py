"""Convenience entry point so `uvicorn main:app` works from the project root.

The app itself is defined in `app/main.py`.
"""

from app.main import app

__all__ = ["app"]
