"""Programmatic uvicorn entry point.

Prefer this over `uvicorn app.main:app` directly so that:
- The `Server: uvicorn` header (which leaks server fingerprint info) is suppressed.
- The reload setting follows the DEBUG env var automatically.

Usage:
    python run.py             # production-like (no reload)
    DEBUG=true python run.py  # hot-reload for development
"""

import uvicorn

from app.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        server_header=False,   # suppress "Server: uvicorn" fingerprinting
        proxy_headers=True,    # honour X-Forwarded-For / X-Forwarded-Proto from a trusted proxy
    )
