# TrackDomain

A domain tracking and monitoring API built with FastAPI and Supabase.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) *(recommended)* or pip

## Setup

### Using `uv` (recommended — fast)

```bash
# 1. Install uv (if not already installed)
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Clone the repo
git clone <repo-url>
cd TrackDomain

# 3. Create virtual environment & install dependencies
uv venv
uv pip install -r requirements.txt

# 4. Activate the virtual environment
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

### Using `pip` (standard)

```bash
git clone <repo-url>
cd TrackDomain

python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Configuration

Copy the example env file and fill in your credentials:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|----------|-------------|---------|
| `SUPABASE_URL` | Your Supabase project URL | — |
| `SUPABASE_KEY` | Your Supabase anon/service key | — |
| `HEALTH_CHECK_TIMEOUT` | Seconds to wait on the Supabase ping | `3.0` |
| `SUPABASE_HEALTH_TABLE` | Optional table to read 1 row from during `/health` | unset |

## Running the API

```bash
uvicorn app.main:app --reload

# `uvicorn main:app --reload` also works — main.py re-exports the app
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

## Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/health` | App status + live Supabase connectivity | — |
| `POST` | `/auth/signup` | Register a new account | — |
| `POST` | `/auth/login` | Exchange credentials for a JWT | — |
| `GET` | `/auth/me` | Current authenticated user | Bearer |

`/health` returns `200` when everything is reachable and `503` when Supabase is not,
so uptime monitors and load balancers can act on the status code alone:

```json
{
  "status": "ok",
  "app": "TrackDomain",
  "version": "0.1.0",
  "environment": "development",
  "database": { "status": "ok", "latency_ms": 581.6, "detail": null }
}
```

`database.status` is one of `ok`, `unauthorized`, `unreachable`, `timeout`,
`error`, or `not_configured` — with `detail` explaining the failure.

## Authentication

Auth is backed by **Supabase Auth (GoTrue)**. Supabase stores the users, hashes the
passwords, and signs the JWTs — this API never sees a password hash and holds no
signing secret. Access tokens are `ES256`, verified locally against the project's
public [JWKS](https://supabase.com/docs/guides/auth/jwts), so protected routes cost
no network round trip once the key set is cached.

```bash
# 1. Register — email confirmation is required, so no token is returned yet
curl -X POST localhost:8000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a-strong-password"}'
# 201 {"user_id":"...","confirmation_required":true,"message":"Check your email..."}

# 2. Confirm via the emailed link, then log in
curl -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a-strong-password"}'
# 200 {"access_token":"eyJ...","refresh_token":"...","expires_in":3600,...}

# 3. Call a protected route
curl localhost:8000/auth/me -H "Authorization: Bearer eyJ..."
# 200 {"id":"...","email":"you@example.com","role":"authenticated"}
```

Protect any route by depending on `get_current_user`:

```python
from app.security import CurrentUser, get_current_user

@router.get("/domains")
async def list_domains(user: CurrentUser = Depends(get_current_user)):
    return {"owner": user.id}
```

To require confirmed emails to be optional (returning tokens straight from signup),
turn **Confirm email** off under *Authentication → Providers → Email* in the Supabase
dashboard; `/auth/signup` already returns `confirmation_required: false` in that case.

## Project Structure

```
main.py             # Entry point shim -> app.main:app
app/
├── main.py         # FastAPI app instance & router registration
├── config.py           # Settings loaded from .env via pydantic-settings
├── db.py               # Supabase connectivity check
├── security.py         # JWT verification (JWKS) + get_current_user dependency
├── supabase_client.py  # Async wrapper over the Supabase Auth (GoTrue) API
└── api/
    ├── health.py       # Health check route
    └── auth.py         # signup / login / me
```

## Tech Stack

| Package | Purpose |
|---------|---------|
| `fastapi` | Web framework |
| `uvicorn` | ASGI server |
| `supabase` | Database & auth |
| `asyncwhois` | Async WHOIS lookups |
| `pydantic` / `pydantic-settings` | Data validation & config |
| `python-dotenv` | Environment variable management |
