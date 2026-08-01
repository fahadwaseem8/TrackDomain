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

| Variable | Description |
|----------|-------------|
| `SUPABASE_URL` | Your Supabase project URL |
| `SUPABASE_KEY` | Your Supabase anon/service key |

## Running the API

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

## Tech Stack

| Package | Purpose |
|---------|---------|
| `fastapi` | Web framework |
| `uvicorn` | ASGI server |
| `supabase` | Database & auth |
| `asyncwhois` | Async WHOIS lookups |
| `pydantic` / `pydantic-settings` | Data validation & config |
| `python-dotenv` | Environment variable management |
