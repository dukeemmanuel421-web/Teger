# Backend (FastAPI)

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app:app --reload --port 8000
```

## Notes
- Uses Gemini via `google-genai` only.
- Automatically falls back to deterministic heuristics if Gemini fails/unavailable.
- Default DB is SQLite at `backend/data/app.db`; set `DATABASE_URL` for Postgres.
- Interswitch mode defaults to `mock` for safe demos.
