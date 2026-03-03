# teger-guardrails

AI-Powered Payment Fraud & Phishing Detection Platform for buildathons. Story: **Before money moves, AI verifies intent.**

## Features
- FastAPI backend with strict **Google Gemini (`google-genai`)** reasoning.
- Deterministic heuristic fallback for reliable demos when Gemini fails/rate-limits/missing key.
- Interswitch-style payment guardrails with `mock` and `live` credit inquiry modes.
- Forensic event vault with filtering/search.
- React + Vite + Tailwind frontend with demo scenarios and demo-mode UX.
- Optional Chrome extension for quick message scans.
- Deploy configs for Render and DigitalOcean App Platform.

## Monorepo Layout
- `backend/` API, AI orchestration, DB, Interswitch client.
- `frontend/` dashboard, payment guard, forensic vault.
- `extension/` optional MV3 popup analyzer.

## Local setup
### Prereqs
- Python 3.11+
- Node 18+

### Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

## Backend Environment Variables
| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `GEMINI_API_KEY` | For Gemini | empty | API key for Gemini calls |
| `GEMINI_MODEL` | No | `gemini-2.5-flash` | Gemini model name |
| `DATABASE_URL` | No | SQLite file | Postgres connection string |
| `ALLOW_ORIGINS` | No | `*` | CORS origins (`*` or CSV) |
| `INTERSWITCH_MODE` | No | `mock` | `mock` or `live` |
| `INTERSWITCH_CLIENT_ID` | live only | empty | OAuth client id |
| `INTERSWITCH_SECRET_KEY` | live only | empty | OAuth secret |
| `INTERSWITCH_TOKEN_URL` | live only | empty | token endpoint |
| `INTERSWITCH_BASE_URL` | live only | empty | API base URL |
| `INTERSWITCH_CREDIT_INQUIRY_PATH` | No | `/transfer/credit-inquiry` | credit inquiry path |

## Frontend Environment Variables
| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `VITE_API_URL` | Yes | `http://localhost:8000` | backend base URL |

## Render deploy
1. Push this repo to GitHub.
2. In Render, create **Blueprint** from `render.yaml`.
3. Set `GEMINI_API_KEY` in backend service environment.
4. Verify backend health at `/health` and frontend static site URL.

## DigitalOcean App Platform deploy
1. Push repo to GitHub.
2. Create app from source repo and choose `.do/app.yaml`.
3. Fill backend secret `GEMINI_API_KEY`.
4. Deploy and confirm backend `/health` returns `ok: true`.

## Demo script (2-3 min)
1. Open Dashboard and click **CEO urgent transfer**.
2. Run Analyze; show high/critical risk, categories, tactics, and recommendation.
3. Click **Create Guardrail Decision**.
4. In Payment Guard, run Credit Inquiry (mock), then Decision; show ALLOW/STEP_UP/BLOCK.
5. Open Forensic Vault, load events, and inspect payload JSON for audit trail.

## Mock vs Live Interswitch mode
- `mock` (default): deterministic, safe response for demos.
- `live`: OAuth token + real credit inquiry call using provided credentials.
- If live call fails, API returns informative error with recommendation to switch to mock.
