# SafeZone AI (hackathon prototype)

## Windows setup (PowerShell, from this folder)
```
python -m venv .venv
.venv\Scripts\activate
pip install -r backend\requirements.txt
copy .env.example .env
uvicorn backend.server:app --port 8000
```
Open http://localhost:8000. Demo data works with no API key. For AI, put your Gemini key in `.env` (never commit it).

## Admin review
Set `ADMIN_TOKEN` in `.env`, then:
`curl -X PATCH localhost:8000/api/admin/hazards/<id> -H "X-Admin-Token: <token>" -H "Content-Type: application/json" -d "{\"verification\":\"verified\"}"`

## Risk indicator
Prototype only: severity 50%, verification 30%, recency 20% (30-day decay), minus 5 per flag. Not validated. No reports does not mean safe.

## 6-hour plan
H1 run backend + demo map. H2 filters/details. H3 reporting + SQLite. H4 geofence + "Simulate a drive". H5 Gemini key + analysis. H6 rehearse a 2-minute demo: open, click demo hazard, press Simulate, show alert, submit a report (shows Unverified).
