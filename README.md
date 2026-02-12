# VP Performance System (MVP)

This is a lightweight BambooHR-style web app implementing a VP Performance framework with:
- 3 pillars (60/20/20 weighting)
- Term dashboard
- Metric entry (Actual values) + auto scoring
- Principal/Admin override (1–4) with reason
- Evidence/notes capture

## Demo accounts
- admin@local / admin123
- principal@local / principal123
- vp@local / vp123

## Local run
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Render start command
```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```
