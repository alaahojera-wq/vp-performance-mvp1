# VP Performance System (MVP)

Structured FastAPI + Jinja2 web app for VP performance scoring + dashboard.

## Deploy on Render (Web Service)
**Build Command**
```
pip install -r requirements.txt
```

**Start Command**
```
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

### Recommended (Persistence)
Add a Render Disk mounted at `/var/data` and keep `DATA_DIR=/var/data`.

## Default logins (can be overridden by env vars)
- Admin: `admin@local` / `admin123`
- Principal: `principal@local` / `principal123`

Environment vars you can set in Render:
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`
- `PRINCIPAL_EMAIL`, `PRINCIPAL_PASSWORD`
- `DEFAULT_TERM`
