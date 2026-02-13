# Elite VP Performance Hub (Supabase/Postgres)

This version stores data in a persistent PostgreSQL database (recommended: Supabase Free), so nothing disappears on Render Free.

## Render deployment
**Build Command**
```
pip install -r requirements.txt
```

**Start Command**
```
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

## Required env var
- `DATABASE_URL` (Postgres connection string, include `sslmode=require`)

## Optional env vars
- `BRAND_NAME` (default: Elite VP Performance Hub)
- `ADMIN_EMAIL`, `ADMIN_PASSWORD` (default: admin@local / admin123)
- `PRINCIPAL_EMAIL`, `PRINCIPAL_PASSWORD` (default: principal@local / principal123)
- `SESSION_SECRET` (recommended to set)
- `DEFAULT_TERM` (default: 2025-26 Term 1)
