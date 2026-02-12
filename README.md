VP Performance System (MVP)

Deploy on Render:
- Build: pip install -r requirements.txt
- Start: uvicorn main:app --host 0.0.0.0 --port $PORT

Admin login:
- Set Render environment variables ADMIN_EMAIL and ADMIN_PASSWORD to change admin credentials.

Admin can manage VPs at /admin/vps
