# Free Deployment Guide

This app needs two deploy pieces:

1. A Python web service that supports WebSockets.
2. A MySQL database.

## Recommended Free Setup

- Web app: Render Free Web Service or Koyeb Free Web Service.
- Database: TiDB Cloud Starter.

This project already includes:

- `Procfile` for the production start command.
- `render.yaml` for Render Blueprint deployment.
- `.python-version` to keep deployment on Python 3.11.
- `schema.sql` for creating the production MySQL tables.
- `.env.example` for required environment variables.

## 1. Create MySQL-Compatible Database On TiDB Cloud

1. Create a TiDB Cloud Starter cluster.
2. Open the cluster and click Connect.
3. Choose Python or General connection details.
4. Copy these values for the app host:
   - `MYSQL_HOST`
   - `MYSQL_PORT`
   - `MYSQL_USER`
   - `MYSQL_PASSWORD`
   - `MYSQL_DB`
5. Use TiDB's SQL editor or a MySQL client to run `schema.sql`.

For most TiDB Cloud Starter clusters, use:

```text
MYSQL_PORT=4000
MYSQL_DB=trading_website
MYSQL_SSL=True
MYSQL_SSL_CA=/etc/ssl/certs/ca-certificates.crt
MYSQL_SSL_VERIFY_CERT=True
MYSQL_SSL_VERIFY_IDENTITY=True
```

## 2. Deploy On Render

### Option A: Blueprint deploy

1. Push this project to GitHub.
2. In Render, choose New > Blueprint.
3. Connect the repository.
4. Select the `render.yaml` file from this repo.
5. Fill the secret values Render asks for:
   - `MYSQL_HOST`
   - `MYSQL_PORT`
   - `MYSQL_USER`
   - `MYSQL_PASSWORD`
   - `MYSQL_DB`
6. The Blueprint already sets the TiDB TLS variables.
7. Apply the Blueprint and wait for the first deploy.

### Option B: Manual web service

1. Push this project to GitHub.
2. In Render, create a new Web Service from the repo.
3. If the repository root contains this project folder, set the root directory to `trading-main`.
4. Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn --config gunicorn_config.py wsgi:application`
5. Add environment variables from `.env.example`.
6. Set:
   - `FLASK_ENV=production`
   - `SESSION_COOKIE_SECURE=True`
   - `OAUTHLIB_INSECURE_TRANSPORT=0`
7. Deploy.

Render provides the `PORT` variable automatically. `gunicorn_config.py` reads it, so do not hard-code a port.

## 3. Deploy On Koyeb

1. Push this project to GitHub.
2. In Koyeb, create a new Web Service from the repo.
3. If needed, set the project directory to `trading-main`.
4. Use:
   - Build command: `pip install -r requirements.txt`
   - Run command: `gunicorn --config gunicorn_config.py wsgi:application`
5. Add environment variables from `.env.example`.
6. Deploy on the free instance.

## Google OAuth

If you use Google login, update the OAuth redirect URI after deployment:

```text
https://your-app-domain/login/google/authorized
```

Then set the same value in:

```text
GOOGLE_REDIRECT_URI
```

Also add:

```text
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
```

Email/password signup does not require Google OAuth.

## Free-Tier Notes

- Free web services may sleep or restart.
- The first request after sleep can be slow.
- Keep `WEB_CONCURRENCY=1` unless you add a Socket.IO message queue like Redis.
- Do not use SQLite or local files for production data on free web hosts.
- Watch your yfinance traffic; free hosts can suspend apps with unusually high outbound traffic.

## Quick Local Production Check

Run this before pushing:

```powershell
python -m py_compile app.py wsgi.py routes\auth.py routes\watchlist.py services\wallet_service.py
gunicorn --config gunicorn_config.py wsgi:application
```

On Windows, `gunicorn` may not run locally. The compile command is still useful; test Gunicorn after deployment or inside Linux.
