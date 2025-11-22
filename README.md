# Prabha Graphics — Flask Website

This project scaffolds a small Flask site for *Prabha Graphics* and adapts your `C1.html` into a templated site with authentication and a catalog download route.

Quick overview:
- `app.py` — Flask app, SQLite DB, authentication, Google OAuth (Authlib).
- `templates/` — Jinja templates (`base.html`, `index.html`, `login.html`, `register.html`, `profile.html`).
- `static/css/style.css` — Styles extracted from your `C1.html`.

Setup (PowerShell):

```powershell
# create and activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# set environment variables for production — replace with your values
$env:FLASK_APP = 'app.py'
$env:FLASK_ENV = 'development'
$env:GOOGLE_CLIENT_ID = '<your-google-client-id>'
$env:GOOGLE_CLIENT_SECRET = '<your-google-client-secret>'
$env:SECRET_KEY = '<set-a-secret-key>'

# initialize DB & run
python app.py
```

Google OAuth:
- Create OAuth 2.0 credentials in Google Cloud Console. Set Authorized redirect URI to `http://localhost:5000/auth/google`.
- Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as environment variables before running the app.

Catalog PDF:
- Put your `catalogue.pdf` either in the project root (same folder as `app.py` and `C1.html`) or in `static/`.
- The home page "Download Catalog" button links to `/download_catalog` which serves the file if present.
