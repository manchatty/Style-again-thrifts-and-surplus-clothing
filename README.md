# STYLE AGAIN THRIFTS AND SURPLUS CLOTHING

Flask + SQLite storefront with manual UPI payment, customer orders, admin dashboard, inventory management and web push notifications.

## Local development

1. Install Python 3.11+.
2. In this folder run:
   `python -m venv .venv`
3. Activate it (Windows PowerShell):
   `.venv\\Scripts\\Activate.ps1`
4. Install dependencies:
   `pip install -r requirements.txt`
5. Start:
   `python app.py`
6. Open `http://127.0.0.1:5000`.
7. Open `/admin` for the admin login. If you have not configured a password locally, the terminal prints a random temporary password for that run.

## Production security setup

Do NOT use the old `admin / styleagain123` credentials. Production requires:
- `STYLE_AGAIN_SECRET` (long random secret)
- `STYLE_AGAIN_ADMIN_ID`
- `STYLE_AGAIN_ADMIN_PASSWORD_HASH` (Werkzeug password hash)
- HTTPS
- `PRODUCTION=true`

Generate a password hash locally:
`python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('REPLACE_WITH_A_LONG_UNIQUE_PASSWORD'))"`

Set the returned hash as `STYLE_AGAIN_ADMIN_PASSWORD_HASH` in your host's environment variables. Never put the real password or secret in GitHub.

The app now uses server-side session authentication, HttpOnly/SameSite cookies, production Secure cookies, login throttling, same-origin checks for admin mutations, security headers, input limits, and no debug mode in production.

## Deploying

Use a Python-capable host such as Render, Railway, Fly.io or a VPS. Start the app with a production WSGI server, e.g.:
`gunicorn --bind 0.0.0.0:$PORT app:app`

For real production inventory/orders, migrate SQLite to PostgreSQL and use persistent storage. SQLite is suitable for testing/small single-instance use but is not the recommended long-term multi-instance store database.

## Important payment note

UPI is manual. The site does not independently verify bank payment. Keep orders in `Payment screenshot pending` until you verify the payment in your bank/UPI app and confirm the order from the admin dashboard.
