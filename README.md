# Secure Login System

A phone-friendly Flask project demonstrating account registration/login, salted password hashing with scrypt, username/password validation, parameterized SQLite queries, session-protected dashboard, logout, and basic security headers.

## Run
1. Install Python 3.10+.
2. `python -m pip install -r requirements.txt`
3. `python app.py`
4. Open `http://127.0.0.1:5000`.

## Deployment
Set a long random `SECRET_KEY` environment variable before public deployment. Set `COOKIE_SECURE=1` when serving over HTTPS. Use HTTPS for public hosting. This is an educational starter project; it does not include rate limiting, email verification, password reset, or 2FA.
