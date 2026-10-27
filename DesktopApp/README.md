# SafeBrowse desktop application

Electron + React (the Figma Make design) + Tailwind. It talks to the Flask backend in `../backend`.
The login token never reaches the web page: the Electron main process (`electron/main.cjs`) holds it and
attaches it to every request.

## Run (two terminals)

1. Backend (from `backend/`, venv active): `python app.py`
2. Desktop (from `desktop/`):
   - first time: `npm install`
   - every time: `npm run dev`   (opens the app window, with hot reload)

Build and run the packaged-style app (no dev server): `npm start`

If the backend is not on `http://127.0.0.1:5000`, set `SAFEBROWSE_API` before starting, e.g. in PowerShell:
`$env:SAFEBROWSE_API="http://127.0.0.1:5000"; npm run dev`

## Screens in this version
User login, Create Account, Check-your-email (link + 6-digit code), Forgot / Reset password,
Staff login, Request Employer Access, and a placeholder home (with extension pairing for users).

## Try it
1. Create Account -> open the email (or the backend terminal in development) -> click the link and press
   "Confirm email", or type the 6-digit code. The app signs in by itself after the link.
2. Home -> "Generate pairing code" shows the one-time code the extension will use.
3. Staff: create the first admin with `python -m scripts.staff_admin create-admin you@example.com "Name"`
   (from `backend/`), then log in on the Staff login screen.
