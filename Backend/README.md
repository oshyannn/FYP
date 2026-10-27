# Backend: Flask API, accounts, database

- `app.py`: entry point. `POST /analyze` runs the detector (from `../AIDev`); the account API is mounted when `SECRET_KEY` and `DATABASE_URL` are set.
- `config.py`: all settings, read from environment variables / `Backend/.env`.
- `web/`: `web_setup.py` (wiring), `controllers/` (HTTP routes), `db_models/` (database tables, NOT machine-learning models), `db.py`, `guards.py`, `security.py`, `mailer.py`, `extensions.py`.
- `scripts/staff_admin.py`: create the first admin, approve employers.

## Run
From this folder with its venv active (`..\setup_envs.py` creates it; copy `.env.example` to `.env` first):
```
.venv\Scripts\activate
python app.py                                   # http://127.0.0.1:5000
python -m scripts.staff_admin create-admin you@example.com "Your Name"
```
The detector needs the models in `../AIDev/models/` and the lists/data in `../AIDev/` (see `../AIDev/README.md`).
