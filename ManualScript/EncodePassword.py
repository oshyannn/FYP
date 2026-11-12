import os, base64
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

#make sure install in cmd:
#   pip install -U cryptography
#   python ManualScript/EncodePassword.py


# ===== change =====
email = "employ2@example.com"
plain_password = "deleted"
# ======================

salt = os.urandom(16)
h = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(plain_password.encode())
b = lambda x: base64.b64encode(x).decode().rstrip("=")
phc = f"$argon2id$v=19$m=65536,t=3,p=4${b(salt)}${b(h)}"

email_sql = email.replace("'", "''")  

print(f"""
update public.users
set password_hash        = '{phc}',
    password_changed_at  = now(),
    failed_login_count   = 0,
    locked_until         = null,
    must_change_password = false
where lower(email) = lower('{email_sql}')
returning id, email, username, role, password_changed_at;
""")

#if need to force user keyin password again, run in sql
#delete from public.sessions
#where user_id = (select id from public.users where lower(email) = lower('employer1@gmail.com'));