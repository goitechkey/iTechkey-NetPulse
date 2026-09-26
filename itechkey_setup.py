"""
itechkey_setup.py — Auto setup wizard for iTechkey NetPulse.
Run once: python itechkey_setup.py
"""
import os
import sys
import json
import socket
import getpass
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
CONFIG_FILE = BASE_DIR / "itechkey_config.json"

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"
B = "\033[94m"; D = "\033[0m"; BOLD = "\033[1m"

def ok(m):   print(f"{G}✓{D} {m}")
def warn(m): print(f"{Y}!{D} {m}")
def err(m):  print(f"{R}✗{D} {m}")
def info(m): print(f"{B}→{D} {m}")
def head(m): print(f"\n{BOLD}{B}{'='*66}\n {m}\n{'='*66}{D}")


def check_python():
    if sys.version_info < (3, 9):
        err(f"Python 3.9+ required (have {sys.version.split()[0]})")
        sys.exit(1)
    ok(f"Python {sys.version.split()[0]}")


def check_packages():
    required = [("flask", "flask"), ("ping3", "ping3"),
                ("requests", "requests"), ("reportlab", "reportlab"),
                ("PIL", "pillow"), ("pymysql", "pymysql"),
                ("dbutils", "DBUtils")]
    missing = []
    for mod, pip_name in required:
        try:
            __import__(mod)
            ok(f"Package: {mod}")
        except ImportError:
            err(f"Missing: {mod}")
            missing.append(pip_name)
    if missing:
        warn(f"Installing: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        ok("Packages installed")


def detect_mysql():
    info("Detecting MySQL...")
    candidates = [{"host": "127.0.0.1", "port": 3306},
                  {"host": "localhost", "port": 3306},
                  {"host": "127.0.0.1", "port": 3307}]
    for c in candidates:
        try:
            s = socket.create_connection((c["host"], c["port"]), timeout=1)
            s.close()
            ok(f"MySQL detected at {c['host']}:{c['port']}")
            return c
        except (socket.error, OSError):
            continue
    warn("No MySQL on standard ports")
    return None


def _random_password(n=20):
    import secrets, string
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def setup_mysql(server_info):
    head("MySQL Configuration")
    import pymysql
    host, port = server_info["host"], server_info["port"]

    default_users = [("root", ""), ("root", "root"),
                     ("root", "password"), ("root", "admin")]
    info("Trying auto-connect...")
    working = None
    for user, pwd in default_users:
        try:
            c = pymysql.connect(host=host, port=port, user=user,
                                password=pwd, connect_timeout=2)
            c.close()
            ok(f"Connected as '{user}'")
            working = (user, pwd)
            break
        except pymysql.err.OperationalError:
            continue

    if not working:
        warn("Auto-connect failed — enter credentials manually")
        user = input(f"{B}MySQL admin username [root]: {D}").strip() or "root"
        pwd = getpass.getpass(f"{B}MySQL admin password: {D}")
        try:
            c = pymysql.connect(host=host, port=port, user=user,
                                password=pwd, connect_timeout=5)
            c.close()
            working = (user, pwd)
            ok(f"Connected as '{user}'")
        except Exception as e:
            err(f"Connection failed: {e}")
            return None

    admin_user, admin_pwd = working
    db_name = "itechkey_monitor"
    app_user = "itechkey"
    app_pwd = _random_password(20)

    info(f"Creating DB '{db_name}' and user '{app_user}'...")
    try:
        c = pymysql.connect(host=host, port=port,
                            user=admin_user, password=admin_pwd)
        cur = c.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {db_name} "
                    f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cur.execute(f"CREATE USER IF NOT EXISTS '{app_user}'@'%' "
                    f"IDENTIFIED BY '{app_pwd}'")
        cur.execute(f"GRANT ALL PRIVILEGES ON {db_name}.* TO "
                    f"'{app_user}'@'%'")
        cur.execute("FLUSH PRIVILEGES")
        c.commit()
        c.close()
        ok(f"Database ready: {db_name}")
    except Exception as e:
        err(f"DB creation failed: {e}")
        return None

    return {
        "backend": "mysql",
        "host": host, "port": port,
        "user": app_user, "password": app_pwd,
        "database": db_name,
    }


def choose_backend():
    head("Database Selection")
    print(f"""
{B}Choose your database:{D}

  1. {G}MySQL{D}   — Recommended for {BOLD}1000+ sensors{D}
  2. {G}SQLite{D}  — Zero setup, < 100 sensors
  3. {G}Auto{D}    — Detect MySQL, fallback to SQLite (default)
""")
    choice = input(f"{B}Enter choice [3]: {D}").strip() or "3"

    if choice == "1":
        info_ = detect_mysql()
        return setup_mysql(info_) if info_ else {"backend": "sqlite"}
    elif choice == "2":
        return {"backend": "sqlite"}
    else:
        info_ = detect_mysql()
        if info_:
            r = setup_mysql(info_)
            if r:
                ok("Using MySQL (auto-detected)")
                return r
        ok("Using SQLite (MySQL not available)")
        return {"backend": "sqlite"}


def write_config(config):
    env_lines = [f"ITECHKEY_DB={config['backend']}"]
    if config["backend"] == "mysql":
        env_lines += [
            f"MYSQL_HOST={config['host']}",
            f"MYSQL_PORT={config['port']}",
            f"MYSQL_USER={config['user']}",
            f"MYSQL_PASSWORD={config['password']}",
            f"MYSQL_DB={config['database']}",
            "MONITOR_WORKERS=20",
        ]
    else:
        env_lines.append("MONITOR_WORKERS=5")
    ENV_FILE.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")
    ok(f"Config saved: {ENV_FILE.name}")
    ok(f"Config saved: {CONFIG_FILE.name}")


def init_database(config):
    head("Database Initialization")
    os.environ["ITECHKEY_DB"] = config["backend"]
    if config["backend"] == "mysql":
        os.environ.update({
            "MYSQL_HOST": config["host"], "MYSQL_PORT": str(config["port"]),
            "MYSQL_USER": config["user"], "MYSQL_PASSWORD": config["password"],
            "MYSQL_DB": config["database"],
        })
    sys.path.insert(0, str(BASE_DIR))
    try:
        import itechkey_monitor as app
        app.init_db()
        ok("Tables created")
        if config["backend"] == "mysql":
            try:
                app.ensure_partitions()
                ok("Partitions ready")
            except Exception as e:
                warn(f"Partition setup: {e}")
        ok("Default admin ready (admin / admin)")
        return True
    except Exception as e:
        err(f"DB init failed: {e}")
        import traceback; traceback.print_exc()
        return False


def migrate_sqlite_if_any(config):
    sqlite_file = BASE_DIR / "itechkey.db"
    if not sqlite_file.exists() or config["backend"] != "mysql":
        return
    head("SQLite Data Migration")
    info(f"Found SQLite DB ({sqlite_file.stat().st_size / 1024 / 1024:.1f} MB)")
    choice = input(f"{B}Migrate to MySQL? [Y/n]: {D}").strip().lower()
    if choice in ("n", "no"):
        return
    try:
        import sqlite3
        src = sqlite3.connect(sqlite_file)
        src.row_factory = sqlite3.Row
        os.environ.update({
            "MYSQL_HOST": config["host"], "MYSQL_PORT": str(config["port"]),
            "MYSQL_USER": config["user"], "MYSQL_PASSWORD": config["password"],
            "MYSQL_DB": config["database"],
        })
        import importlib
        import itechkey_monitor as app
        importlib.reload(app)
        dst = app.db()
        tables = ["users", "groups", "snmp_credentials", "devices",
                  "sensors", "sensor_data", "alert_rules",
                  "notifications", "settings"]
        for t in tables:
            try:
                rows = src.execute(f"SELECT * FROM {t}").fetchall()
            except sqlite3.OperationalError:
                continue
            if not rows:
                continue
            cols = list(rows[0].keys())
            ph = ",".join(["?"] * len(cols))
            sql = f"INSERT IGNORE INTO {t} ({','.join(cols)}) VALUES ({ph})"
            for r in rows:
                dst.execute(sql, tuple(r[c] for c in cols))
            dst.commit()
            ok(f"Migrated {t}: {len(rows)} rows")
        src.close(); dst.close()
        ok("Migration complete")
    except Exception as e:
        err(f"Migration failed: {e}")


def summary(config):
    head("Setup Complete ✅")
    print(f"""
  {BOLD}Backend{D}       : {G}{config['backend'].upper()}{D}""")
    if config["backend"] == "mysql":
        print(f"""  {BOLD}MySQL{D}         : {config['host']}:{config['port']}
  {BOLD}Database{D}      : {config['database']}
  {BOLD}DB User{D}       : {config['user']}
  {BOLD}Password{D}      : see .env (KEEP SAFE!)""")
    else:
        print(f"""  {BOLD}SQLite file{D}   : itechkey.db""")
    print(f"""
  {BOLD}Next steps:{D}
    1. {G}python itechkey_monitor.py{D}
    2. Open {G}http://localhost:5000{D}
    3. Login: {BOLD}admin / admin{D} {Y}→ change immediately!{D}
    4. Configure SMTP in Settings page.
    5. Add devices, discover interfaces, add sensors.

  {BOLD}Production:{D}
    gunicorn -w 4 --threads 8 -b 0.0.0.0:5000 itechkey_monitor:app
""")


def main():
    print(f"""
{BOLD}{B}╔════════════════════════════════════════════════════════════════╗
║        iTechkey NetPulse — Auto Setup Wizard  v1.0.0            ║
║      MySQL (1000+ sensors)  ·  SQLite (small)                  ║
╚════════════════════════════════════════════════════════════════╝{D}
""")
    check_python()
    head("Checking Packages")
    check_packages()
    config = choose_backend()
    if not config:
        err("Setup aborted"); sys.exit(1)
    write_config(config)
    if not init_database(config):
        err("DB init failed"); sys.exit(1)
    migrate_sqlite_if_any(config)
    summary(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}Setup cancelled{D}"); sys.exit(1)