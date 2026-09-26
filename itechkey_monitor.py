"""
iTechkey NetPulse - Network Monitoring System
Version : 1.1.0
Author  : iTechkey
Contact : admin@itechkey.com
"""

import os
import sys
import json
import time
import socket
import ssl
import smtplib
import threading
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from io import BytesIO
from email.message import EmailMessage

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, flash, jsonify, send_file, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from ping3 import ping
except ImportError:
    ping = None

try:
    import requests as _requests
except ImportError:
    _requests = None

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    Image as RLImage,
)

from itechkey_snmp import (
    SNMPClient, SNMPError, SNMPTimeout,
    discover_interfaces, IF_OPER_STATUS, IF_MIB,
)


# ============================================================================
# METADATA
# ============================================================================
__app_name__    = "iTechkey NetPulse"
__app_version__ = "1.1.0"
__author__      = "iTechkey"
__contact__     = "admin@itechkey.com"


# ============================================================================
# PATHS & CONFIG
# ============================================================================
BASE_DIR = Path(__file__).resolve().parent

_ENV_FILE = BASE_DIR / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

DB_BACKEND = os.environ.get("ITECHKEY_DB", "sqlite").lower()
DB_FILE = BASE_DIR / "itechkey.db"
LOG_FILE = BASE_DIR / "itechkey.log"
SECRET_FILE = BASE_DIR / "itechkey_secret.key"
STATIC_DIR = BASE_DIR / "static"
LOGO_FILE = STATIC_DIR / "itechkey-logo.png"

MYSQL_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.environ.get("MYSQL_PORT", 3306)),
    "user": os.environ.get("MYSQL_USER", "itechkey"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DB", "itechkey_monitor"),
    "charset": "utf8mb4",
    "autocommit": False,
}

DEFAULT_INTERVAL = 60
DEFAULT_TIMEOUT = 5
DEFAULT_RETRIES = 2
MAX_POINTS_CHART = 500
RETENTION_MONTHS = 6
MONITOR_WORKERS = int(os.environ.get("MONITOR_WORKERS", 20))
BATCH_FLUSH_SECONDS = 5

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

STATIC_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

if SECRET_FILE.exists():
    app.secret_key = SECRET_FILE.read_bytes()
else:
    _key = os.urandom(32)
    SECRET_FILE.write_bytes(_key)
    app.secret_key = _key


# ============================================================================
# FIREWALL OIDs
# ============================================================================
FIREWALL_OIDS = {
    "fortinet": {
        "label": "Fortinet FortiGate",
        "sessions": "1.3.6.1.4.1.12356.101.4.1.8.0",
        "cpu": "1.3.6.1.4.1.12356.101.4.1.3.0",
        "memory": "1.3.6.1.4.1.12356.101.4.1.4.0",
    },
    "paloalto": {
        "label": "Palo Alto PAN-OS",
        "sessions": "1.3.6.1.4.1.25461.2.1.2.3.1.0",
        "cpu": "1.3.6.1.4.1.25461.2.1.2.1.6.0",
        "memory": "1.3.6.1.4.1.25461.2.1.2.1.8.0",
    },
    "cisco_asa": {
        "label": "Cisco ASA",
        "sessions": "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6",
        "cpu": "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1",
        "memory": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    },
    "pfsense": {
        "label": "pfSense / OPNsense",
        "sessions": "1.3.6.1.4.1.12325.1.200.1.7.0",
        "cpu": "1.3.6.1.4.1.12325.1.200.1.2.0",
        "memory": "1.3.6.1.4.1.12325.1.200.1.3.0",
    },
    "sophos": {
        "label": "Sophos Firewall",
        "sessions": "1.3.6.1.4.1.2604.5.1.1.1.8.0",
        "cpu": "1.3.6.1.4.1.2604.5.1.1.1.2.0",
        "memory": "1.3.6.1.4.1.2604.5.1.1.1.4.0",
    },
}


# ============================================================================
# DATABASE SCHEMAS
# ============================================================================
SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snmp_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    version TEXT DEFAULT '2c',
    community TEXT NOT NULL,
    port INTEGER DEFAULT 161,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    snmp_cred_id INTEGER,
    device_role TEXT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    tags TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sensors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    sensor_type TEXT NOT NULL,
    params TEXT,
    interval_seconds INTEGER DEFAULT 60,
    timeout_seconds INTEGER DEFAULT 5,
    retries INTEGER DEFAULT 2,
    enabled INTEGER DEFAULT 1,
    paused_until TEXT,
    warning_latency_ms INTEGER,
    error_latency_ms INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sensor_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms REAL,
    message TEXT,
    value_in REAL,
    value_out REAL,
    meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_sd_sid_ts ON sensor_data(sensor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_sd_ts ON sensor_data(timestamp);
CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id INTEGER,
    condition TEXT NOT NULL,
    threshold REAL,
    notify_email INTEGER DEFAULT 1,
    notify_webhook INTEGER DEFAULT 0,
    webhook_url TEXT,
    cooldown_minutes INTEGER DEFAULT 15,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id INTEGER,
    rule_id INTEGER,
    timestamp TEXT NOT NULL,
    subject TEXT,
    message TEXT,
    status TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

SCHEMA_MYSQL = """
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description VARCHAR(255),
    created_at VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS snmp_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    version VARCHAR(8) DEFAULT '2c',
    community VARCHAR(255) NOT NULL,
    port INT DEFAULT 161,
    created_at VARCHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_id INT,
    snmp_cred_id INT,
    device_role VARCHAR(32),
    name VARCHAR(150) NOT NULL,
    host VARCHAR(150) NOT NULL,
    tags VARCHAR(255),
    created_at VARCHAR(32) NOT NULL,
    INDEX idx_dev_group (group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sensors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    name VARCHAR(150) NOT NULL,
    sensor_type VARCHAR(32) NOT NULL,
    params TEXT,
    interval_seconds INT DEFAULT 60,
    timeout_seconds INT DEFAULT 5,
    retries INT DEFAULT 2,
    enabled INT DEFAULT 1,
    paused_until VARCHAR(32),
    warning_latency_ms INT,
    error_latency_ms INT,
    created_at VARCHAR(32) NOT NULL,
    INDEX idx_sensor_device (device_id),
    INDEX idx_sensor_enabled (enabled, interval_seconds)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sensor_data (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sensor_id INT NOT NULL,
    timestamp DATETIME NOT NULL,
    status VARCHAR(16) NOT NULL,
    latency_ms DOUBLE,
    message VARCHAR(500),
    value_in DOUBLE,
    value_out DOUBLE,
    meta TEXT,
    INDEX idx_sd_sid_ts (sensor_id, timestamp),
    INDEX idx_sd_ts (timestamp),
    INDEX idx_sd_status_ts (status, timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS alert_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sensor_id INT,
    condition VARCHAR(32) NOT NULL,
    threshold DOUBLE,
    notify_email INT DEFAULT 1,
    notify_webhook INT DEFAULT 0,
    webhook_url VARCHAR(500),
    cooldown_minutes INT DEFAULT 15,
    enabled INT DEFAULT 1,
    created_at VARCHAR(32) NOT NULL,
    INDEX idx_rule_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sensor_id INT,
    rule_id INT,
    timestamp DATETIME NOT NULL,
    subject VARCHAR(500),
    message TEXT,
    status VARCHAR(100),
    INDEX idx_notif_ts (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS settings (
    `key` VARCHAR(100) PRIMARY KEY,
    value TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

SCHEMA = SCHEMA_MYSQL if DB_BACKEND == "mysql" else SCHEMA_SQLITE


# ============================================================================
# DATABASE LAYER
# ============================================================================
_MYSQL_POOL = None


def _get_pool():
    global _MYSQL_POOL
    if _MYSQL_POOL is None:
        from dbutils.pooled_db import PooledDB
        import pymysql
        _MYSQL_POOL = PooledDB(
            creator=pymysql, maxconnections=30, mincached=5,
            maxcached=20, blocking=True, ping=1, **MYSQL_CONFIG,
        )
    return _MYSQL_POOL


class _Row(dict):
    pass


class _MySQLCursor:
    def __init__(self, cur):
        self._cur = cur
    def fetchone(self):
        row = self._cur.fetchone()
        return _Row(row) if row else None
    def fetchall(self):
        return [_Row(r) for r in self._cur.fetchall()]
    def __iter__(self):
        for r in self._cur:
            yield _Row(r)
    @property
    def lastrowid(self):
        return self._cur.lastrowid
    def close(self):
        self._cur.close()


class _DB:
    def __init__(self):
        self._is_mysql = (DB_BACKEND == "mysql")
        if self._is_mysql:
            import pymysql
            import pymysql.cursors
            self._conn = _get_pool().connection()
            self._cursorclass = pymysql.cursors.DictCursor
        else:
            import sqlite3
            self._conn = sqlite3.connect(
                DB_FILE, timeout=15, check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.execute("PRAGMA busy_timeout = 5000")

    def _adapt(self, sql):
        if self._is_mysql:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql, params=()):
        if self._is_mysql:
            cur = self._conn.cursor(self._cursorclass)
            cur.execute(self._adapt(sql), params)
            return _MySQLCursor(cur)
        return self._conn.execute(sql, params)

    def executemany(self, sql, seq):
        if self._is_mysql:
            cur = self._conn.cursor(self._cursorclass)
            cur.executemany(self._adapt(sql), seq)
            return _MySQLCursor(cur)
        return self._conn.executemany(sql, seq)

    def executescript(self, sql):
        if self._is_mysql:
            import pymysql
            cur = self._conn.cursor()
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if not stmt or stmt.startswith("--"):
                    continue
                try:
                    cur.execute(stmt)
                except pymysql.err.OperationalError as e:
                    if "already exists" not in str(e):
                        raise
            cur.close()
        else:
            self._conn.executescript(sql)

    def commit(self):
        self._conn.commit()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


def db():
    return _DB()


# ============================================================================
# INIT DATABASE
# ============================================================================
def init_db():
    conn = db()
    conn.executescript(SCHEMA)

    if DB_BACKEND == "sqlite":
        def _ensure_col(table, col, decl):
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(" + table + ")")]
            if col not in cols:
                conn.execute("ALTER TABLE " + table + " ADD COLUMN " + col + " " + decl)
        _ensure_col("devices", "snmp_cred_id", "INTEGER")
        _ensure_col("devices", "device_role", "TEXT")
        _ensure_col("sensor_data", "value_in", "REAL")
        _ensure_col("sensor_data", "value_out", "REAL")
        _ensure_col("sensor_data", "meta", "TEXT")

    row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row and row["c"] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) "
            "VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin"),
             datetime.now().isoformat(timespec="seconds")),
        )

    defaults = {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": "587",
        "smtp_security": "starttls",
        "smtp_sender": "",
        "smtp_password": "",
        "smtp_recipients": "",
        "email_enabled": "0",
    }
    if DB_BACKEND == "mysql":
        sql_ins = "INSERT IGNORE INTO settings (`key`, value) VALUES (?, ?)"
    else:
        sql_ins = "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)"
    for k, v in defaults.items():
        conn.execute(sql_ins, (k, v))

    conn.commit()
    conn.close()


def get_setting(key, default=None):
    conn = db()
    try:
        if DB_BACKEND == "mysql":
            row = conn.execute(
                "SELECT value FROM settings WHERE `key` = ?", (key,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key, value):
    conn = db()
    try:
        if DB_BACKEND == "mysql":
            sql = ("INSERT INTO settings (`key`, value) VALUES (?, ?) "
                   "ON DUPLICATE KEY UPDATE value = VALUES(value)")
        else:
            sql = ("INSERT INTO settings (key, value) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        conn.execute(sql, (key, str(value)))
        conn.commit()
    finally:
        conn.close()


# ============================================================================
# PARTITIONS (MySQL only)
# ============================================================================
def ensure_partitions():
    if DB_BACKEND != "mysql":
        return
    conn = db()
    try:
        nxt = (datetime.now().replace(day=1) + timedelta(days=32)).replace(day=1)
        nxt2 = (nxt + timedelta(days=32)).replace(day=1)
        pname = "p" + nxt.strftime("%Y%m")
        exists = conn.execute(
            "SELECT PARTITION_NAME FROM information_schema.PARTITIONS "
            "WHERE TABLE_NAME='sensor_data' AND PARTITION_NAME=?",
            (pname,),
        ).fetchone()
        if not exists:
            sql = ("ALTER TABLE sensor_data REORGANIZE PARTITION pmax INTO ("
                   "PARTITION " + pname + " VALUES LESS THAN ('"
                   + nxt2.strftime("%Y-%m-%d") + "'), "
                   "PARTITION pmax VALUES LESS THAN (MAXVALUE))")
            try:
                conn.execute(sql)
                conn.commit()
                logging.info("Created partition %s", pname)
            except Exception as e:
                logging.warning("Partition create failed: %s", e)
    finally:
        conn.close()


def drop_old_partitions():
    if DB_BACKEND != "mysql":
        return
    conn = db()
    try:
        cutoff = datetime.now() - timedelta(days=RETENTION_MONTHS * 30)
        rows = conn.execute(
            "SELECT PARTITION_NAME FROM information_schema.PARTITIONS "
            "WHERE TABLE_NAME='sensor_data' "
            "AND PARTITION_NAME LIKE 'p%' "
            "AND PARTITION_NAME != 'pmax'"
        ).fetchall()
        for r in rows:
            try:
                pdate = datetime.strptime(r["PARTITION_NAME"][1:], "%Y%m")
                if pdate < cutoff:
                    conn.execute(
                        "ALTER TABLE sensor_data DROP PARTITION "
                        + r["PARTITION_NAME"]
                    )
                    conn.commit()
            except ValueError:
                continue
    finally:
        conn.close()


# ============================================================================
# AUTH
# ============================================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


# ============================================================================
# SENSOR CHECK FUNCTIONS
# ============================================================================
def check_ping(host, timeout, retries, warn, err):
    last_err = ""
    for _ in range(retries + 1):
        latency = None
        try:
            if ping is not None:
                result = ping(host, timeout=timeout, unit="ms")
                if result is not None and result is not False:
                    latency = float(result)
            else:
                import re
                cmd = (["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
                       if os.name == "nt"
                       else ["ping", "-c", "1", "-W", str(int(timeout)), host])
                cp = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=timeout + 2, encoding="utf-8", errors="replace",
                )
                m = re.search(r"time[=<]\s*([\d.]+)\s*ms", cp.stdout, re.I)
                if m:
                    latency = float(m.group(1))
        except Exception as e:
            last_err = str(e)
        if latency is not None:
            status = "up"
            if warn and latency >= warn:
                status = "warning"
            if err and latency >= err:
                status = "down"
            return status, latency, "Reply in %.1f ms" % latency
        time.sleep(0.5)
    return "down", None, "Timeout" + (" — " + last_err if last_err else "")


def check_tcp(host, port, timeout, retries, warn, err):
    last_err = ""
    for _ in range(retries + 1):
        t0 = time.time()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                latency = (time.time() - t0) * 1000
                status = "up"
                if warn and latency >= warn:
                    status = "warning"
                if err and latency >= err:
                    status = "down"
                return status, latency, "TCP %s open in %.0f ms" % (port, latency)
        except Exception as e:
            last_err = str(e)
        time.sleep(0.3)
    return "down", None, "TCP %s closed — %s" % (port, last_err)


def check_http(url, timeout, retries, warn, err):
    if _requests is None:
        return "down", None, "requests library not installed"
    last_err = ""
    for _ in range(retries + 1):
        t0 = time.time()
        try:
            resp = _requests.get(url, timeout=timeout, allow_redirects=True)
            latency = (time.time() - t0) * 1000
            if 200 <= resp.status_code < 400:
                status = "up"
                if warn and latency >= warn:
                    status = "warning"
                if err and latency >= err:
                    status = "down"
                return status, latency, "HTTP %s in %.0f ms" % (
                    resp.status_code, latency,
                )
            return "down", latency, "HTTP %s" % resp.status_code
        except Exception as e:
            last_err = str(e)
        time.sleep(0.3)
    return "down", None, "HTTP check failed — " + last_err


def check_dns(host, timeout, retries, warn, err):
    last_err = ""
    for _ in range(retries + 1):
        t0 = time.time()
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(host)
            latency = (time.time() - t0) * 1000
            return "up", latency, "Resolved to " + ip
        except Exception as e:
            last_err = str(e)
        time.sleep(0.2)
    return "down", None, "DNS lookup failed — " + last_err


def _sensor_device_ctx(sensor_row):
    conn = db()
    try:
        return conn.execute(
            "SELECT d.*, c.community, c.version AS snmp_ver, c.port AS snmp_port "
            "FROM devices d "
            "LEFT JOIN snmp_credentials c ON c.id = d.snmp_cred_id "
            "WHERE d.id = ?",
            (sensor_row["device_id"],),
        ).fetchone()
    finally:
        conn.close()


def _snmp_for(dev, timeout=5, retries=1):
    if not dev or not dev["community"]:
        raise SNMPError("Device has no SNMP credentials attached")
    ver = 1 if (dev["snmp_ver"] or "2c") == "2c" else 0
    return SNMPClient(
        dev["host"], community=dev["community"], version=ver,
        port=dev["snmp_port"] or 161, timeout=timeout, retries=retries,
    )


def check_snmp_traffic(sensor_row):
    params = json.loads(sensor_row["params"] or "{}")
    if_index = params.get("if_index")
    if if_index is None:
        return "down", None, "No if_index configured", None

    dev = _sensor_device_ctx(sensor_row)
    try:
        cli = _snmp_for(dev, timeout=sensor_row["timeout_seconds"] or 5,
                        retries=sensor_row["retries"] or 1)
    except SNMPError as e:
        return "down", None, "SNMP: " + str(e), None

    in_oct = out_oct = None
    try:
        in_oct = cli.get("1.3.6.1.2.1.31.1.1.1.6." + str(if_index))
        out_oct = cli.get("1.3.6.1.2.1.31.1.1.1.10." + str(if_index))
    except SNMPError:
        pass

    if in_oct is None or out_oct is None:
        try:
            in_oct = cli.get("1.3.6.1.2.1.2.2.1.10." + str(if_index))
            out_oct = cli.get("1.3.6.1.2.1.2.2.1.16." + str(if_index))
        except SNMPError as e:
            return "down", None, "SNMP GET failed: " + str(e), None

    if in_oct is None or out_oct is None:
        return "down", None, "ifIndex " + str(if_index) + " not present", None

    try:
        oper = cli.get("1.3.6.1.2.1.2.2.1.8." + str(if_index))
        oper_str = IF_OPER_STATUS.get(oper, str(oper))
    except SNMPError:
        oper_str = "?"

    conn = db()
    try:
        last = conn.execute(
            "SELECT timestamp, meta FROM sensor_data "
            "WHERE sensor_id = ? ORDER BY id DESC LIMIT 1",
            (sensor_row["id"],),
        ).fetchone()
    finally:
        conn.close()

    now = datetime.now()
    in_mbps = out_mbps = None
    if last and last["meta"]:
        try:
            meta_old = json.loads(last["meta"])
            last_in = meta_old.get("in_octets")
            last_out = meta_old.get("out_octets")
            ts = last["timestamp"]
            if isinstance(ts, str):
                lt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            else:
                lt = ts
            dt = (now - lt).total_seconds()
            if dt > 0 and last_in is not None and last_out is not None:
                d_in = in_oct - last_in
                d_out = out_oct - last_out
                if in_oct < 2 ** 32 and d_in < 0:
                    d_in += 2 ** 32
                if out_oct < 2 ** 32 and d_out < 0:
                    d_out += 2 ** 32
                in_mbps = (d_in * 8) / dt / 1_000_000
                out_mbps = (d_out * 8) / dt / 1_000_000
        except (ValueError, KeyError, TypeError):
            pass

    meta = json.dumps({
        "in_octets": in_oct, "out_octets": out_oct,
        "if_index": if_index, "oper_status": oper_str,
        "in_mbps": in_mbps, "out_mbps": out_mbps,
    })

    if in_mbps is None:
        return "up", None, "Baseline (in=" + str(in_oct) + " B, out=" + str(out_oct) + " B)", meta

    peak = max(in_mbps, out_mbps or 0)
    warn = sensor_row["warning_latency_ms"]
    err = sensor_row["error_latency_ms"]
    status = "up"
    if warn and peak >= warn:
        status = "warning"
    if err and peak >= err:
        status = "down"
    msg = "IN %.2f Mbps | OUT %.2f Mbps | oper=%s" % (in_mbps, out_mbps, oper_str)
    return status, round(in_mbps, 3), msg, meta


def check_snmp_interface(sensor_row):
    params = json.loads(sensor_row["params"] or "{}")
    if_index = params.get("if_index")
    if if_index is None:
        return "down", None, "No if_index configured", None

    dev = _sensor_device_ctx(sensor_row)
    try:
        cli = _snmp_for(dev, timeout=sensor_row["timeout_seconds"] or 5,
                        retries=sensor_row["retries"] or 1)
        oper = cli.get("1.3.6.1.2.1.2.2.1.8." + str(if_index))
        in_err = cli.get("1.3.6.1.2.1.2.2.1.14." + str(if_index)) or 0
        out_err = cli.get("1.3.6.1.2.1.2.2.1.20." + str(if_index)) or 0
    except SNMPError as e:
        return "down", None, "SNMP error: " + str(e), None

    oper_str = IF_OPER_STATUS.get(oper, str(oper))
    status = "up" if oper == 1 else "down"
    meta = json.dumps({
        "oper_status": oper_str, "in_errors": in_err,
        "out_errors": out_err, "if_index": if_index,
    })
    msg = "oper=%s in_err=%s out_err=%s" % (oper_str, in_err, out_err)
    return status, None, msg, meta


def check_firewall_health(sensor_row):
    params = json.loads(sensor_row["params"] or "{}")
    vendor = params.get("vendor", "fortinet")
    oids = FIREWALL_OIDS.get(vendor)
    if not oids:
        return "down", None, "Unknown vendor: " + vendor, None

    dev = _sensor_device_ctx(sensor_row)
    try:
        cli = _snmp_for(dev, timeout=sensor_row["timeout_seconds"] or 5,
                        retries=sensor_row["retries"] or 1)
    except SNMPError as e:
        return "down", None, "SNMP: " + str(e), None

    res = {}
    for key in ("sessions", "cpu", "memory"):
        oid = oids.get(key)
        res[key] = None
        if not oid:
            continue
        try:
            res[key] = cli.get(oid)
        except SNMPError:
            pass

    if res["sessions"] is None and res["cpu"] is None and res["memory"] is None:
        return "down", None, "No SNMP response from firewall", None

    sess = res["sessions"]
    status = "up"
    warn = sensor_row["warning_latency_ms"]
    err = sensor_row["error_latency_ms"]
    if sess is not None and warn and sess >= warn:
        status = "warning"
    if sess is not None and err and sess >= err:
        status = "down"

    parts = []
    if sess is not None:
        parts.append("sessions=" + str(sess))
    if res["cpu"] is not None:
        parts.append("cpu=" + str(res["cpu"]) + "%")
    if res["memory"] is not None:
        parts.append("mem=" + str(res["memory"]) + "%")
    return status, sess, " | ".join(parts), json.dumps(res)


def run_sensor_check(sensor_row):
    stype = sensor_row["sensor_type"]
    params = json.loads(sensor_row["params"] or "{}")
    conn = db()
    try:
        dev = conn.execute(
            "SELECT host FROM devices WHERE id = ?",
            (sensor_row["device_id"],),
        ).fetchone()
    finally:
        conn.close()

    host = dev["host"] if dev else ""
    timeout = sensor_row["timeout_seconds"] or DEFAULT_TIMEOUT
    retries = sensor_row["retries"] or 0
    warn = sensor_row["warning_latency_ms"]
    err = sensor_row["error_latency_ms"]

    if stype == "ping":
        s, l, m = check_ping(host, timeout, retries, warn, err)
        return s, l, m, None
    if stype == "tcp":
        s, l, m = check_tcp(host, params.get("port", 80), timeout, retries, warn, err)
        return s, l, m, None
    if stype in ("http", "https"):
        url = params.get("url") or (stype + "://" + host)
        s, l, m = check_http(url, timeout, retries, warn, err)
        return s, l, m, None
    if stype == "dns":
        s, l, m = check_dns(host, timeout, retries, warn, err)
        return s, l, m, None
    if stype == "snmp_traffic":
        return check_snmp_traffic(sensor_row)
    if stype == "snmp_interface":
        return check_snmp_interface(sensor_row)
    if stype == "firewall_health":
        return check_firewall_health(sensor_row)
    return "down", None, "Unknown sensor type: " + stype, None


# ============================================================================
# ALERT ENGINE
# ============================================================================
_last_alert = {}


def _rule_matches(rule, status, latency, prev_status):
    cond = rule["condition"]
    if cond == "down" and status == "down":
        return True
    if cond == "up" and status == "up" and prev_status in ("down", "warning"):
        return True
    if cond == "warning" and status == "warning":
        return True
    if cond == "latency_gt" and latency is not None \
            and rule["threshold"] is not None and latency > rule["threshold"]:
        return True
    return False


def process_alerts(sensor, status, latency, message, prev_status):
    conn = db()
    try:
        rules = conn.execute(
            "SELECT * FROM alert_rules WHERE enabled = 1 "
            "AND (sensor_id = ? OR sensor_id IS NULL)",
            (sensor["id"],),
        ).fetchall()
        if not rules:
            return
        dev = conn.execute(
            "SELECT d.name AS dname, g.name AS gname "
            "FROM devices d LEFT JOIN groups g ON g.id = d.group_id "
            "WHERE d.id = ?",
            (sensor["device_id"],),
        ).fetchone()
    finally:
        conn.close()

    dev_name = dev["dname"] if dev else "?"
    grp_name = (dev["gname"] if dev and dev["gname"] else "-")
    now = datetime.now()

    for rule in rules:
        if not _rule_matches(rule, status, latency, prev_status):
            continue
        key = (rule["id"], sensor["id"])
        last = _last_alert.get(key)
        cooldown = timedelta(minutes=rule["cooldown_minutes"] or 15)
        if last and now - last < cooldown:
            continue
        _last_alert[key] = now

        subject = "[%s] %s / %s / %s" % (
            status.upper(), grp_name, dev_name, sensor["name"])
        body = (
            "Sensor : %s (%s)\nDevice : %s (group: %s)\nStatus : %s\n"
            "Latency: %s\nMessage: %s\nTime   : %s\n\n— %s v%s\n"
        ) % (
            sensor["name"], sensor["sensor_type"], dev_name, grp_name,
            status.upper(),
            ("%.1f ms" % latency) if latency is not None else "-",
            message, now.strftime("%Y-%m-%d %H:%M:%S"),
            __app_name__, __app_version__,
        )
        _deliver_notification(rule, sensor["id"], subject, body)


def _deliver_notification(rule, sensor_id, subject, body):
    flags = []
    if rule["notify_email"]:
        try:
            send_alert_email(subject, body)
            flags.append("email:sent")
        except Exception as e:
            logging.exception("Alert email failed")
            flags.append("email:failed(%s)" % e)

    if rule["notify_webhook"] and rule["webhook_url"]:
        try:
            if _requests:
                _requests.post(
                    rule["webhook_url"],
                    json={"subject": subject, "body": body, "source": __app_name__},
                    timeout=10,
                )
                flags.append("webhook:sent")
        except Exception as e:
            flags.append("webhook:failed(%s)" % e)

    conn = db()
    try:
        conn.execute(
            "INSERT INTO notifications "
            "(sensor_id, rule_id, timestamp, subject, message, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sensor_id, rule["id"],
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             subject, body, ",".join(flags) or "no-channel"),
        )
        conn.commit()
    finally:
        conn.close()


def send_alert_email(subject, body):
    if get_setting("email_enabled") != "1":
        raise RuntimeError("Email not enabled in settings")

    sender = get_setting("smtp_sender")
    password = get_setting("smtp_password")
    recipients = [
        r.strip() for r in (get_setting("smtp_recipients") or "").split(",")
        if r.strip()
    ]
    if not (sender and password and recipients):
        raise RuntimeError("SMTP sender/password/recipients not configured")

    msg = EmailMessage()
    msg["From"] = "%s <%s>" % (__app_name__, sender)
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body)

    logo_data = LOGO_FILE.read_bytes() if LOGO_FILE.exists() else None
    logo_tag = ('<img src="cid:itechkey_logo" style="height:44px">'
                if logo_data else '<b style="color:#0a66c2">iTechkey</b>')

    html_body = (
        '<!doctype html><html><body style="font-family:Arial;color:#1a2533;'
        'max-width:720px;margin:auto">'
        '<div style="border-bottom:3px solid #0a66c2;padding-bottom:10px;'
        'margin-bottom:16px">' + logo_tag +
        '<span style="float:right;color:#6c757d;font-size:12px;'
        'padding-top:14px">' + __app_name__ + ' v' + __app_version__ + '</span>'
        '</div>'
        '<pre style="font-family:Consolas,monospace;font-size:13px;'
        'white-space:pre-wrap">' + body + '</pre>'
        '<p style="color:#adb5bd;font-size:11px;margin-top:24px;'
        'border-top:1px solid #e9ecef;padding-top:10px">'
        '© ' + str(datetime.now().year) + ' ' + __author__ + ' · ' +
        __contact__ + '</p></body></html>'
    )
    msg.add_alternative(html_body, subtype="html")

    if logo_data:
        msg.get_payload()[-1].add_related(
            logo_data, maintype="image", subtype="png",
            cid="<itechkey_logo>", filename="itechkey-logo.png",
            disposition="inline",
        )

    host = get_setting("smtp_host", "smtp.gmail.com")
    port = int(get_setting("smtp_port", "587"))
    security = get_setting("smtp_security", "starttls").lower()

    if security == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=30,
                              context=ssl.create_default_context()) as s:
            s.login(sender, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as s:
            s.ehlo()
            if security == "starttls":
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            s.login(sender, password)
            s.send_message(msg)


# ============================================================================
# MONITOR ENGINE
# ============================================================================
_monitor_stop = threading.Event()
_data_queue = []
_queue_lock = threading.Lock()


def _flush_batch():
    global _data_queue
    with _queue_lock:
        if not _data_queue:
            return
        batch = _data_queue
        _data_queue = []
    conn = db()
    try:
        conn.executemany(
            "INSERT INTO sensor_data "
            "(sensor_id, timestamp, status, latency_ms, message, "
            "value_in, value_out, meta) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            batch,
        )
        conn.commit()
    except Exception:
        logging.exception("Batch flush failed (%d rows)", len(batch))
    finally:
        conn.close()


def _poll_sensor(sensor):
    try:
        status, latency, message, meta = run_sensor_check(sensor)
    except Exception as e:
        logging.exception("Sensor %s crashed", sensor["id"])
        status, latency, message, meta = "down", None, "crash: " + str(e), None

    v_in = v_out = None
    if meta and sensor["sensor_type"] == "snmp_traffic":
        try:
            md = json.loads(meta)
            v_in = md.get("in_mbps")
            v_out = md.get("out_mbps")
        except (ValueError, TypeError):
            pass

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "row": (sensor["id"], now_str, status, latency, message, v_in, v_out, meta),
        "sensor": sensor,
        "status": status,
        "latency": latency,
        "message": message,
    }


def _sensor_due(sensor, now):
    if sensor["paused_until"]:
        try:
            if datetime.fromisoformat(sensor["paused_until"]) > now:
                return False
        except ValueError:
            pass

    conn = db()
    try:
        row = conn.execute(
            "SELECT timestamp FROM sensor_data WHERE sensor_id = ? "
            "ORDER BY id DESC LIMIT 1", (sensor["id"],),
        ).fetchone()
    finally:
        conn.close()

    interval = max(5, sensor["interval_seconds"] or 60)
    if not row:
        return True

    ts = row["timestamp"]
    if isinstance(ts, str):
        try:
            lt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return True
    else:
        lt = ts
    return (now - lt).total_seconds() >= interval


def _get_prev_status(sensor_id):
    conn = db()
    try:
        row = conn.execute(
            "SELECT status FROM sensor_data WHERE sensor_id = ? "
            "ORDER BY id DESC LIMIT 1", (sensor_id,),
        ).fetchone()
        return row["status"] if row else None
    finally:
        conn.close()


def monitor_loop():
    logging.info("%s v%s monitor started (workers=%d)",
                 __app_name__, __app_version__, MONITOR_WORKERS)
    with ThreadPoolExecutor(max_workers=MONITOR_WORKERS,
                            thread_name_prefix="poll") as pool:
        while not _monitor_stop.is_set():
            t0 = time.time()
            now = datetime.now()

            conn = db()
            try:
                sensors = conn.execute(
                    "SELECT * FROM sensors WHERE enabled = 1"
                ).fetchall()
            finally:
                conn.close()

            due = [s for s in sensors if _sensor_due(s, now)]
            if due:
                futures = {pool.submit(_poll_sensor, s): s for s in due}
                for fut in as_completed(futures):
                    try:
                        result = fut.result(timeout=60)
                        with _queue_lock:
                            _data_queue.append(result["row"])
                        s = futures[fut]
                        prev = _get_prev_status(s["id"])
                        process_alerts(s, result["status"], result["latency"],
                                       result["message"], prev)
                    except Exception:
                        logging.exception("Poll future failed")
                _flush_batch()

            duration = time.time() - t0
            logging.info("Cycle: %d/%d polled in %.1fs",
                         len(due), len(sensors), duration)
            _monitor_stop.wait(max(1.0, 5.0 - duration))


def batch_flush_loop():
    while not _monitor_stop.is_set():
        try:
            _flush_batch()
        except Exception:
            logging.exception("Flusher error")
        _monitor_stop.wait(BATCH_FLUSH_SECONDS)


def retention_loop():
    while not _monitor_stop.is_set():
        try:
            ensure_partitions()
            drop_old_partitions()
            cutoff = (datetime.now() - timedelta(days=90)).strftime(
                "%Y-%m-%d %H:%M:%S")
            conn = db()
            try:
                conn.execute(
                    "DELETE FROM notifications WHERE timestamp < ?", (cutoff,))
                conn.commit()
            finally:
                conn.close()
        except Exception:
            logging.exception("Retention error")
        _monitor_stop.wait(86400)


def start_monitor():
    threading.Thread(target=monitor_loop, name="monitor", daemon=True).start()
    threading.Thread(target=batch_flush_loop, name="flusher", daemon=True).start()
    threading.Thread(target=retention_loop, name="retention", daemon=True).start()


# ============================================================================
# BASE HTML TEMPLATE
# ============================================================================
BASE_HTML = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{{ title or 'iTechkey NetPulse' }} — iTechkey</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/static/itechkey-logo.png">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#f1f5f9;--fg:#1a2533;--primary:#0a66c2;--up:#16a34a;--warn:#f59e0b;--down:#dc2626;--dark:#0f1c2e}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Arial;background:var(--bg);color:var(--fg)}
nav{background:var(--dark);color:#fff;padding:10px 22px;display:flex;align-items:center;gap:18px;flex-wrap:wrap;box-shadow:0 2px 6px rgba(0,0,0,.2);border-bottom:3px solid var(--primary)}
nav a{color:#cfd8e3;text-decoration:none;font-weight:600;padding:6px 4px;font-size:14px}
nav a:hover,nav a.active{color:#fff;border-bottom:2px solid var(--primary)}
nav .brand{display:flex;align-items:center;gap:10px;margin-right:8px}
nav .brand img{height:32px;width:auto}
nav .brand span{font-size:11px;color:#9fb0c4;font-weight:600;letter-spacing:.8px;text-transform:uppercase}
nav .spacer{flex:1}
nav .user{font-size:13px;color:#9fb0c4}
.wrap{max-width:1400px;margin:20px auto;padding:0 16px}
h1,h2{margin:0 0 14px}
.btn{display:inline-block;padding:8px 14px;border-radius:6px;background:var(--primary);color:#fff;text-decoration:none;font-weight:600;border:none;cursor:pointer;font-size:13px}
.btn:hover{opacity:.9}
.btn.red{background:var(--down)}
.btn.grey{background:#6c757d}
.btn.green{background:var(--up)}
.btn.small{padding:5px 9px;font-size:12px}
.card{background:#fff;border-radius:10px;padding:16px 20px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:18px}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid #e4e8ed;font-size:13px}
th{background:#f8f9fb;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:#5b6b7b}
tr:hover td{background:#fafbfc}
.badge{display:inline-block;padding:4px 11px;border-radius:14px;color:#fff;font-weight:700;font-size:11px}
.up{background:var(--up)}
.down{background:var(--down)}
.warning{background:var(--warn);color:#111}
.paused{background:#6c757d}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}
.sensor-card{background:#fff;border-radius:10px;padding:14px;box-shadow:0 1px 4px rgba(0,0,0,.08);border-left:5px solid #ccc;cursor:pointer;transition:.15s}
.sensor-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.12)}
.sensor-card.up{border-left-color:var(--up)}
.sensor-card.warning{border-left-color:var(--warn)}
.sensor-card.down{border-left-color:var(--down)}
.sensor-card.paused{border-left-color:#6c757d}
.sensor-card h3{margin:0 0 6px;font-size:15px}
.sensor-card .meta{font-size:12px;color:#6c757d;margin-bottom:6px}
.sensor-card .lat{font-size:22px;font-weight:800;margin:4px 0}
.sensor-card .msg{font-size:11px;color:#8a97a5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.flash{padding:10px 14px;border-radius:6px;background:#fff3cd;color:#664d03;margin-bottom:14px;border:1px solid #ffe69c}
.flash.ok{background:#d1e7dd;color:#0f5132;border-color:#a3cfbb}
.flash.err{background:#f8d7da;color:#842029;border-color:#f1aeb5}
form .row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px}
form .row>div{flex:1;min-width:180px}
label{display:block;font-size:12px;color:#5b6b7b;font-weight:600;margin-bottom:4px}
input,select,textarea{width:100%;padding:8px 10px;border:1px solid #ced4da;border-radius:6px;font-size:13px;font-family:inherit;background:#fff}
input[type=checkbox]{width:auto}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.toolbar .spacer{flex:1}
.stat-box{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.stat{background:#fff;border-radius:10px;padding:14px 20px;box-shadow:0 1px 4px rgba(0,0,0,.08);min-width:140px}
.stat .v{font-size:24px;font-weight:800}
.stat .l{font-size:11px;text-transform:uppercase;color:#6c757d}
.chart-box{height:340px;position:relative}
footer{text-align:center;color:#8a97a5;font-size:12px;padding:20px 0 30px}
footer b{color:var(--primary)}
</style></head><body>
{% if session.user %}
<nav>
<span class="brand">
<img src="/static/itechkey-logo.png" alt="iTechkey" onerror="this.style.display='none'">
<span>NetPulse</span></span>
<a href="{{ url_for('dashboard') }}" class="{{ 'active' if active=='dash' }}">Dashboard</a>
<a href="{{ url_for('devices') }}" class="{{ 'active' if active=='devices' }}">Devices</a>
<a href="{{ url_for('sensors_page') }}" class="{{ 'active' if active=='sensors' }}">Sensors</a>
<a href="{{ url_for('traffic_dashboard') }}" class="{{ 'active' if active=='traffic' }}">Traffic</a>
<a href="{{ url_for('alerts_page') }}" class="{{ 'active' if active=='alerts' }}">Alerts</a>
<a href="{{ url_for('notifications_page') }}" class="{{ 'active' if active=='notif' }}">Log</a>
<a href="{{ url_for('settings_page') }}" class="{{ 'active' if active=='settings' }}">Settings</a>
<span class="spacer"></span>
<span class="user">👤 {{ session.user }}</span>
<a href="{{ url_for('logout') }}">Logout</a>
</nav>{% endif %}
<div class="wrap">
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
{% endwith %}
{{ body|safe }}
</div>
<footer>© {{ year }} <b>iTechkey</b> NetPulse v{{ version }} · {{ contact }}</footer>
</body></html>
"""


LOGIN_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<title>Sign in — iTechkey NetPulse</title>
<link rel="icon" href="/static/itechkey-logo.png">
<style>
body{margin:0;font-family:system-ui;background:#eef1f5}
.login-box{max-width:380px;margin:70px auto;background:#fff;border-radius:12px;padding:28px 30px;box-shadow:0 8px 30px rgba(0,0,0,.12)}
p.sub{color:#6c757d;font-size:13px;margin:0 0 22px;text-align:center}
label{display:block;font-size:12px;color:#5b6b7b;font-weight:600;margin-bottom:4px}
input{width:100%;padding:9px 11px;border:1px solid #ced4da;border-radius:6px;font-size:14px;margin-bottom:14px;box-sizing:border-box}
button{width:100%;padding:10px;background:#0a66c2;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:14px}
.flash{padding:9px 12px;background:#f8d7da;color:#842029;border-radius:6px;font-size:13px;margin-bottom:14px}
</style></head><body>
<div class="login-box">
<div style="text-align:center;margin-bottom:16px">
<img src="/static/itechkey-logo.png" style="max-width:210px;width:100%" onerror="this.outerHTML='<h2 style=color:#0a66c2>iTechkey</h2>'">
</div>
<p class="sub">Network Monitoring Console</p>
{% with msgs = get_flashed_messages() %}
{% for m in msgs %}<div class="flash">{{ m }}</div>{% endfor %}
{% endwith %}
<form method="post">
<label>Username</label><input name="username" autofocus required>
<label>Password</label><input name="password" type="password" required>
<button type="submit">Sign in</button>
</form></div></body></html>
"""


def render_ctx(body, title=None, active=None):
    return render_template_string(
        BASE_HTML, body=body, title=title, active=active,
        session=session, year=datetime.now().year,
        version=__app_version__, contact=__contact__,
    )


def _flash_redirect(url, msg, cat="ok"):
    flash(msg, cat)
    return redirect(url)


# ============================================================================
# ROUTES — AUTH
# ============================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        finally:
            conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session["user"] = username
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid credentials")
    return render_template_string(LOGIN_HTML)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================================
# ROUTES — DASHBOARD
# ============================================================================
DASH_HTML = """
<h1>Sensor Overview</h1>
<div class="stat-box">
<div class="stat"><div class="v">{{ counts.total }}</div><div class="l">Sensors</div></div>
<div class="stat"><div class="v" style="color:#16a34a">{{ counts.up }}</div><div class="l">Up</div></div>
<div class="stat"><div class="v" style="color:#f59e0b">{{ counts.warning }}</div><div class="l">Warning</div></div>
<div class="stat"><div class="v" style="color:#dc2626">{{ counts.down }}</div><div class="l">Down</div></div>
<div class="stat"><div class="v" style="color:#6c757d">{{ counts.paused }}</div><div class="l">Paused</div></div>
</div>
<div class="toolbar">
<a class="btn" href="{{ url_for('device_new') }}">+ Add Device</a>
<a class="btn green" href="{{ url_for('sensor_new') }}">+ Add Sensor</a>
<a class="btn grey" href="{{ url_for('dashboard') }}">↻ Refresh</a>
<span class="spacer"></span>
<form method="get" style="display:flex;gap:6px;align-items:center;margin:0">
<select name="group" onchange="this.form.submit()" style="min-width:160px">
<option value="">All groups</option>
{% for g in groups %}
<option value="{{ g.id }}" {{ 'selected' if group_filter == g.id|string }}>{{ g.name }}</option>
{% endfor %}
</select></form></div>
{% if sensors %}
<div class="grid">
{% for s in sensors %}
<a href="{{ url_for('sensor_detail', sid=s.id) }}" style="text-decoration:none;color:inherit">
<div class="sensor-card {{ s.effective_status }}">
<h3>{{ s.name }}</h3>
<div class="meta">{{ s.group_name or '—' }} / {{ s.device_name }} ({{ s.host }})</div>
<div style="display:flex;justify-content:space-between;align-items:center">
<div><div class="lat">
{% if s.latency_ms is not none %}{{ '%.0f'|format(s.latency_ms) }} ms{% else %}—{% endif %}
</div>
<div class="msg">{{ s.message or 'no data yet' }}</div>
</div>
<span class="badge {{ s.effective_status }}">{{ s.effective_status|upper }}</span>
</div></div></a>
{% endfor %}</div>
{% else %}
<div class="card">No sensors yet. <a href="{{ url_for('device_new') }}">Add a device</a> to begin.</div>
{% endif %}
"""


@app.route("/")
@login_required
def dashboard():
    group_filter = request.args.get("group", "")
    conn = db()
    try:
        if group_filter:
            sql = ("SELECT s.*, d.name AS device_name, d.host, "
                   "g.name AS group_name FROM sensors s "
                   "JOIN devices d ON d.id = s.device_id "
                   "LEFT JOIN groups g ON g.id = d.group_id "
                   "WHERE d.group_id = ? ORDER BY g.name, d.name, s.name")
            rows = conn.execute(sql, (group_filter,)).fetchall()
        else:
            sql = ("SELECT s.*, d.name AS device_name, d.host, "
                   "g.name AS group_name FROM sensors s "
                   "JOIN devices d ON d.id = s.device_id "
                   "LEFT JOIN groups g ON g.id = d.group_id "
                   "ORDER BY g.name, d.name, s.name")
            rows = conn.execute(sql).fetchall()

        now = datetime.now()
        sensors = []
        counts = {"total": 0, "up": 0, "warning": 0, "down": 0, "paused": 0}
        for s in rows:
            last = conn.execute(
                "SELECT status, latency_ms, message FROM sensor_data "
                "WHERE sensor_id = ? ORDER BY id DESC LIMIT 1", (s["id"],),
            ).fetchone()
            paused = False
            if s["paused_until"]:
                try:
                    paused = datetime.fromisoformat(s["paused_until"]) > now
                except ValueError:
                    pass
            last_status = last["status"] if last else None
            eff = "paused" if (paused or not s["enabled"]) else (last_status or "paused")
            sensors.append({
                "id": s["id"], "name": s["name"],
                "device_name": s["device_name"], "host": s["host"],
                "group_name": s["group_name"],
                "latency_ms": last["latency_ms"] if last else None,
                "message": last["message"] if last else None,
                "effective_status": eff,
            })
            counts["total"] += 1
            if eff in counts:
                counts[eff] += 1
        groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    finally:
        conn.close()

    body = render_template_string(
        DASH_HTML, sensors=sensors, counts=counts,
        groups=groups, group_filter=group_filter, url_for=url_for)
    return render_ctx(body, "Dashboard", "dash")


# ============================================================================
# ROUTES — SENSOR DETAIL
# ============================================================================
SENSOR_DETAIL_HTML = """
<div class="toolbar">
<a class="btn grey" href="{{ url_for('dashboard') }}">← Dashboard</a>
<span class="spacer"></span>
<a class="btn" href="{{ url_for('sensor_edit', sid=sensor.id) }}">Edit</a>
<form method="post" action="{{ url_for('sensor_delete', sid=sensor.id) }}"
      style="display:inline" onsubmit="return confirm('Delete?')">
<button class="btn red">Delete</button></form></div>
<div class="card">
<h1>{{ sensor.name }} <span class="badge {{ status }}">{{ status|upper }}</span></h1>
<div style="color:#5b6b7b;font-size:13px">
<b>Device:</b> {{ device.name }} ({{ device.host }}) &nbsp;|&nbsp;
<b>Group:</b> {{ group.name if group else '—' }} &nbsp;|&nbsp;
<b>Type:</b> {{ sensor.sensor_type }} &nbsp;|&nbsp;
<b>Interval:</b> {{ sensor.interval_seconds }}s</div>
{% if last %}<div style="margin-top:12px;font-size:14px">
<b>Last check:</b> {{ last.timestamp }} —
{% if last.latency_ms is not none %}<b>{{ '%.1f'|format(last.latency_ms) }} ms</b>{% endif %}
— {{ last.message }}</div>{% endif %}
</div>
<div class="card">
<div class="toolbar" style="margin-bottom:6px">
<h2 style="margin:0">Latency History</h2><span class="spacer"></span>
<select id="rangeSel" onchange="loadChart()">
<option value="24">Last 24 hours</option>
<option value="168">Last 7 days</option>
<option value="720">Last 30 days</option>
</select></div>
<div class="chart-box"><canvas id="chart"></canvas></div></div>
<div class="card"><h2>Recent Checks (latest 100)</h2>
<table><tr><th>Timestamp</th><th>Status</th><th>Latency</th><th>Message</th></tr>
{% for r in recent %}<tr><td>{{ r.timestamp }}</td>
<td><span class="badge {{ r.status }}">{{ r.status|upper }}</span></td>
<td>{{ '%.1f ms'|format(r.latency_ms) if r.latency_ms is not none else '-' }}</td>
<td>{{ r.message }}</td></tr>{% endfor %}</table></div>
<script>
let chart;
async function loadChart(){
  const h = document.getElementById('rangeSel').value;
  const res = await fetch('/api/sensor/{{ sensor.id }}/series?hours='+h);
  const data = await res.json();
  const ctx = document.getElementById('chart').getContext('2d');
  if (chart) chart.destroy();
  chart = new Chart(ctx,{type:'line',data:{labels:data.labels,datasets:[{
    label:'Latency (ms)',data:data.values,borderColor:'#0a66c2',
    backgroundColor:'rgba(10,102,194,.15)',fill:true,tension:.25,
    pointRadius:0,borderWidth:2,spanGaps:false}]},
    options:{responsive:true,maintainAspectRatio:false,
    interaction:{mode:'index',intersect:false},
    scales:{y:{beginAtZero:true,title:{display:true,text:'ms'}},
    x:{ticks:{maxTicksLimit:12}}},plugins:{legend:{display:false}}}});
}
loadChart();
</script>
"""


@app.route("/sensor/<int:sid>")
@login_required
def sensor_detail(sid):
    conn = db()
    try:
        sensor = conn.execute("SELECT * FROM sensors WHERE id = ?", (sid,)).fetchone()
        if not sensor:
            abort(404)
        device = conn.execute("SELECT * FROM devices WHERE id = ?",
                              (sensor["device_id"],)).fetchone()
        group = None
        if device and device["group_id"]:
            group = conn.execute("SELECT * FROM groups WHERE id = ?",
                                 (device["group_id"],)).fetchone()
        last = conn.execute("SELECT * FROM sensor_data WHERE sensor_id = ? "
                            "ORDER BY id DESC LIMIT 1", (sid,)).fetchone()
        recent = conn.execute("SELECT * FROM sensor_data WHERE sensor_id = ? "
                              "ORDER BY id DESC LIMIT 100", (sid,)).fetchall()
    finally:
        conn.close()

    paused = False
    if sensor["paused_until"]:
        try:
            paused = datetime.fromisoformat(sensor["paused_until"]) > datetime.now()
        except ValueError:
            pass
    status = "paused" if (paused or not sensor["enabled"]) else (
        last["status"] if last else "paused")

    body = render_template_string(
        SENSOR_DETAIL_HTML, sensor=sensor, device=device, group=group,
        last=last, recent=recent, status=status, url_for=url_for)
    return render_ctx(body, sensor["name"], "sensors")


@app.route("/api/sensor/<int:sid>/series")
@login_required
def api_series(sid):
    hours = int(request.args.get("hours", 24))
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    conn = db()
    try:
        rows = conn.execute(
            "SELECT timestamp, latency_ms FROM sensor_data "
            "WHERE sensor_id = ? AND timestamp >= ? ORDER BY timestamp",
            (sid, cutoff)).fetchall()
    finally:
        conn.close()

    step = max(1, len(rows) // MAX_POINTS_CHART) if rows else 1
    labels, values = [], []
    for i in range(0, len(rows), step):
        chunk = rows[i:i + step]
        vals = [r["latency_ms"] for r in chunk if r["latency_ms"] is not None]
        avg = sum(vals) / len(vals) if vals else None
        ts = chunk[0]["timestamp"]
        labels.append(ts[11:16] if isinstance(ts, str) else ts.strftime("%H:%M"))
        values.append(round(avg, 1) if avg is not None else None)
    return jsonify({"labels": labels, "values": values})


@app.route("/api/status")
@login_required
def api_status():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT s.id, s.name, s.sensor_type, d.name AS dname, d.host, "
            "(SELECT status FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS status, "
            "(SELECT latency_ms FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS latency_ms "
            "FROM sensors s JOIN devices d ON d.id = s.device_id "
            "WHERE s.enabled = 1").fetchall()
    finally:
        conn.close()
    return jsonify({
        "app": __app_name__, "version": __app_version__,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "sensors": [dict(r) for r in rows],
    })


@app.route("/health")
def health():
    try:
        conn = db()
        try:
            row = conn.execute("SELECT MAX(timestamp) AS latest FROM sensor_data").fetchone()
            total = conn.execute("SELECT COUNT(*) AS c FROM sensors WHERE enabled = 1").fetchone()["c"]
        finally:
            conn.close()
        latest = row["latest"] if row else None
        if latest and isinstance(latest, str):
            try:
                latest = datetime.strptime(latest, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                latest = None
        age = (datetime.now() - latest).total_seconds() if latest else 9999
        return jsonify({
            "status": "healthy" if age < 300 else "stale",
            "sensors_enabled": total,
            "last_data_seconds_ago": round(age, 1),
            "monitor_workers": MONITOR_WORKERS,
            "app": __app_name__, "version": __app_version__,
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/sensors/<int:sid>/delete", methods=["POST"])
@login_required
def sensor_delete(sid):
    conn = db()
    try:
        conn.execute("DELETE FROM sensors WHERE id = ?", (sid,))
        conn.commit()
    finally:
        conn.close()
    return _flash_redirect(url_for("sensors_page"), "Sensor deleted")


# ============================================================================
# ROUTES — DEVICES
# ============================================================================
DEVICES_HTML = """
<div class="toolbar"><h1 style="margin:0">Devices</h1>
<span class="spacer"></span>
<a class="btn" href="{{ url_for('device_new') }}">+ Add Device</a>
<a class="btn grey" href="{{ url_for('group_new') }}">+ Add Group</a>
<a class="btn grey" href="{{ url_for('snmp_creds_page') }}">SNMP Credentials</a></div>
<div class="card"><h2>Groups</h2>
{% if groups %}<table>
<tr><th>Name</th><th>Description</th><th>Devices</th><th></th></tr>
{% for g in groups %}<tr><td><b>{{ g.name }}</b></td>
<td>{{ g.description or '' }}</td><td>{{ g.device_count }}</td>
<td><form method="post" action="{{ url_for('group_delete', gid=g.id) }}"
style="display:inline" onsubmit="return confirm('Delete?')">
<button class="btn red small">Delete</button></form></td></tr>
{% endfor %}</table>{% else %}<p>No groups yet.</p>{% endif %}</div>
<div class="card"><h2>Devices</h2>
{% if devices %}<table>
<tr><th>Group</th><th>Name</th><th>Host</th><th>Role</th>
<th>Tags</th><th>Sensors</th><th></th></tr>
{% for d in devices %}<tr>
<td>{{ d.group_name or '—' }}</td><td><b>{{ d.name }}</b></td>
<td>{{ d.host }}</td><td>{{ d.device_role or '—' }}</td>
<td>{{ d.tags or '' }}</td><td>{{ d.sensor_count }}</td>
<td>
<a class="btn small" href="{{ url_for('device_interfaces', did=d.id) }}">Interfaces</a>
<a class="btn small grey" href="{{ url_for('device_edit', did=d.id) }}">Edit</a>
<form method="post" action="{{ url_for('device_delete', did=d.id) }}"
style="display:inline" onsubmit="return confirm('Delete?')">
<button class="btn red small">Del</button></form>
</td></tr>{% endfor %}</table>
{% else %}<p>No devices yet.</p>{% endif %}</div>
"""


@app.route("/devices")
@login_required
def devices():
    conn = db()
    try:
        groups = conn.execute(
            "SELECT g.*, (SELECT COUNT(*) FROM devices WHERE group_id = g.id) "
            "AS device_count FROM groups g ORDER BY g.name").fetchall()
        devs = conn.execute(
            "SELECT d.*, g.name AS group_name, "
            "(SELECT COUNT(*) FROM sensors WHERE device_id = d.id) AS sensor_count "
            "FROM devices d LEFT JOIN groups g ON g.id = d.group_id "
            "ORDER BY g.name, d.name").fetchall()
    finally:
        conn.close()
    body = render_template_string(DEVICES_HTML, groups=groups, devices=devs,
                                  url_for=url_for)
    return render_ctx(body, "Devices", "devices")


DEVICE_FORM_HTML = """
<h1>{{ 'Edit' if device else 'Add' }} Device</h1>
<form method="post"><div class="card">
<div class="row">
<div><label>Group</label>
<select name="group_id"><option value="">— none —</option>
{% for g in groups %}
<option value="{{ g.id }}" {{ 'selected' if device and device.group_id==g.id }}>{{ g.name }}</option>
{% endfor %}</select></div>
<div><label>Device name</label>
<input name="name" required value="{{ device.name if device else '' }}"></div>
</div>
<div class="row">
<div><label>Host / IP</label>
<input name="host" required value="{{ device.host if device else '' }}"
       placeholder="8.8.8.8 or hostname"></div>
<div><label>Device role</label>
<select name="device_role">
{% for r in ['', 'firewall', 'router', 'switch', 'server', 'ap'] %}
<option value="{{ r }}" {{ 'selected' if device and device.device_role==r }}>{{ r or '— none —' }}</option>
{% endfor %}</select></div>
<div><label>SNMP credentials</label>
<select name="snmp_cred_id"><option value="">— none —</option>
{% for c in snmp_creds %}
<option value="{{ c.id }}" {{ 'selected' if device and device.snmp_cred_id==c.id }}>{{ c.name }} (v{{ c.version }})</option>
{% endfor %}</select></div></div>
<div class="row">
<div><label>Tags</label>
<input name="tags" value="{{ device.tags if device else '' }}"></div></div>
<button class="btn" type="submit">Save</button>
<a class="btn grey" href="{{ url_for('devices') }}">Cancel</a>
</div></form>
"""


@app.route("/devices/new", methods=["GET", "POST"])
@login_required
def device_new():
    conn = db()
    try:
        groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
        creds = conn.execute("SELECT * FROM snmp_credentials ORDER BY name").fetchall()
        if request.method == "POST":
            now = datetime.now().isoformat(timespec="seconds")
            host = request.form["host"].strip()
            cur = conn.execute(
                "INSERT INTO devices "
                "(group_id, name, host, tags, snmp_cred_id, device_role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (request.form.get("group_id") or None,
                 request.form["name"].strip(), host,
                 request.form.get("tags", "").strip(),
                 request.form.get("snmp_cred_id") or None,
                 request.form.get("device_role") or None, now))
            did = cur.lastrowid
            conn.execute(
                "INSERT INTO sensors "
                "(device_id, name, sensor_type, params, interval_seconds, "
                "timeout_seconds, retries, enabled, warning_latency_ms, "
                "error_latency_ms, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (did, "Ping " + host, "ping", "{}",
                 DEFAULT_INTERVAL, DEFAULT_TIMEOUT, DEFAULT_RETRIES,
                 1, 100, 300, now))
            conn.commit()
            return _flash_redirect(url_for("devices"), "Device added")
        body = render_template_string(DEVICE_FORM_HTML, device=None,
                                      groups=groups, snmp_creds=creds,
                                      url_for=url_for)
        return render_ctx(body, "New device", "devices")
    finally:
        conn.close()


@app.route("/devices/<int:did>/edit", methods=["GET", "POST"])
@login_required
def device_edit(did):
    conn = db()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (did,)).fetchone()
        if not device:
            abort(404)
        if request.method == "POST":
            conn.execute(
                "UPDATE devices SET group_id = ?, name = ?, host = ?, tags = ?, "
                "snmp_cred_id = ?, device_role = ? WHERE id = ?",
                (request.form.get("group_id") or None,
                 request.form["name"].strip(),
                 request.form["host"].strip(),
                 request.form.get("tags", "").strip(),
                 request.form.get("snmp_cred_id") or None,
                 request.form.get("device_role") or None, did))
            conn.commit()
            return _flash_redirect(url_for("devices"), "Device updated")
        groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
        creds = conn.execute("SELECT * FROM snmp_credentials ORDER BY name").fetchall()
        body = render_template_string(DEVICE_FORM_HTML, device=device,
                                      groups=groups, snmp_creds=creds,
                                      url_for=url_for)
        return render_ctx(body, "Edit device", "devices")
    finally:
        conn.close()


@app.route("/devices/<int:did>/delete", methods=["POST"])
@login_required
def device_delete(did):
    conn = db()
    try:
        conn.execute("DELETE FROM devices WHERE id = ?", (did,))
        conn.commit()
    finally:
        conn.close()
    return _flash_redirect(url_for("devices"), "Device deleted")


GROUP_FORM_HTML = """
<h1>Add Group</h1>
<form method="post"><div class="card">
<div class="row">
<div><label>Name</label><input name="name" required></div>
<div><label>Description</label><input name="description"></div>
</div>
<button class="btn">Save</button>
<a class="btn grey" href="{{ url_for('devices') }}">Cancel</a>
</div></form>
"""


@app.route("/groups/new", methods=["GET", "POST"])
@login_required
def group_new():
    if request.method == "POST":
        conn = db()
        try:
            try:
                conn.execute(
                    "INSERT INTO groups (name, description, created_at) "
                    "VALUES (?, ?, ?)",
                    (request.form["name"].strip(),
                     request.form.get("description", "").strip(),
                     datetime.now().isoformat(timespec="seconds")))
                conn.commit()
            except Exception:
                flash("Group name already exists", "err")
                return redirect(url_for("group_new"))
        finally:
            conn.close()
        return _flash_redirect(url_for("devices"), "Group added")
    return render_ctx(GROUP_FORM_HTML, "New group", "devices")


@app.route("/groups/<int:gid>/delete", methods=["POST"])
@login_required
def group_delete(gid):
    conn = db()
    try:
        conn.execute("UPDATE devices SET group_id = NULL WHERE group_id = ?", (gid,))
        conn.execute("DELETE FROM groups WHERE id = ?", (gid,))
        conn.commit()
    finally:
        conn.close()
    return _flash_redirect(url_for("devices"), "Group deleted")


# ============================================================================
# ROUTES — SNMP CREDENTIALS
# ============================================================================
SNMP_CREDS_HTML = """
<div class="toolbar"><h1 style="margin:0">SNMP Credentials</h1>
<span class="spacer"></span>
<a class="btn" href="{{ url_for('snmp_creds_new') }}">+ Add Credential</a></div>
<div class="card">{% if rows %}<table>
<tr><th>Name</th><th>Version</th><th>Port</th><th>Devices</th><th></th></tr>
{% for r in rows %}<tr>
<td><b>{{ r.name }}</b></td><td>v{{ r.version }}</td>
<td>{{ r.port }}</td><td>{{ r.device_count }}</td>
<td><form method="post" action="{{ url_for('snmp_creds_delete', cid=r.id) }}"
style="display:inline" onsubmit="return confirm('Delete?')">
<button class="btn red small">Delete</button></form></td></tr>
{% endfor %}</table>
{% else %}<p>No credentials. <a href="{{ url_for('snmp_creds_new') }}">Add one</a>.</p>{% endif %}
<p style="color:#6c757d;font-size:12px;margin-top:12px">
SNMP v2c recommended. Allow monitor server IP on device.</p></div>
"""


@app.route("/snmp-credentials")
@login_required
def snmp_creds_page():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM devices WHERE snmp_cred_id = c.id) "
            "AS device_count FROM snmp_credentials c ORDER BY c.name").fetchall()
    finally:
        conn.close()
    body = render_template_string(SNMP_CREDS_HTML, rows=rows, url_for=url_for)
    return render_ctx(body, "SNMP Credentials", "devices")


SNMP_CRED_FORM_HTML = """
<h1>Add SNMP Credential</h1>
<form method="post"><div class="card">
<div class="row">
<div><label>Name</label><input name="name" required></div>
<div><label>Version</label>
<select name="version"><option value="2c">v2c</option>
<option value="1">v1</option></select></div>
<div><label>Port</label><input type="number" name="port" value="161"></div>
</div>
<div class="row">
<div style="flex:2"><label>Community</label>
<input name="community" required placeholder="public"></div>
</div>
<button class="btn">Save</button>
<a class="btn grey" href="{{ url_for('snmp_creds_page') }}">Cancel</a>
</div></form>
"""


@app.route("/snmp-credentials/new", methods=["GET", "POST"])
@login_required
def snmp_creds_new():
    if request.method == "POST":
        conn = db()
        try:
            try:
                conn.execute(
                    "INSERT INTO snmp_credentials "
                    "(name, version, community, port, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (request.form["name"].strip(),
                     request.form.get("version", "2c"),
                     request.form["community"].strip(),
                     int(request.form.get("port") or 161),
                     datetime.now().isoformat(timespec="seconds")))
                conn.commit()
            except Exception:
                flash("Credential name already exists", "err")
                return redirect(url_for("snmp_creds_new"))
        finally:
            conn.close()
        return _flash_redirect(url_for("snmp_creds_page"), "Credential added")
    return render_ctx(SNMP_CRED_FORM_HTML, "New SNMP credential", "devices")


@app.route("/snmp-credentials/<int:cid>/delete", methods=["POST"])
@login_required
def snmp_creds_delete(cid):
    conn = db()
    try:
        conn.execute("UPDATE devices SET snmp_cred_id = NULL WHERE snmp_cred_id = ?",
                     (cid,))
        conn.execute("DELETE FROM snmp_credentials WHERE id = ?", (cid,))
        conn.commit()
    finally:
        conn.close()
    return _flash_redirect(url_for("snmp_creds_page"), "Credential deleted")


# ============================================================================
# ROUTES — INTERFACES (with bulk import)
# ============================================================================
INTERFACES_HTML = """
<div class="toolbar">
<a class="btn grey" href="{{ url_for('devices') }}">← Devices</a>
<span class="spacer"></span>
<h1 style="margin:0">{{ dev.name }} — Interfaces</h1>
<span class="spacer"></span>
<a class="btn" href="{{ url_for('device_interfaces', did=dev.id) }}">↻ Refresh</a>
</div>

{% if not creds_ok %}
<div class="flash err">No SNMP credentials attached.
<a href="{{ url_for('device_edit', did=dev.id) }}">Attach credential</a> first.</div>
{% elif err %}
<div class="flash err">{{ err }}</div>
{% else %}

<div class="card"><div style="font-size:13px;color:#5b6b7b">
<b>Host:</b> {{ dev.host }} | <b>SysName:</b> {{ sysname or '—' }} |
<b>Interfaces:</b> {{ ifaces|length }}
</div></div>

{% if ifaces %}
<form method="post" action="{{ url_for('device_interface_bulk_add', did=dev.id) }}"
      id="bulkForm">
<div class="card" style="background:#f8f9fb;border-left:5px solid var(--primary)">
<h2 style="margin-top:0">⚡ Bulk Add Sensors</h2>
<p style="color:#6c757d;font-size:13px;margin-bottom:12px">
Select interfaces using checkboxes below, configure options, then click "Add Selected Sensors".
</p>
<div class="row">
<div><label>Sensor Types</label>
<label style="font-weight:600;margin-top:6px">
<input type="checkbox" name="bulk_create_traffic" value="1" checked>
Traffic (IN/OUT Mbps)
</label>
<label style="font-weight:600;margin-top:6px">
<input type="checkbox" name="bulk_create_status" value="1">
Status (up/down + errors)
</label></div>
<div><label>Warning threshold (Mbps)</label>
<input type="number" name="bulk_warn_mbps" value="800"
placeholder="80% of link speed"></div>
<div><label>Error threshold (Mbps)</label>
<input type="number" name="bulk_err_mbps" value="950"
placeholder="95% of link speed"></div>
<div><label>Interval (seconds)</label>
<input type="number" name="bulk_interval" value="60" min="15"></div>
</div>
<button class="btn green" type="submit"
        onclick="return confirm('Create sensors for all selected interfaces?')">
✓ Add Sensors for Selected Interfaces
</button>
</div>

<div class="card"><h2>Detected Interfaces ({{ ifaces|length }})</h2>
<table>
<tr>
<th style="width:40px">
<input type="checkbox" id="selectAll" onchange="toggleAll(this)">
</th>
<th>Idx</th><th>Name</th><th>Alias</th><th>Type</th>
<th>Oper</th><th>Speed</th><th>Individual Add</th>
</tr>
{% for i in ifaces %}
<tr>
<td>
<input type="checkbox" name="selected_if"
value="{{ i.if_index }}|{{ i.name or i.descr or ('if' + i.if_index) }}|{{ i.alias or '' }}"
class="if-checkbox">
</td>
<td>{{ i.if_index }}</td>
<td><b>{{ i.name or i.descr or '—' }}</b></td>
<td>{{ i.alias or '' }}</td>
<td>{{ i.if_type or '' }}</td>
<td>{% if i.oper_status == 'up' %}<span class="badge up">UP</span>
{% elif i.oper_status %}<span class="badge down">{{ i.oper_status }}</span>{% endif %}</td>
<td>{% if i.speed_mbps %}{{ i.speed_mbps }} Mbps{% else %}—{% endif %}</td>
<td>
<form method="post" action="{{ url_for('device_interface_add_sensor', did=dev.id) }}"
style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;margin:0">
<input type="hidden" name="if_index" value="{{ i.if_index }}">
<input type="hidden" name="if_name"
value="{{ i.name or i.descr or ('if' + i.if_index) }}">
<input type="hidden" name="if_alias" value="{{ i.alias or '' }}">
<label style="margin:0;font-size:11px">
<input type="checkbox" name="create_traffic" value="1" checked> T</label>
<label style="margin:0;font-size:11px">
<input type="checkbox" name="create_status" value="1"> S</label>
<input type="number" name="warn_mbps" placeholder="warn"
style="width:60px;font-size:11px;padding:3px 5px">
<input type="number" name="err_mbps" placeholder="err"
style="width:50px;font-size:11px;padding:3px 5px">
<input type="number" name="interval" value="60"
style="width:50px;font-size:11px;padding:3px 5px">
<button class="btn small green" style="padding:3px 8px;font-size:11px">Add</button>
</form>
</td>
</tr>
{% endfor %}
</table>
</div>
</form>

<script>
function toggleAll(cb){
  document.querySelectorAll('.if-checkbox').forEach(function(el){
    el.checked = cb.checked;
  });
}
</script>

{% else %}
<div class="card"><p>No interfaces detected. Check SNMP community / allow-list.</p></div>
{% endif %}
{% endif %}
"""


@app.route("/devices/<int:did>/interfaces")
@login_required
def device_interfaces(did):
    conn = db()
    try:
        dev = conn.execute(
            "SELECT d.*, c.community, c.version AS snmp_ver, c.port AS snmp_port "
            "FROM devices d "
            "LEFT JOIN snmp_credentials c ON c.id = d.snmp_cred_id "
            "WHERE d.id = ?", (did,)).fetchone()
        if not dev:
            abort(404)
    finally:
        conn.close()

    ifaces, sysname, sysdescr, err = [], "", "", None
    if dev["community"]:
        try:
            cli = _snmp_for(dev, timeout=4, retries=1)
            ifaces = discover_interfaces(cli, l3_only=False)
            sysname = cli.sysname()
            sysdescr = cli.sysdescr()
        except Exception as e:
            err = "SNMP discovery failed: " + str(e)

    body = render_template_string(
        INTERFACES_HTML, dev=dev, ifaces=ifaces, sysname=sysname,
        sysdescr=sysdescr, err=err, creds_ok=bool(dev["community"]),
        url_for=url_for)
    return render_ctx(body, "Interfaces — " + dev["name"], "devices")


@app.route("/devices/<int:did>/interfaces/add", methods=["POST"])
@login_required
def device_interface_add_sensor(did):
    try:
        if_index = int(request.form["if_index"])
    except (KeyError, ValueError):
        flash("Invalid interface", "err")
        return redirect(url_for("device_interfaces", did=did))

    if_name = (request.form.get("if_name") or ("if" + str(if_index))).strip()[:40]
    alias = (request.form.get("if_alias") or "").strip()[:60]
    want_traffic = request.form.get("create_traffic") == "1"
    want_status = request.form.get("create_status") == "1"

    try:
        warn_mbps = float(request.form["warn_mbps"]) \
            if request.form.get("warn_mbps") else None
    except ValueError:
        warn_mbps = None
    try:
        err_mbps = float(request.form["err_mbps"]) \
            if request.form.get("err_mbps") else None
    except ValueError:
        err_mbps = None
    try:
        interval = max(15, int(request.form.get("interval") or 60))
    except ValueError:
        interval = 60

    now = datetime.now().isoformat(timespec="seconds")
    conn = db()
    try:
        if want_traffic:
            conn.execute(
                "INSERT INTO sensors "
                "(device_id, name, sensor_type, params, interval_seconds, "
                "timeout_seconds, retries, enabled, warning_latency_ms, "
                "error_latency_ms, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (did, "Traffic " + if_name, "snmp_traffic",
                 json.dumps({"if_index": if_index, "if_name": if_name,
                             "if_alias": alias}),
                 interval, 5, 1, 1,
                 int(warn_mbps) if warn_mbps is not None else None,
                 int(err_mbps) if err_mbps is not None else None, now))
        if want_status:
            conn.execute(
                "INSERT INTO sensors "
                "(device_id, name, sensor_type, params, interval_seconds, "
                "timeout_seconds, retries, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (did, "Status " + if_name, "snmp_interface",
                 json.dumps({"if_index": if_index, "if_name": if_name}),
                 interval, 5, 1, 1, now))
        conn.commit()
    finally:
        conn.close()

    flash("Sensor(s) created", "ok")
    return redirect(url_for("device_interfaces", did=did))


@app.route("/devices/<int:did>/interfaces/bulk-add", methods=["POST"])
@login_required
def device_interface_bulk_add(did):
    selected = request.form.getlist("selected_if")
    if not selected:
        flash("No interfaces selected", "err")
        return redirect(url_for("device_interfaces", did=did))

    want_traffic = request.form.get("bulk_create_traffic") == "1"
    want_status = request.form.get("bulk_create_status") == "1"
    if not (want_traffic or want_status):
        flash("Select at least one sensor type", "err")
        return redirect(url_for("device_interfaces", did=did))

    try:
        warn_mbps = float(request.form["bulk_warn_mbps"]) \
            if request.form.get("bulk_warn_mbps") else None
    except ValueError:
        warn_mbps = None
    try:
        err_mbps = float(request.form["bulk_err_mbps"]) \
            if request.form.get("bulk_err_mbps") else None
    except ValueError:
        err_mbps = None
    try:
        interval = max(15, int(request.form.get("bulk_interval") or 60))
    except ValueError:
        interval = 60

    now = datetime.now().isoformat(timespec="seconds")
    created = 0
    conn = db()
    try:
        for entry in selected:
            parts = entry.split("|", 2)
            if len(parts) < 2:
                continue
            try:
                if_index = int(parts[0])
            except ValueError:
                continue
            if_name = parts[1][:40]
            alias = (parts[2] if len(parts) > 2 else "")[:60]

            def sensor_exists(stype):
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM sensors "
                    "WHERE device_id = ? AND sensor_type = ? AND params LIKE ?",
                    (did, stype, '%"if_index": ' + str(if_index) + '%'),
                ).fetchone()
                return row["c"] > 0

            if want_traffic and not sensor_exists("snmp_traffic"):
                conn.execute(
                    "INSERT INTO sensors "
                    "(device_id, name, sensor_type, params, interval_seconds, "
                    "timeout_seconds, retries, enabled, warning_latency_ms, "
                    "error_latency_ms, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (did, "Traffic " + if_name, "snmp_traffic",
                     json.dumps({"if_index": if_index, "if_name": if_name,
                                 "if_alias": alias}),
                     interval, 5, 1, 1,
                     int(warn_mbps) if warn_mbps is not None else None,
                     int(err_mbps) if err_mbps is not None else None, now))
                created += 1

            if want_status and not sensor_exists("snmp_interface"):
                conn.execute(
                    "INSERT INTO sensors "
                    "(device_id, name, sensor_type, params, interval_seconds, "
                    "timeout_seconds, retries, enabled, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (did, "Status " + if_name, "snmp_interface",
                     json.dumps({"if_index": if_index, "if_name": if_name}),
                     interval, 5, 1, 1, now))
                created += 1
        conn.commit()
    finally:
        conn.close()

    flash("%d sensor(s) created successfully" % created, "ok")
    return redirect(url_for("device_interfaces", did=did))


# ============================================================================
# ROUTES — TRAFFIC DASHBOARD
# ============================================================================
TRAFFIC_HTML = """
<div class="toolbar"><h1 style="margin:0">Traffic & Firewall Health</h1>
<span class="spacer"></span>
<a class="btn grey" href="{{ url_for('traffic_dashboard') }}">↻ Refresh</a></div>
{% if rows %}<div class="grid">
{% for r in rows %}
<a href="{{ url_for('sensor_detail', sid=r.id) }}"
   style="text-decoration:none;color:inherit">
<div class="sensor-card {{ r.status or 'paused' }}">
<h3>{{ r.name }}</h3>
<div class="meta">{{ r.gname or '—' }} / {{ r.dname }} ({{ r.host }})</div>
{% if r.sensor_type == 'snmp_traffic' %}
<div style="display:flex;gap:14px;font-weight:800">
<div><div style="font-size:10px;color:#5b6b7b">IN</div>
<div style="color:#0a66c2">
{{ '%.2f'|format(r.v_in) if r.v_in is not none else '—' }}
<span style="font-size:11px">Mbps</span></div></div>
<div><div style="font-size:10px;color:#5b6b7b">OUT</div>
<div style="color:#6f42c1">
{{ '%.2f'|format(r.v_out) if r.v_out is not none else '—' }}
<span style="font-size:11px">Mbps</span></div></div>
</div>
{% else %}
<div class="lat">
{% if r.value1 is not none %}{{ '%.0f'|format(r.value1) }}{% else %}—{% endif %}
</div>
{% endif %}
<div class="msg">{{ r.msg or '' }}</div>
<div style="font-size:10px;color:#adb5bd;margin-top:6px">{{ r.ts or '' }}</div>
</div></a>
{% endfor %}</div>
{% else %}
<div class="card">No traffic sensors. <a href="{{ url_for('devices') }}">Devices</a>
→ Interfaces → Add monitoring.</div>
{% endif %}
"""


@app.route("/traffic")
@login_required
def traffic_dashboard():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT s.id, s.name, s.sensor_type, s.params, "
            "d.name AS dname, d.host, g.name AS gname, "
            "(SELECT status FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS status, "
            "(SELECT latency_ms FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS value1, "
            "(SELECT value_in FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS v_in, "
            "(SELECT value_out FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS v_out, "
            "(SELECT message FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS msg, "
            "(SELECT timestamp FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS ts "
            "FROM sensors s "
            "JOIN devices d ON d.id = s.device_id "
            "LEFT JOIN groups g ON g.id = d.group_id "
            "WHERE s.sensor_type IN "
            "('snmp_traffic', 'snmp_interface', 'firewall_health') "
            "ORDER BY g.name, d.name, s.name").fetchall()
    finally:
        conn.close()
    body = render_template_string(TRAFFIC_HTML, rows=rows, url_for=url_for)
    return render_ctx(body, "Traffic", "traffic")


# ============================================================================
# ROUTES — SENSORS LIST
# ============================================================================
SENSORS_HTML = """
<div class="toolbar"><h1 style="margin:0">Sensors</h1>
<span class="spacer"></span>
<a class="btn green" href="{{ url_for('sensor_new') }}">+ Add Sensor</a></div>
<div class="card">{% if sensors %}<table>
<tr><th>Sensor</th><th>Type</th><th>Device</th><th>Interval</th>
<th>Enabled</th><th>Warn/Err</th><th></th></tr>
{% for s in sensors %}<tr>
<td><a href="{{ url_for('sensor_detail', sid=s.id) }}"><b>{{ s.name }}</b></a></td>
<td>{{ s.sensor_type }}</td>
<td>{{ s.device_name }} <span style="color:#889">{{ s.host }}</span></td>
<td>{{ s.interval_seconds }}s</td>
<td>{{ '✔' if s.enabled else '✘' }}</td>
<td>{{ s.warning_latency_ms or '-' }} / {{ s.error_latency_ms or '-' }}</td>
<td><a class="btn small grey" href="{{ url_for('sensor_edit', sid=s.id) }}">Edit</a>
<form method="post" action="{{ url_for('sensor_delete', sid=s.id) }}"
style="display:inline" onsubmit="return confirm('Delete?')">
<button class="btn red small">Del</button></form></td></tr>
{% endfor %}</table>
{% else %}<p>No sensors. <a href="{{ url_for('sensor_new') }}">Add one</a>.</p>{% endif %}
</div>
"""


@app.route("/sensors")
@login_required
def sensors_page():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT s.*, d.name AS device_name, d.host FROM sensors s "
            "JOIN devices d ON d.id = s.device_id ORDER BY d.name, s.name"
        ).fetchall()
    finally:
        conn.close()
    body = render_template_string(SENSORS_HTML, sensors=rows, url_for=url_for)
    return render_ctx(body, "Sensors", "sensors")


SENSOR_FORM_HTML = """
<h1>{{ 'Edit' if sensor else 'Add' }} Sensor</h1>
<form method="post"><div class="card">
<div class="row">
<div><label>Device</label>
<select name="device_id" required><option value="">— select —</option>
{% for d in devices %}
<option value="{{ d.id }}" {{ 'selected' if sensor and sensor.device_id==d.id }}>{{ d.name }} ({{ d.host }})</option>
{% endfor %}</select></div>
<div><label>Sensor name</label>
<input name="name" required value="{{ sensor.name if sensor else '' }}"></div>
<div><label>Type</label>
<select name="sensor_type" id="stype" onchange="updateTypeFields()">
{% for t in ['ping','tcp','http','https','dns','snmp_traffic','snmp_interface','firewall_health'] %}
<option value="{{ t }}" {{ 'selected' if sensor and sensor.sensor_type==t }}>{{ t }}</option>
{% endfor %}</select></div></div>
<div class="row" id="typeRow">
<div id="portField" style="display:none"><label>TCP Port</label>
<input name="port" id="port" value="{{ params.port if params and params.port else 80 }}"></div>
<div id="urlField" style="display:none;flex:2"><label>URL</label>
<input name="url" id="url" value="{{ params.url if params and params.url else '' }}"
placeholder="https://example.com/health"></div>
<div id="ifField" style="display:none;flex:2"><label>Interface Index</label>
<input name="if_index" id="if_index"
value="{{ params.if_index if params and params.if_index else '' }}"></div>
<div id="vendorField" style="display:none"><label>Vendor</label>
<select name="vendor" id="vendor">
{% for v in ['fortinet','paloalto','cisco_asa','pfsense','sophos'] %}
<option value="{{ v }}" {{ 'selected' if params and params.vendor==v }}>{{ v }}</option>
{% endfor %}</select></div></div>
<div class="row">
<div><label>Interval (s)</label>
<input type="number" name="interval_seconds" min="5"
value="{{ sensor.interval_seconds if sensor else 60 }}"></div>
<div><label>Timeout (s)</label>
<input type="number" name="timeout_seconds" min="1"
value="{{ sensor.timeout_seconds if sensor else 5 }}"></div>
<div><label>Retries</label>
<input type="number" name="retries" min="0"
value="{{ sensor.retries if sensor else 2 }}"></div></div>
<div class="row">
<div><label>Warning threshold</label>
<input type="number" name="warning_latency_ms"
value="{{ sensor.warning_latency_ms if sensor and sensor.warning_latency_ms is not none else 100 }}"></div>
<div><label>Error threshold</label>
<input type="number" name="error_latency_ms"
value="{{ sensor.error_latency_ms if sensor and sensor.error_latency_ms is not none else 300 }}"></div>
<div><label>&nbsp;</label>
<label style="font-weight:600">
<input type="checkbox" name="enabled" value="1"
{{ 'checked' if (not sensor) or sensor.enabled }}> Enabled</label></div></div>
<button class="btn">Save</button>
<a class="btn grey" href="{{ url_for('sensors_page') }}">Cancel</a>
</div></form>
<script>
function updateTypeFields(){
  const t=document.getElementById('stype').value;
  document.getElementById('portField').style.display=(t==='tcp')?'block':'none';
  document.getElementById('urlField').style.display=(t==='http'||t==='https')?'block':'none';
  document.getElementById('ifField').style.display=(t==='snmp_traffic'||t==='snmp_interface')?'block':'none';
  document.getElementById('vendorField').style.display=(t==='firewall_health')?'block':'none';
}
updateTypeFields();
</script>
"""


def _parse_sensor_form():
    st = request.form["sensor_type"]
    params = {}
    if st == "tcp":
        try:
            params["port"] = int(request.form.get("port") or 80)
        except ValueError:
            params["port"] = 80
    if st in ("http", "https"):
        u = request.form.get("url", "").strip()
        if u:
            params["url"] = u
    if st in ("snmp_traffic", "snmp_interface"):
        try:
            params["if_index"] = int(request.form.get("if_index") or 0)
        except ValueError:
            params["if_index"] = 0
    if st == "firewall_health":
        params["vendor"] = request.form.get("vendor", "fortinet")

    def num(name):
        v = request.form.get(name, "").strip()
        try:
            return int(v) if v else None
        except ValueError:
            return None

    try:
        interval = max(5, int(request.form.get("interval_seconds") or 60))
    except ValueError:
        interval = 60
    try:
        timeout = max(1, int(request.form.get("timeout_seconds") or 5))
    except ValueError:
        timeout = 5
    try:
        retries = max(0, int(request.form.get("retries") or 0))
    except ValueError:
        retries = 0

    return {
        "name": request.form["name"].strip(),
        "sensor_type": st,
        "params": json.dumps(params),
        "interval_seconds": interval,
        "timeout_seconds": timeout,
        "retries": retries,
        "warning_latency_ms": num("warning_latency_ms"),
        "error_latency_ms": num("error_latency_ms"),
        "enabled": 1 if request.form.get("enabled") else 0,
        "device_id": int(request.form["device_id"]),
    }


@app.route("/sensors/new", methods=["GET", "POST"])
@login_required
def sensor_new():
    conn = db()
    try:
        devs = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
        if request.method == "POST":
            d = _parse_sensor_form()
            conn.execute(
                "INSERT INTO sensors "
                "(device_id, name, sensor_type, params, interval_seconds, "
                "timeout_seconds, retries, enabled, warning_latency_ms, "
                "error_latency_ms, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (d["device_id"], d["name"], d["sensor_type"], d["params"],
                 d["interval_seconds"], d["timeout_seconds"], d["retries"],
                 d["enabled"], d["warning_latency_ms"], d["error_latency_ms"],
                 datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            return _flash_redirect(url_for("sensors_page"), "Sensor created")
        body = render_template_string(SENSOR_FORM_HTML, sensor=None,
                                      devices=devs, params={}, url_for=url_for)
        return render_ctx(body, "New sensor", "sensors")
    finally:
        conn.close()


@app.route("/sensors/<int:sid>/edit", methods=["GET", "POST"])
@login_required
def sensor_edit(sid):
    conn = db()
    try:
        sensor = conn.execute("SELECT * FROM sensors WHERE id = ?", (sid,)).fetchone()
        if not sensor:
            abort(404)
        if request.method == "POST":
            d = _parse_sensor_form()
            conn.execute(
                "UPDATE sensors SET device_id = ?, name = ?, sensor_type = ?, "
                "params = ?, interval_seconds = ?, timeout_seconds = ?, "
                "retries = ?, enabled = ?, warning_latency_ms = ?, "
                "error_latency_ms = ? WHERE id = ?",
                (d["device_id"], d["name"], d["sensor_type"], d["params"],
                 d["interval_seconds"], d["timeout_seconds"], d["retries"],
                 d["enabled"], d["warning_latency_ms"], d["error_latency_ms"], sid))
            conn.commit()
            return _flash_redirect(url_for("sensor_detail", sid=sid), "Sensor updated")
        devs = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
        body = render_template_string(SENSOR_FORM_HTML, sensor=sensor,
                                      devices=devs,
                                      params=json.loads(sensor["params"] or "{}"),
                                      url_for=url_for)
        return render_ctx(body, "Edit sensor", "sensors")
    finally:
        conn.close()


# ============================================================================
# ROUTES — ALERTS
# ============================================================================
ALERTS_HTML = """
<div class="toolbar"><h1 style="margin:0">Alert Rules</h1>
<span class="spacer"></span>
<a class="btn" href="{{ url_for('alert_new') }}">+ Add Rule</a></div>
<div class="card">{% if rules %}<table>
<tr><th>Sensor</th><th>Condition</th><th>Threshold</th>
<th>Email</th><th>Webhook</th><th>Cooldown</th><th></th></tr>
{% for r in rules %}<tr>
<td>{{ r.sensor_name or 'All sensors' }}</td>
<td>{{ r.condition }}</td>
<td>{{ r.threshold if r.threshold is not none else '-' }}</td>
<td>{{ '✔' if r.notify_email else '—' }}</td>
<td>{{ '✔' if r.notify_webhook else '—' }}</td>
<td>{{ r.cooldown_minutes }}m</td>
<td><form method="post" action="{{ url_for('alert_delete', rid=r.id) }}"
style="display:inline" onsubmit="return confirm('Delete?')">
<button class="btn red small">Del</button></form></td></tr>
{% endfor %}</table>
{% else %}<p>No rules yet.</p>{% endif %}</div>
"""


@app.route("/alerts")
@login_required
def alerts_page():
    conn = db()
    try:
        rules = conn.execute(
            "SELECT r.*, s.name AS sensor_name FROM alert_rules r "
            "LEFT JOIN sensors s ON s.id = r.sensor_id ORDER BY r.id DESC"
        ).fetchall()
    finally:
        conn.close()
    body = render_template_string(ALERTS_HTML, rules=rules, url_for=url_for)
    return render_ctx(body, "Alerts", "alerts")


ALERT_FORM_HTML = """
<h1>Add Alert Rule</h1>
<form method="post"><div class="card">
<div class="row">
<div><label>Sensor (blank = ALL)</label>
<select name="sensor_id"><option value="">All sensors</option>
{% for s in sensors %}
<option value="{{ s.id }}">{{ s.device_name }} / {{ s.name }}</option>
{% endfor %}</select></div>
<div><label>Condition</label>
<select name="condition">
<option value="down">DOWN</option>
<option value="up">Recovery (UP after down/warn)</option>
<option value="warning">WARNING</option>
<option value="latency_gt">Latency greater than</option>
</select></div>
<div><label>Threshold</label>
<input type="number" step="0.1" name="threshold"></div></div>
<div class="row">
<div><label>Cooldown (min)</label>
<input type="number" name="cooldown_minutes" value="15"></div>
<div><label>&nbsp;</label><label style="font-weight:600">
<input type="checkbox" name="notify_email" value="1" checked> Email</label></div>
<div><label>&nbsp;</label><label style="font-weight:600">
<input type="checkbox" name="notify_webhook" value="1"> Webhook</label></div></div>
<div class="row">
<div style="flex:2"><label>Webhook URL</label>
<input name="webhook_url" placeholder="https://hooks.slack.com/..."></div>
<div><label>&nbsp;</label><label style="font-weight:600">
<input type="checkbox" name="enabled" value="1" checked> Enabled</label></div></div>
<button class="btn">Save</button>
<a class="btn grey" href="{{ url_for('alerts_page') }}">Cancel</a>
</div></form>
"""


@app.route("/alerts/new", methods=["GET", "POST"])
@login_required
def alert_new():
    conn = db()
    try:
        if request.method == "POST":
            sid = request.form.get("sensor_id") or None
            th = None
            if request.form["condition"] == "latency_gt":
                try:
                    th = float(request.form.get("threshold") or 0)
                except ValueError:
                    th = None
            conn.execute(
                "INSERT INTO alert_rules "
                "(sensor_id, condition, threshold, notify_email, "
                "notify_webhook, webhook_url, cooldown_minutes, enabled, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (sid, request.form["condition"], th,
                 1 if request.form.get("notify_email") else 0,
                 1 if request.form.get("notify_webhook") else 0,
                 request.form.get("webhook_url", "").strip() or None,
                 int(request.form.get("cooldown_minutes") or 15),
                 1 if request.form.get("enabled") else 0,
                 datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            return _flash_redirect(url_for("alerts_page"), "Rule created")
        sensors = conn.execute(
            "SELECT s.id, s.name, d.name AS device_name FROM sensors s "
            "JOIN devices d ON d.id = s.device_id ORDER BY d.name, s.name"
        ).fetchall()
        body = render_template_string(ALERT_FORM_HTML, sensors=sensors,
                                      url_for=url_for)
        return render_ctx(body, "New alert", "alerts")
    finally:
        conn.close()


@app.route("/alerts/<int:rid>/delete", methods=["POST"])
@login_required
def alert_delete(rid):
    conn = db()
    try:
        conn.execute("DELETE FROM alert_rules WHERE id = ?", (rid,))
        conn.commit()
    finally:
        conn.close()
    return _flash_redirect(url_for("alerts_page"), "Rule deleted")


NOTIFICATIONS_HTML = """
<h1>Notification Log</h1>
<div class="card">
{% if rows %}<table>
<tr><th>Time</th><th>Sensor</th><th>Subject</th><th>Status</th></tr>
{% for n in rows %}<tr>
<td>{{ n.timestamp }}</td><td>{{ n.sensor_name or '-' }}</td>
<td>{{ n.subject }}</td><td>{{ n.status }}</td></tr>{% endfor %}</table>
{% else %}<p>No notifications yet.</p>{% endif %}
</div>
"""


@app.route("/notifications")
@login_required
def notifications_page():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT n.*, s.name AS sensor_name FROM notifications n "
            "LEFT JOIN sensors s ON s.id = n.sensor_id "
            "ORDER BY n.id DESC LIMIT 500").fetchall()
    finally:
        conn.close()
    body = render_template_string(NOTIFICATIONS_HTML, rows=rows, url_for=url_for)
    return render_ctx(body, "Notifications", "notif")


# ============================================================================
# ROUTES — SETTINGS
# ============================================================================
SETTINGS_HTML = """
<h1>Settings</h1>
<div class="card"><h2>Email / SMTP</h2>
<form method="post">
<div class="row">
<div><label>SMTP host</label>
<input name="smtp_host" value="{{ s.smtp_host }}"></div>
<div><label>SMTP port</label>
<input name="smtp_port" value="{{ s.smtp_port }}"></div>
<div><label>Security</label>
<select name="smtp_security">
{% for v in ['starttls','ssl','plain'] %}
<option value="{{ v }}" {{ 'selected' if s.smtp_security==v }}>{{ v }}</option>
{% endfor %}</select></div></div>
<div class="row">
<div><label>Sender address</label>
<input name="smtp_sender" value="{{ s.smtp_sender }}"></div>
<div><label>Password / App password</label>
<input name="smtp_password" type="password" value="{{ s.smtp_password }}"></div>
</div>
<div class="row">
<div style="flex:2"><label>Recipients (comma-separated)</label>
<input name="smtp_recipients" value="{{ s.smtp_recipients }}"></div>
<div><label>&nbsp;</label><label style="font-weight:600">
<input type="checkbox" name="email_enabled" value="1"
{{ 'checked' if s.email_enabled == '1' }}> Email alerts enabled</label></div></div>
<button class="btn">Save</button>
<button class="btn grey" type="submit" name="action" value="test"
formnovalidate>Save &amp; Send Test Email</button>
</form>
<p style="color:#6c757d;font-size:12px;margin-top:14px">
Gmail: use App Password (regular password won't work).</p>
</div>
<div class="card"><h2>Change Password</h2>
<form method="post" action="{{ url_for('change_password') }}">
<div class="row">
<div><label>Current</label>
<input name="old_password" type="password" required></div>
<div><label>New</label>
<input name="new_password" type="password" required></div>
<div><label>Confirm</label>
<input name="confirm_password" type="password" required></div></div>
<button class="btn">Change Password</button>
</form></div>
<div class="card"><h2>About</h2><table>
<tr><td>Application</td><td><b>{{ app_name }}</b></td></tr>
<tr><td>Version</td><td>{{ version }}</td></tr>
<tr><td>Database</td><td>{{ db_backend }}</td></tr>
<tr><td>Author</td><td>{{ author }}</td></tr>
<tr><td>Contact</td><td>{{ contact }}</td></tr>
</table></div>
"""


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_page():
    if request.method == "POST":
        for k in ["smtp_host", "smtp_port", "smtp_security", "smtp_sender",
                  "smtp_password", "smtp_recipients"]:
            set_setting(k, request.form.get(k, ""))
        set_setting("email_enabled",
                    "1" if request.form.get("email_enabled") else "0")
        if request.form.get("action") == "test":
            try:
                send_alert_email(
                    "[TEST] " + __app_name__ + " v" + __app_version__,
                    "This is a test alert email.\n\n"
                    "If you received this, SMTP is configured correctly.\n\n"
                    "— " + __app_name__ + " v" + __app_version__ + "\n"
                    + __contact__)
                flash("Test email sent successfully", "ok")
            except Exception as e:
                flash("Test email failed: " + str(e), "err")
        else:
            flash("Settings saved", "ok")
        return redirect(url_for("settings_page"))

    s = {k: get_setting(k, "") for k in
         ["smtp_host", "smtp_port", "smtp_security", "smtp_sender",
          "smtp_password", "smtp_recipients", "email_enabled"]}
    body = render_template_string(
        SETTINGS_HTML, s=s, url_for=url_for,
        app_name=__app_name__, version=__app_version__,
        author=__author__, contact=__contact__,
        db_backend=DB_BACKEND.upper())
    return render_ctx(body, "Settings", "settings")


@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    old = request.form["old_password"]
    new = request.form["new_password"]
    conf = request.form["confirm_password"]
    if new != conf:
        return _flash_redirect(url_for("settings_page"), "Passwords don't match", "err")
    if len(new) < 6:
        return _flash_redirect(url_for("settings_page"), "Min 6 characters", "err")
    conn = db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                           (session["user"],)).fetchone()
        if not row or not check_password_hash(row["password_hash"], old):
            return _flash_redirect(url_for("settings_page"),
                                   "Current password wrong", "err")
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(new), row["id"]))
        conn.commit()
    finally:
        conn.close()
    return _flash_redirect(url_for("settings_page"), "Password updated", "ok")


# ============================================================================
# ROUTES — PDF REPORT
# ============================================================================
@app.route("/report.pdf")
@login_required
def report_pdf():
    conn = db()
    try:
        rows = conn.execute(
            "SELECT s.*, d.name AS dname, d.host, g.name AS gname, "
            "(SELECT status FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS status, "
            "(SELECT latency_ms FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS latency_ms, "
            "(SELECT message FROM sensor_data WHERE sensor_id = s.id "
            " ORDER BY id DESC LIMIT 1) AS message "
            "FROM sensors s JOIN devices d ON d.id = s.device_id "
            "LEFT JOIN groups g ON g.id = d.group_id "
            "ORDER BY g.name, d.name, s.name").fetchall()
    finally:
        conn.close()

    scan_time = datetime.now()
    up = sum(1 for r in rows if r["status"] == "up")
    warn = sum(1 for r in rows if r["status"] == "warning")
    down = sum(1 for r in rows if r["status"] == "down")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        rightMargin=12 * mm, leftMargin=12 * mm,
        topMargin=12 * mm, bottomMargin=15 * mm,
        title=__app_name__ + " Report", author=__author__)
    styles = getSampleStyleSheet()

    header_parts = []
    if LOGO_FILE.exists():
        try:
            header_parts.append(RLImage(str(LOGO_FILE), width=55 * mm, height=18 * mm))
        except Exception:
            pass
    header_parts.append(Paragraph("iTechkey NetPulse — Network Report", styles["Title"]))
    ht = Table([header_parts], colWidths=[60 * mm, None])
    ht.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    story = [
        ht, Spacer(1, 3 * mm),
        Paragraph("Generated: %s" % scan_time.strftime("%d %B %Y, %I:%M:%S %p"),
                  styles["Normal"]),
        Spacer(1, 3 * mm),
        Paragraph("Total: %d &nbsp;&nbsp; UP: %d &nbsp;&nbsp; WARN: %d "
                  "&nbsp;&nbsp; DOWN: %d" % (len(rows), up, warn, down),
                  styles["Heading2"]),
        Spacer(1, 3 * mm),
    ]

    data = [["#", "Group", "Device", "Host", "Sensor", "Type",
             "Status", "Latency", "Message"]]
    for i, r in enumerate(rows, 1):
        lat = ("%.0f ms" % r["latency_ms"]) if r["latency_ms"] is not None else "-"
        data.append([i, r["gname"] or "-", r["dname"], r["host"], r["name"],
                     r["sensor_type"], (r["status"] or "unknown").upper(),
                     lat, (r["message"] or "")[:60]])

    table = Table(data, repeatRows=1,
                  colWidths=[10 * mm, 30 * mm, 40 * mm, 40 * mm, 45 * mm, 18 * mm,
                             20 * mm, 22 * mm, 55 * mm])
    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1c2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#a0aab5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f1f5f9")]),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, r in enumerate(rows, 1):
        st = (r["status"] or "").lower()
        color_hex = {"up": "#16a34a", "warning": "#b48200", "down": "#dc2626"} \
            .get(st, "#333333")
        tbl_style.append(("TEXTCOLOR", (6, i), (6, i), colors.HexColor(color_hex)))
        tbl_style.append(("FONTNAME", (6, i), (6, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(tbl_style))
    story.append(table)

    def footer(canvas, docu):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6c757d"))
        if LOGO_FILE.exists():
            try:
                canvas.drawImage(str(LOGO_FILE), 12 * mm, 9 * mm,
                                 width=22 * mm, height=7 * mm,
                                 preserveAspectRatio=True, mask="auto")
            except Exception:
                pass
        canvas.drawString(38 * mm, 8 * mm, __app_name__ + " v" + __app_version__)
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 8 * mm,
                               "Page %d" % docu.page)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    filename = "itechkey-report-%s.pdf" % scan_time.strftime("%Y%m%d-%H%M%S")
    return send_file(buffer, mimetype="application/pdf",
                     as_attachment=True, download_name=filename)


# ============================================================================
# STARTUP
# ============================================================================
def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "YOUR-IP"
    finally:
        s.close()


def print_banner():
    ip = get_lan_ip()
    print("=" * 66)
    print(" %s  v%s" % (__app_name__, __app_version__))
    print(" Real-time ping · SNMP · Firewall & L3 traffic")
    print("=" * 66)
    print("  Backend     : %s" % DB_BACKEND.upper())
    print("  Local URL   : http://127.0.0.1:5000")
    print("  Network URL : http://%s:5000" % ip)
    print("  Login       : admin / admin  (change immediately!)")
    print("  Workers     : %d parallel pollers" % MONITOR_WORKERS)
    print("  Author      : %s · %s" % (__author__, __contact__))
    print("=" * 66)
    print("  Press Ctrl+C to stop.")
    print("=" * 66, flush=True)


if __name__ == "__main__":
    if not _ENV_FILE.exists():
        print("=" * 66)
        print("  ⚠  First-time setup required!")
        print("  ⚠  Please run:  python itechkey_setup.py")
        print("=" * 66)
        sys.exit(1)
    try:
        init_db()
    except Exception as e:
        print("  ✗ DB init failed: " + str(e))
        print("  → Re-run: python itechkey_setup.py")
        sys.exit(1)
    start_monitor()
    print_banner()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)