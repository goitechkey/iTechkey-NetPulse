# iTechkey NetPulse

**Version:** 1.0.0 · **Author:** iTechkey · **Contact:** admin@itechkey.com

Real-time ping, SNMP, firewall health and L3 port traffic monitoring.
Built for **1000+ sensors** with MySQL + thread-pool architecture.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Place your logo
#    Put logo.png at:  static/itechkey-logo.png

# 3. Run setup wizard (ONE TIME)
python itechkey_setup.py
#    → auto-detects MySQL, creates DB, tables, partitions
#    → or falls back to SQLite if MySQL unavailable

# 4. Start the monitor
python itechkey_monitor.py

# 5. Open browser
#    http://localhost:5000
#    Login: admin / admin   ← CHANGE IMMEDIATELY
```

## Architecture (1000+ sensors)

- **MySQL 8** with InnoDB (or SQLite for small setups)
- **Thread pool**: 20 parallel monitor workers
- **Batch inserts**: flush every 5s (500 rows max)
- **Connection pool**: 30 connections (DBUtils)
- **Monthly partitions**: easy retention (drop partition, no lock)
- **Materialized status cache**: fast dashboard for 1000+ sensors
- **Gunicorn**: 4 workers × 8 threads for web UI

## First-Time Configuration

1. Change password — **Settings → Change Password**
2. Configure SMTP — **Settings** (Gmail App Password recommended)
3. Add SNMP credential — **SNMP Credentials → + Add**
4. Add device — **Devices → + Add Device** (attach SNMP credential)
5. Discover interfaces — **Devices → Interfaces button**
6. Create traffic sensors — pick interfaces, add Traffic + Status sensors
7. Set alert rules — **Alerts → + Add Rule**

## SNMP Setup on Devices

### FortiGate
```
config system snmp community
  edit 1
    set name "public"
    config hosts
      edit 1
        set ip <monitor-ip> 255.255.255.255
      next
    end
  next
end
```

### Cisco IOS
```
snmp-server community public RO <acl>
```

### pfSense
Services → SNMP → Enable, community `public`.

## Production Deployment

### Gunicorn (Linux)
```bash
export $(cat .env | xargs)
gunicorn -w 4 --threads 8 -b 0.0.0.0:5000 --timeout 120 itechkey_monitor:app
```

### systemd service
```ini
[Unit]
Description=iTechkey NetPulse
After=network.target mysql.service
Requires=mysql.service

[Service]
User=monitor
WorkingDirectory=/opt/itechkey-monitor
EnvironmentFile=/opt/itechkey-monitor/.env
ExecStart=/opt/itechkey-monitor/venv/bin/gunicorn -w 4 --threads 8 -b 0.0.0.0:5000 itechkey_monitor:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Health check endpoint
```
GET /health  → {status, sensors_enabled, last_data_seconds_ago}
```

## Retention & Partitions

- **Auto-partition**: monthly partitions for `sensor_data`
- **Retention**: 6 months (configurable)
- **Cleanup**: partition drop (instant) — no DELETE locks

## Environment Variables (.env — auto-generated)

```env
ITECHKEY_DB=mysql                    # mysql | sqlite
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=itechkey
MYSQL_PASSWORD=<generated>
MYSQL_DB=itechkey_monitor
MONITOR_WORKERS=20
```

## License

Proprietary — © iTechkey. All rights reserved.