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
#    http://localhost
#    Login: admin / admin   ← CHANGE IMMEDIATELY
```

The app listens on standard HTTP port **80**. To enable HTTPS on port **443**, set both certificate paths in `.env` before starting the app:

```env
ITECHKEY_HTTP_PORT=80
ITECHKEY_HTTPS_PORT=443
ITECHKEY_SSL_CERT=/path/to/fullchain.pem
ITECHKEY_SSL_KEY=/path/to/private-key.pem
```

Use a valid certificate for your hostname and protect the private key. HTTP requests are redirected to HTTPS when TLS is enabled. Without certificate paths, the app serves HTTP only. Ports 80/443 may require administrator/root privileges and must be allowed through the host/network firewall.

## Architecture (1000+ sensors)

- **MySQL 8** with InnoDB (or SQLite for small setups)
- **Thread pool**: 20 parallel monitor workers
- **Batch inserts**: flush every 5s (500 rows max)
- **Connection pool**: 30 connections (DBUtils)
- **Monthly partitions**: easy retention (drop partition, no lock)
- **Materialized status cache**: fast dashboard for 1000+ sensors
- **Gunicorn**: 4 workers × 8 threads for web UI

## WAN, Switch-Port & Storage Monitoring

- On a router/firewall or switch, open **Devices → Interfaces** and add traffic sensors to the WAN interface and switch ports. The collector reports inbound/outbound Mbps; link utilization is shown when capacity is available from interface discovery. For an internet service, edit the sensor and set **Link capacity (Mbps)** to the subscribed WAN bandwidth if it differs from the interface speed.
- Open **Devices → Storage** to discover fixed-disk volumes exposed through HOST-RESOURCES-MIB, select volumes, and set warning/critical utilization limits. Results include used/total capacity and volume availability.
- The Traffic view refreshes live readings automatically every 10 seconds; collection speed is controlled by each sensor's polling interval.
- Generic SNMP can report logical volume use and availability, but cannot reliably report physical-disk SMART/RAID health across vendors. Hardware health requires vendor-specific MIBs or a host agent; this is not a claim of full PRTG feature parity.

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
gunicorn -w 4 --threads 8 -b 127.0.0.1:5000 --timeout 120 itechkey_monitor:app
```

When using Gunicorn, keep its backend bound to localhost (for example, `127.0.0.1:5000`) and configure a production reverse proxy such as Nginx, Caddy, Apache, or IIS to handle public ports 80/443 and TLS. Gunicorn does not use the direct-launch HTTP/HTTPS listener configuration above. Run exactly one collector process alongside the web workers:

```bash
python itechkey_collector.py
```

The collector is a separate process so multiple Gunicorn workers do not poll the same sensors repeatedly. Run it under your service manager and keep only one active collector per database.

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
ExecStart=/opt/itechkey-monitor/venv/bin/gunicorn -w 4 --threads 8 -b 127.0.0.1:5000 itechkey_monitor:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Create a second systemd service for the collector, using the same user, working directory, virtual environment, and environment file:

```ini
[Unit]
Description=iTechkey NetPulse Sensor Collector
After=network.target mysql.service

[Service]
User=monitor
WorkingDirectory=/opt/itechkey-monitor
EnvironmentFile=/opt/itechkey-monitor/.env
ExecStart=/opt/itechkey-monitor/venv/bin/python itechkey_collector.py
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
ITECHKEY_HTTP_PORT=80
ITECHKEY_HTTPS_PORT=443
# Configure both values to enable HTTPS; omit them for HTTP-only mode.
ITECHKEY_SSL_CERT=/path/to/fullchain.pem
ITECHKEY_SSL_KEY=/path/to/private-key.pem
```

## License

Proprietary — © iTechkey. All rights reserved.