import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import itechkey_monitor as monitor
from itechkey_ssh import (
    SSHError,
    SSH_PROFILE_REGISTRY,
    register_ssh_profile,
    parse_cisco_interface_details,
    parse_cisco_interface_status,
)


class SSHMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.original_db_file = monitor.DB_FILE
        self.original_db_factory = monitor.db
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        monitor.DB_FILE = Path(self.temp_dir.name) / "ssh-test.db"
        monitor.init_db()

    def tearDown(self):
        monitor.db = self.original_db_factory
        monitor.DB_FILE = self.original_db_file
        self.temp_dir.cleanup()

    def test_cisco_port_discovery_parses_status_rows(self):
        output = """Port      Name                 Status       Vlan       Duplex  Speed Type
Gi1/0/1   uplink to core        connected    10         a-full  a-1000 10/100/1000BaseTX
Gi1/0/2                        notconnect   1          auto    auto   10/100/1000BaseTX
"""
        ports = parse_cisco_interface_status(output)
        self.assertEqual([port["port"] for port in ports], ["Gi1/0/1", "Gi1/0/2"])
        self.assertEqual(ports[0]["name"], "uplink to core")
        self.assertEqual(ports[0]["oper_status"], "connected")

    def test_cisco_details_parse_rates_and_counters(self):
        output = """GigabitEthernet1/0/1 is up, line protocol is up
  5 minute input rate 1250000 bits/sec, 100 packets/sec
  5 minute output rate 2500000 bits/sec, 200 packets/sec
     5 input errors, 2 CRC, 0 frame, 0 overrun, 0 ignored
     3 input packets, 4 output errors, 1 collisions
"""
        details = parse_cisco_interface_details("Gi1/0/1", output)
        self.assertEqual(details["oper_status"], "up")
        self.assertEqual(details["in_mbps"], 1.25)
        self.assertEqual(details["out_mbps"], 2.5)
        self.assertEqual(details["input_errors"], 5)
        self.assertEqual(details["output_errors"], 4)
        self.assertEqual(details["crc_errors"], 2)

    def test_malformed_cli_output_is_not_reported_as_zero(self):
        with self.assertRaises(SSHError):
            parse_cisco_interface_status("% Invalid input detected")
        with self.assertRaises(SSHError):
            parse_cisco_interface_details("Gi1/0/1", "not an interface response")

    def test_ssh_profile_registry_accepts_vendor_adapters(self):
        class TestProfile:
            discover_command = "show ports"

            def parse_ports(self, output):
                return []

            def details_command(self, port):
                return "show port " + port

            def parse_details(self, port, output):
                return {"port": port}

        register_ssh_profile("test_vendor", TestProfile)
        try:
            self.assertIn("test_vendor", SSH_PROFILE_REGISTRY)
        finally:
            del SSH_PROFILE_REGISTRY["test_vendor"]

    def test_ssh_traffic_check_returns_separate_rates(self):
        sensor = {
            "id": 1,
            "device_id": 1,
            "params": json.dumps({"port": "Gi1/0/1"}),
            "timeout_seconds": 5,
            "warning_latency_ms": 800,
            "error_latency_ms": 950,
        }
        details = {
            "port": "Gi1/0/1", "oper_status": "up", "admin_status": "up",
            "line_status": "up", "in_mbps": 12.5, "out_mbps": 5.25,
            "input_errors": 0, "output_errors": 0, "crc_errors": 0,
        }
        with mock.patch.object(monitor, "_ssh_port_details", return_value=details):
            status, value, message, meta = monitor.check_ssh_traffic(sensor)
        self.assertEqual(status, "up")
        self.assertEqual(value, 12.5)
        self.assertIn("IN 12.5000 Mbps", message)
        self.assertEqual(json.loads(meta)["out_mbps"], 5.25)

    def test_ssh_error_check_reports_per_poll_delta(self):
        conn = monitor.db()
        try:
            device_id = conn.execute(
                "INSERT INTO devices (name, host, created_at) VALUES (?, ?, ?)",
                ("switch", "192.0.2.10", "2026-01-01T00:00:00"),
            ).lastrowid
            sensor_id = conn.execute(
                "INSERT INTO sensors (device_id, name, sensor_type, params, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (device_id, "Switch errors", "ssh_errors", '{"port":"Gi1/0/1"}',
                 "2026-01-01T00:00:00"),
            ).lastrowid
            conn.execute(
                "INSERT INTO sensor_data (sensor_id, timestamp, status, meta) "
                "VALUES (?, ?, ?, ?)",
                (sensor_id, "2026-01-01 00:00:00", "up", json.dumps({
                    "input_errors": 3, "output_errors": 4, "crc_errors": 1,
                })),
            )
            conn.commit()
        finally:
            conn.close()
        sensor = {
            "id": sensor_id, "device_id": device_id,
            "params": '{"port":"Gi1/0/1"}', "timeout_seconds": 5,
            "warning_latency_ms": 1, "error_latency_ms": 10,
        }
        current = {
            "port": "Gi1/0/1", "oper_status": "up", "admin_status": "up",
            "line_status": "up", "in_mbps": 1, "out_mbps": 2,
            "input_errors": 5, "output_errors": 4, "crc_errors": 3,
        }
        with mock.patch.object(monitor, "_ssh_port_details", return_value=current):
            status, value, message, meta = monitor.check_ssh_errors(sensor)
        self.assertEqual(status, "warning")
        self.assertEqual(value, 4)
        self.assertIn("4 new errors", message)
        self.assertEqual(json.loads(meta)["error_delta"], {
            "input_errors": 2, "output_errors": 0, "crc_errors": 2,
        })

    def test_new_database_has_ssh_profiles_and_device_association(self):
        conn = monitor.db()
        try:
            tables = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
            self.assertIn("ssh_cred_id", tables)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) AS count FROM ssh_credentials").fetchone()["count"],
                0,
            )
        finally:
            conn.close()

    def test_ssh_password_is_encrypted_and_round_trips(self):
        encrypted = monitor._encrypt_ssh_password("switch-secret")
        self.assertNotIn("switch-secret", encrypted)
        self.assertTrue(encrypted.startswith("fernet:"))
        self.assertEqual(monitor._decrypt_ssh_password(encrypted), "switch-secret")

    def test_ssh_profile_form_saves_credentials_and_never_lists_password(self):
        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"
            state["_csrf_token"] = "test-token"
        page = client.get("/ssh-profiles/new")
        self.assertEqual(page.status_code, 200)
        response = client.post("/ssh-profiles/new", data={
            "_csrf_token": "test-token", "name": "Lab Cisco", "profile": "cisco_ios",
            "username": "monitor", "password": "switch-secret", "port": "22",
            "host_key_sha256": "A" * 43,
        })
        self.assertEqual(response.status_code, 302)
        conn = monitor.db()
        try:
            stored = conn.execute(
                "SELECT password FROM ssh_credentials WHERE name = ?", ("Lab Cisco",)
            ).fetchone()["password"]
            self.assertNotEqual(stored, "switch-secret")
            self.assertEqual(monitor._decrypt_ssh_password(stored), "switch-secret")
        finally:
            conn.close()
        listing = client.get("/ssh-profiles")
        self.assertEqual(listing.status_code, 200)
        self.assertNotIn("switch-secret", listing.get_data(as_text=True))

    def test_device_ssh_discovery_and_bulk_sensor_creation(self):
        conn = monitor.db()
        try:
            credential_id = conn.execute(
                "INSERT INTO ssh_credentials "
                "(name, profile, username, password, port, host_key_sha256, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("Test switch", "cisco_ios", "monitor",
                 monitor._encrypt_ssh_password("switch-secret"), 22, "A" * 43,
                 "2026-01-01T00:00:00"),
            ).lastrowid
            conn.commit()
        finally:
            conn.close()

        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"
            state["_csrf_token"] = "test-token"
        response = client.post("/devices/new", data={
            "_csrf_token": "test-token", "name": "Access switch",
            "host": "192.0.2.10", "ssh_cred_id": str(credential_id),
            "device_role": "switch",
        })
        self.assertEqual(response.status_code, 302)

        conn = monitor.db()
        try:
            device_id = conn.execute(
                "SELECT id FROM devices WHERE name = ?", ("Access switch",)
            ).fetchone()["id"]
        finally:
            conn.close()

        class MockSSHClient:
            def discover_ports(self):
                return [{"port": "Gi1/0/1", "name": "Uplink", "oper_status": "connected"}]

        with mock.patch.object(monitor, "_ssh_for", return_value=MockSSHClient()):
            page = client.get("/devices/%d/interfaces" % device_id)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Gi1/0/1", page.data)

        response = client.post("/devices/%d/interfaces/bulk-add" % device_id, data={
            "_csrf_token": "test-token", "selected_if": "Gi1/0/1|Uplink||",
            "bulk_create_traffic": "1", "bulk_create_status": "1",
            "bulk_create_errors": "1", "bulk_interval": "60",
        })
        self.assertEqual(response.status_code, 302)
        conn = monitor.db()
        try:
            types = {row["sensor_type"] for row in conn.execute(
                "SELECT sensor_type FROM sensors WHERE device_id = ?", (device_id,)
            )}
            self.assertTrue({"ssh_traffic", "ssh_interface", "ssh_errors"}.issubset(types))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
