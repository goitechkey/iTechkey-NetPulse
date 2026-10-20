import tempfile
import unittest
import time
import io
from datetime import datetime, timedelta
from pathlib import Path
import re
from unittest import mock

import itechkey_monitor as monitor
import itechkey_background as background
from itechkey_snmp import SNMPClient


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.original_db_file = monitor.DB_FILE
        self.original_db_factory = monitor.db
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        monitor.DB_FILE = Path(self.temp_dir.name) / "test.db"
        monitor._data_queue = []
        monitor._last_poll_at.clear()
        monitor._last_status.clear()
        monitor._restart_requested.clear()
        with monitor._web_server_lock:
            monitor._active_web_servers.clear()
        monitor.init_db()

    def tearDown(self):
        monitor.stop_monitor()
        deadline = time.monotonic() + 3
        while monitor._monitor_started and time.monotonic() < deadline:
            time.sleep(0.02)
        monitor.db = self.original_db_factory
        monitor.DB_FILE = self.original_db_file
        monitor._data_queue = []
        monitor._last_poll_at.clear()
        monitor._last_status.clear()
        monitor._restart_requested.clear()
        self.temp_dir.cleanup()

    def _create_sensor(self):
        conn = monitor.db()
        try:
            device_id = conn.execute(
                "INSERT INTO devices (name, host, created_at) VALUES (?, ?, ?)",
                ("router", "192.0.2.1", "2026-01-01T00:00:00"),
            ).lastrowid
            sensor_id = conn.execute(
                "INSERT INTO sensors "
                "(device_id, name, sensor_type, created_at) VALUES (?, ?, ?, ?)",
                (device_id, "Ping router", "ping", "2026-01-01T00:00:00"),
            ).lastrowid
            conn.commit()
            return device_id, sensor_id
        finally:
            conn.close()

    def test_snmp_v2c_uses_the_v2c_wire_version(self):
        client = monitor._snmp_for({
            "community": "public", "snmp_ver": "2c",
            "host": "192.0.2.1", "snmp_port": 161,
        })
        self.assertEqual(client.version, 1)  # BER encodes SNMP v2c as 1.
        self.assertEqual(SNMPClient("192.0.2.1", version=1).version, 0)

    def test_failed_batch_flush_keeps_samples_for_retry(self):
        class FailingDB:
            def executemany(self, *_args):
                raise RuntimeError("database unavailable")

            def close(self):
                pass

        row = (1, "2026-01-01 00:00:00", "up", 1.0, "ok", None, None, None)
        monitor._data_queue = [row]
        monitor.db = lambda: FailingDB()
        self.assertFalse(monitor._flush_batch())
        self.assertEqual(monitor._data_queue, [row])

    def test_retention_removes_expired_sensor_history(self):
        _, sensor_id = self._create_sensor()
        conn = monitor.db()
        try:
            conn.executemany(
                "INSERT INTO sensor_data "
                "(sensor_id, timestamp, status, message) VALUES (?, ?, ?, ?)",
                [
                    (sensor_id, "2026-01-01 00:00:00", "up", "old"),
                    (sensor_id, "2026-12-31 00:00:00", "up", "new"),
                ],
            )
            conn.commit()
        finally:
            conn.close()

        monitor.purge_expired_data(datetime(2027, 1, 1))

        conn = monitor.db()
        try:
            rows = conn.execute("SELECT message FROM sensor_data ORDER BY id").fetchall()
            self.assertEqual([row["message"] for row in rows], ["new"])
        finally:
            conn.close()

    def test_device_deletion_removes_its_sensor_tree(self):
        device_id, sensor_id = self._create_sensor()
        conn = monitor.db()
        try:
            conn.execute(
                "INSERT INTO sensor_data (sensor_id, timestamp, status) VALUES (?, ?, ?)",
                (sensor_id, "2026-01-01 00:00:00", "up"),
            )
            conn.execute(
                "INSERT INTO alert_rules (sensor_id, condition, created_at) VALUES (?, ?, ?)",
                (sensor_id, "down", "2026-01-01T00:00:00"),
            )
            conn.commit()
            monitor._delete_device_tree(conn, device_id)
            conn.commit()
            self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM sensors").fetchone()["c"], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM sensor_data").fetchone()["c"], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM alert_rules").fetchone()["c"], 0)
        finally:
            conn.close()

    def test_alert_rule_deletion_preserves_notification_history_without_orphan(self):
        _, sensor_id = self._create_sensor()
        conn = monitor.db()
        try:
            rule_id = conn.execute(
                "INSERT INTO alert_rules (sensor_id, condition, created_at) VALUES (?, ?, ?)",
                (sensor_id, "down", "2026-01-01T00:00:00"),
            ).lastrowid
            conn.execute(
                "INSERT INTO notifications (sensor_id, rule_id, timestamp, status) "
                "VALUES (?, ?, ?, ?)",
                (sensor_id, rule_id, "2026-01-01 00:00:00", "sent"),
            )
            conn.commit()
        finally:
            conn.close()

        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"
            state["_csrf_token"] = "test-token"
        response = client.post(
            f"/alerts/{rule_id}/delete", data={"_csrf_token": "test-token"}
        )
        self.assertEqual(response.status_code, 302)

        conn = monitor.db()
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) AS c FROM alert_rules").fetchone()["c"], 0
            )
            self.assertIsNone(
                conn.execute("SELECT rule_id FROM notifications").fetchone()["rule_id"]
            )
        finally:
            conn.close()

    def test_due_check_uses_cached_schedule_state(self):
        sensor = {
            "id": 10, "paused_until": None, "interval_seconds": 60,
            "last_timestamp": "2026-01-01 00:00:00",
        }
        self.assertFalse(monitor._sensor_due(sensor, datetime(2026, 1, 1, 0, 0, 59)))
        self.assertTrue(monitor._sensor_due(sensor, datetime(2026, 1, 1, 0, 1, 1)))

    def test_scheduler_records_completed_poll_without_network_access(self):
        _, sensor_id = self._create_sensor()
        original_check = monitor.run_sensor_check
        monitor.run_sensor_check = lambda _sensor: ("up", 1.0, "ok", None)
        try:
            self.assertTrue(monitor.start_monitor())
            deadline = time.monotonic() + 3
            samples = 0
            while time.monotonic() < deadline:
                conn = monitor.db()
                try:
                    samples = conn.execute(
                        "SELECT COUNT(*) AS c FROM sensor_data WHERE sensor_id = ?",
                        (sensor_id,),
                    ).fetchone()["c"]
                finally:
                    conn.close()
                if samples:
                    break
                time.sleep(0.05)
            self.assertEqual(samples, 1)
        finally:
            monitor.run_sensor_check = original_check

    def test_post_without_csrf_token_is_rejected(self):
        client = monitor.app.test_client()
        response = client.post("/login", data={"username": "admin", "password": "wrong"})
        self.assertEqual(response.status_code, 400)

    def test_login_csrf_and_initial_password_change_flow(self):
        client = monitor.app.test_client()
        login_page = client.get("/login")
        token = re.search(
            r'name="_csrf_token" value="([^"]+)"', login_page.get_data(as_text=True)
        ).group(1)
        response = client.post(
            "/login?next=https://example.invalid/",
            data={"username": "admin", "password": "admin", "_csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")

        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/settings", response.headers["Location"])
        settings_page = client.get("/settings")
        token = re.search(
            r'name="_csrf_token" value="([^"]+)"', settings_page.get_data(as_text=True)
        ).group(1)
        response = client.post(
            "/change-password",
            data={
                "old_password": "admin", "new_password": "changed-password",
                "confirm_password": "changed-password", "_csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(monitor.get_setting("force_password_change"), "0")

    def test_sensor_can_be_paused_and_resumed(self):
        _, sensor_id = self._create_sensor()
        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"
            state["_csrf_token"] = "test-token"

        response = client.post(
            f"/sensors/{sensor_id}/pause",
            data={"minutes": "15", "_csrf_token": "test-token"},
        )
        self.assertEqual(response.status_code, 302)
        conn = monitor.db()
        try:
            self.assertIsNotNone(
                conn.execute(
                    "SELECT paused_until FROM sensors WHERE id = ?", (sensor_id,)
                ).fetchone()["paused_until"]
            )
        finally:
            conn.close()

        response = client.post(
            f"/sensors/{sensor_id}/resume",
            data={"_csrf_token": "test-token"},
        )
        self.assertEqual(response.status_code, 302)
        conn = monitor.db()
        try:
            self.assertIsNone(
                conn.execute(
                    "SELECT paused_until FROM sensors WHERE id = ?", (sensor_id,)
                ).fetchone()["paused_until"]
            )
        finally:
            conn.close()

    def test_group_and_snmp_credential_forms_render_valid_csrf_tokens(self):
        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"

        group_page = client.get("/groups/new")
        token = re.search(
            r'name="_csrf_token" value="([^"]+)"', group_page.get_data(as_text=True)
        ).group(1)
        self.assertNotEqual(token, "{{ csrf_token() }}")
        response = client.post(
            "/groups/new", data={"name": "Branch", "_csrf_token": token}
        )
        self.assertEqual(response.status_code, 302)

        credential_page = client.get("/snmp-credentials/new")
        token = re.search(
            r'name="_csrf_token" value="([^"]+)"',
            credential_page.get_data(as_text=True),
        ).group(1)
        response = client.post(
            "/snmp-credentials/new",
            data={
                "name": "Branch SNMP", "version": "2c", "community": "public",
                "port": "161", "_csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_dashboard_separates_sensors_by_group_in_all_groups_view(self):
        conn = monitor.db()
        try:
            firewall_group = conn.execute(
                "INSERT INTO groups (name, created_at) VALUES (?, ?)",
                ("Firewall", "2026-01-01T00:00:00"),
            ).lastrowid
            windows_group = conn.execute(
                "INSERT INTO groups (name, created_at) VALUES (?, ?)",
                ("Windows Server", "2026-01-01T00:00:00"),
            ).lastrowid
            firewall_device = conn.execute(
                "INSERT INTO devices (group_id, name, host, created_at) VALUES (?, ?, ?, ?)",
                (firewall_group, "Firewall-01", "192.0.2.10", "2026-01-01T00:00:00"),
            ).lastrowid
            windows_device = conn.execute(
                "INSERT INTO devices (group_id, name, host, created_at) VALUES (?, ?, ?, ?)",
                (windows_group, "Windows-01", "192.0.2.20", "2026-01-01T00:00:00"),
            ).lastrowid
            conn.executemany(
                "INSERT INTO sensors (device_id, name, sensor_type, created_at) VALUES (?, ?, ?, ?)",
                [
                    (firewall_device, "Firewall Ping", "ping", "2026-01-01T00:00:00"),
                    (windows_device, "Windows Disk", "snmp_storage", "2026-01-01T00:00:00"),
                ],
            )
            conn.commit()
        finally:
            conn.close()

        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"

        page = client.get("/").get_data(as_text=True)
        self.assertIn('<h2>Firewall</h2>', page)
        self.assertIn('<h2>Windows Server</h2>', page)
        self.assertLess(page.index('<h2>Firewall</h2>'), page.index('<h2>Windows Server</h2>'))
        self.assertIn('Firewall-01 (192.0.2.10)', page)
        self.assertIn('Windows-01 (192.0.2.20)', page)

        filtered_page = client.get(f"/?group={firewall_group}").get_data(as_text=True)
        self.assertNotIn('<section class="sensor-group">', filtered_page)
        self.assertIn('Firewall / Firewall-01 (192.0.2.10)', filtered_page)

    def test_dashboard_displays_storage_usage_as_a_percentage(self):
        conn = monitor.db()
        try:
            device_id = conn.execute(
                "INSERT INTO devices (name, host, created_at) VALUES (?, ?, ?)",
                ("Storage Host", "192.0.2.30", "2026-01-01T00:00:00"),
            ).lastrowid
            sensor_id = conn.execute(
                "INSERT INTO sensors (device_id, name, sensor_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (device_id, "Drive C", "snmp_storage", "2026-01-01T00:00:00"),
            ).lastrowid
            conn.execute(
                "INSERT INTO sensor_data (sensor_id, timestamp, status, latency_ms, message) "
                "VALUES (?, ?, ?, ?, ?)",
                (sensor_id, "2026-01-01 00:00:00", "up", 12.34, "C: 12.3% used"),
            )
            conn.commit()
        finally:
            conn.close()

        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"

        page = client.get("/").get_data(as_text=True)
        self.assertIn("12.3% used", page)
        self.assertNotIn("12 ms", page)

    def test_restart_control_is_available_to_authenticated_users(self):
        monitor.set_setting("force_password_change", "0")
        client = monitor.app.test_client()
        with client.session_transaction() as state:
            state["user"] = "admin"
            state["_csrf_token"] = "test-token"

        settings_page = client.get("/settings").get_data(as_text=True)
        self.assertIn("Restart Application", settings_page)

        original_schedule = monitor.schedule_application_restart
        scheduled = []
        monitor.schedule_application_restart = lambda: scheduled.append(True) or True
        try:
            response = client.post("/restart", data={"_csrf_token": "test-token"})
        finally:
            monitor.schedule_application_restart = original_schedule

        self.assertEqual(response.status_code, 302)
        self.assertEqual(scheduled, [True])

    def test_supervisor_starts_a_fresh_child_after_a_restart_request(self):
        restart_child = mock.Mock()
        restart_child.wait.return_value = background.RESTART_EXIT_CODE
        new_child = mock.Mock()
        new_child.wait.return_value = 0
        log = io.StringIO()

        with mock.patch.object(
                background.subprocess, "Popen", side_effect=[restart_child, new_child]
        ) as launch, mock.patch.object(background.time, "sleep"):
            exit_code = background.run_supervised_monitor(log)

        self.assertEqual(exit_code, 0)
        self.assertEqual(launch.call_count, 2)
        self.assertEqual(launch.call_args.kwargs["env"]["ITECHKEY_SUPERVISED"], "1")
        self.assertIn("restart requested", log.getvalue())

    def test_supervised_restart_exits_with_the_supervisor_restart_code(self):
        with mock.patch.dict(monitor.os.environ, {"ITECHKEY_SUPERVISED": "1"}):
            with self.assertRaises(SystemExit) as exited:
                monitor.restart_current_process()
        self.assertEqual(exited.exception.code, monitor.RESTART_EXIT_CODE)

    def test_remote_http_is_rejected_without_explicit_opt_in(self):
        original = (monitor.BIND_HOST, monitor.SSL_CERT_FILE,
                    monitor.SSL_KEY_FILE, monitor.ALLOW_INSECURE_REMOTE)
        try:
            monitor.BIND_HOST = "0.0.0.0"
            monitor.SSL_CERT_FILE = ""
            monitor.SSL_KEY_FILE = ""
            monitor.ALLOW_INSECURE_REMOTE = False
            with self.assertRaisesRegex(ValueError, "Refusing remote HTTP"):
                monitor.run_web_servers()
        finally:
            (monitor.BIND_HOST, monitor.SSL_CERT_FILE,
             monitor.SSL_KEY_FILE, monitor.ALLOW_INSECURE_REMOTE) = original


if __name__ == "__main__":
    unittest.main()
