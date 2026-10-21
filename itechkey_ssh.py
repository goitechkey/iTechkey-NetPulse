"""Extensible, read-only SSH collectors for managed L2 switches."""
import re

try:
    import paramiko
except ImportError:  # Keep the web application usable without optional dependencies.
    paramiko = None


class SSHError(RuntimeError):
    """Safe-to-display SSH or parser failure."""


PORT_STATUSES = {
    "connected", "notconnect", "disabled", "err-disabled", "inactive",
    "suspended", "sfpabsent", "down", "up", "monitoring", "trunk",
}
MAX_COMMAND_OUTPUT = 1_048_576


def _to_text(data):
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)


def parse_cisco_interface_status(output):
    """Parse useful rows from Cisco IOS/IOS XE ``show interfaces status``."""
    ports = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(("port ", "---", "name ")):
            continue
        columns = re.split(r"\s+", line)
        if len(columns) < 2:
            continue
        status_index = next(
            (index for index, value in enumerate(columns[1:], 1)
             if value.lower() in PORT_STATUSES), None,
        )
        if status_index is None:
            continue
        port = columns[0]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9/.-]*", port):
            continue
        name = " ".join(columns[1:status_index]) or port
        speed = next(
            (value for value in columns[status_index + 1:]
             if re.search(r"(?:\d|auto)", value, re.I)), "",
        )
        ports.append({
            "port": port, "name": name,
            "oper_status": columns[status_index].lower(), "speed": speed,
        })
    if not ports:
        raise SSHError("No switch ports parsed; verify the selected SSH profile and command output")
    return ports


def _first_int(pattern, output):
    match = re.search(pattern, output, re.I | re.M)
    return int(match.group(1).replace(",", "")) if match else None


def parse_cisco_interface_details(port, output):
    """Parse Cisco interface state, five-minute rates and error counters."""
    status_match = re.search(
        r"\bis\s+(administratively down|up|down)\s*,\s*line protocol is\s+(up|down)",
        output, re.I,
    )
    if not status_match:
        raise SSHError("Could not parse interface status from switch output")
    admin_status = status_match.group(1).lower()
    line_status = status_match.group(2).lower()
    in_bps = _first_int(r"(?:5 minute )?input rate\s+(\d+)\s+bits/sec", output)
    out_bps = _first_int(r"(?:5 minute )?output rate\s+(\d+)\s+bits/sec", output)
    return {
        "port": port,
        "oper_status": "up" if admin_status == "up" and line_status == "up" else "down",
        "admin_status": admin_status, "line_status": line_status,
        "in_mbps": round(in_bps / 1_000_000, 6) if in_bps is not None else None,
        "out_mbps": round(out_bps / 1_000_000, 6) if out_bps is not None else None,
        "input_errors": _first_int(r"(\d+)\s+input errors", output),
        "output_errors": _first_int(r"(\d+)\s+output errors", output),
        "crc_errors": _first_int(r"(\d+)\s+CRC", output),
    }


class CiscoIOSProfile:
    """Vendor adapter. Implement these methods to add another CLI family."""
    discover_command = "show interfaces status"

    def parse_ports(self, output):
        return parse_cisco_interface_status(output)

    def details_command(self, port):
        if not re.fullmatch(r"[A-Za-z0-9/.-]+", str(port).strip()):
            raise SSHError("Invalid switch port name")
        return "show interfaces " + str(port).strip()

    def parse_details(self, port, output):
        return parse_cisco_interface_details(port, output)


SSH_PROFILE_REGISTRY = {"cisco_ios": CiscoIOSProfile}


def register_ssh_profile(profile_id, profile_factory):
    """Register a vendor adapter implementing parse_ports/details methods."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", str(profile_id)):
        raise ValueError("Profile IDs must be lowercase identifiers")
    SSH_PROFILE_REGISTRY[profile_id] = profile_factory


class _ExpectedHostKeyPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    def __init__(self, expected_fingerprint):
        fingerprint = (expected_fingerprint or "").replace("SHA256:", "").strip()
        self.expected_fingerprint = fingerprint.rstrip("=")

    def missing_host_key(self, _client, hostname, key):
        import base64
        import hashlib
        actual = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if not self.expected_fingerprint or actual != self.expected_fingerprint:
            raise SSHError("SSH host key is not trusted; configure its SHA256 fingerprint")


class SSHSwitchClient:
    """Bounded SSH client for read-only switch commands with strict host-key checks."""

    def __init__(self, host, username, password=None, port=22, timeout=10,
                 profile="cisco_ios", expected_host_key=""):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or 22)
        self.timeout = max(1, int(timeout or 10))
        self.profile_name = profile or "cisco_ios"
        factory = SSH_PROFILE_REGISTRY.get(self.profile_name)
        if factory is None:
            raise SSHError("Unsupported SSH switch profile: " + self.profile_name)
        self.profile = factory()
        self.expected_host_key = expected_host_key

    def _run(self, command):
        if paramiko is None:
            raise SSHError("SSH support is unavailable; install Paramiko")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_ExpectedHostKeyPolicy(self.expected_host_key))
        try:
            client.connect(
                hostname=self.host, port=self.port, username=self.username,
                password=self.password or None, timeout=self.timeout,
                banner_timeout=self.timeout, auth_timeout=self.timeout,
                look_for_keys=False, allow_agent=False,
            )
            _stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            output = _to_text(stdout.read(MAX_COMMAND_OUTPUT + 1))
            error = _to_text(stderr.read(MAX_COMMAND_OUTPUT + 1)).strip()
            if len(output) > MAX_COMMAND_OUTPUT:
                raise SSHError("Switch command output exceeded the size limit")
            if error and not output.strip():
                raise SSHError("Switch rejected the read-only command")
            return output
        except SSHError:
            raise
        except Exception as exc:
            # Do not expose device banners, credentials, or raw library errors in the UI.
            raise SSHError("SSH request failed: " + type(exc).__name__) from exc
        finally:
            client.close()

    def discover_ports(self):
        return self.profile.parse_ports(self._run(self.profile.discover_command))

    def port_details(self, port):
        command = self.profile.details_command(port)
        return self.profile.parse_details(port, self._run(command))
