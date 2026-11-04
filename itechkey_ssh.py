"""Extensible, read-only SSH collectors for managed L2 switches."""
import io
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
READ_ONLY_COMMAND = re.compile(r"^\s*(?:show|display|get|status)\b", re.I)


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


def _capture_pattern(pattern, output, field):
    """Return a named capture or the first capture from a custom CLI regex."""
    if not pattern:
        return None
    try:
        match = re.search(pattern, output, re.I | re.M)
    except re.error as exc:
        raise SSHError("Invalid custom %s regex" % field) from exc
    if not match:
        return None
    values = match.groupdict()
    return values.get(field) or values.get("value") or values.get("status") or match.group(1)


def _numeric_capture(pattern, output, field):
    value = _capture_pattern(pattern, output, field)
    if value is None:
        return None
    try:
        return float(str(value).replace(",", ""))
    except ValueError as exc:
        raise SSHError("Custom %s regex did not capture a number" % field) from exc


def _read_only_command(command, field, require_port=False):
    command = str(command or "").strip()
    if (not command or not READ_ONLY_COMMAND.match(command)
            or any(token in command for token in (";", "\n", "\r", "|", "&", "`", "$"))):
        raise SSHError("Custom %s must be a read-only show/display/get/status command" % field)
    if require_port and "{port}" not in command:
        raise SSHError("Custom port command must include {port}")
    return command


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


class CustomCLIProfile:
    """Admin-configured parser for a switch CLI that has no built-in adapter."""

    def __init__(self, config):
        self.config = config or {}
        self.discovery_command = _read_only_command(
            self.config.get("discovery_command"), "discovery command",
        )
        self._port_command = _read_only_command(
            self.config.get("port_command"), "port command", require_port=True,
        )

    def parse_ports(self, output):
        pattern = self.config.get("port_regex", "")
        try:
            matches = list(re.finditer(pattern, output, re.I | re.M))
        except re.error as exc:
            raise SSHError("Invalid custom port discovery regex") from exc
        ports = []
        for match in matches:
            values = match.groupdict()
            port = str(values.get("port", "")).strip()
            if not re.fullmatch(r"[A-Za-z0-9/.-]+", port):
                continue
            ports.append({
                "port": port,
                "name": str(values.get("name", "")).strip() or port,
                "oper_status": str(values.get("status", "unknown")).lower(),
                "speed": str(values.get("speed", "")).strip(),
            })
        if not ports:
            raise SSHError("No ports matched the custom discovery regex")
        return ports

    def details_command(self, port):
        clean_port = str(port).strip()
        if not re.fullmatch(r"[A-Za-z0-9/.-]+", clean_port):
            raise SSHError("Invalid switch port name")
        return self._port_command.replace("{port}", clean_port)

    def parse_details(self, port, output):
        status = _capture_pattern(self.config.get("status_regex", ""), output, "status")
        status = str(status or "unknown").lower()
        up_values = {
            value.strip().lower() for value in
            str(self.config.get("up_values") or "up,connected").split(",") if value.strip()
        }
        rate_unit = str(self.config.get("rate_unit") or "bps").lower()
        rate_divisor = {"bps": 1_000_000, "kbps": 1_000, "mbps": 1}.get(rate_unit)
        if rate_divisor is None:
            raise SSHError("Custom rate unit must be bps, kbps, or mbps")
        in_rate = _numeric_capture(self.config.get("input_rate_regex", ""), output, "input rate")
        out_rate = _numeric_capture(self.config.get("output_rate_regex", ""), output, "output rate")
        def counter(pattern, name):
            value = _numeric_capture(pattern, output, name)
            return int(value) if value is not None else None
        return {
            "port": port,
            "oper_status": "up" if status in up_values else "down",
            "admin_status": status,
            "line_status": status,
            "in_mbps": round(in_rate / rate_divisor, 6) if in_rate is not None else None,
            "out_mbps": round(out_rate / rate_divisor, 6) if out_rate is not None else None,
            "input_errors": counter(self.config.get("input_errors_regex", ""), "input errors"),
            "output_errors": counter(self.config.get("output_errors_regex", ""), "output errors"),
            "crc_errors": counter(self.config.get("crc_errors_regex", ""), "CRC errors"),
        }


SSH_PROFILE_REGISTRY = {
    "cisco_ios": CiscoIOSProfile,
    "custom_cli": CustomCLIProfile,
}


def register_ssh_profile(profile_id, profile_factory):
    """Register a vendor adapter implementing parse_ports/details methods."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", str(profile_id)):
        raise ValueError("Profile IDs must be lowercase identifiers")
    SSH_PROFILE_REGISTRY[profile_id] = profile_factory


class _ExpectedHostKeyPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    """Verify a saved key, or learn one during an explicit first connection."""

    def __init__(self, expected_fingerprint="", trust_on_first_use=False):
        fingerprint = (expected_fingerprint or "").replace("SHA256:", "").strip()
        self.expected_fingerprint = fingerprint.rstrip("=")
        self.trust_on_first_use = bool(trust_on_first_use)
        self.observed_fingerprint = ""

    def missing_host_key(self, _client, hostname, key):
        import base64
        import hashlib
        actual = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if self.expected_fingerprint:
            if actual != self.expected_fingerprint:
                raise SSHError(
                    "SSH host key changed; edit the device and choose Trust SSH key again"
                )
        elif not self.trust_on_first_use:
            raise SSHError("SSH host key is not trusted")
        self.observed_fingerprint = actual


class SSHSwitchClient:
    """Bounded SSH client for read-only commands with pinned SSH host keys."""

    def __init__(self, host, username, password=None, private_key=None,
                 key_passphrase=None, port=22, timeout=10, profile="cisco_ios",
                 profile_config=None, expected_host_key="", trust_on_first_use=False):
        self.host = host
        self.username = username
        self.password = password
        self.private_key = private_key or ""
        self.key_passphrase = key_passphrase or ""
        self.port = int(port or 22)
        self.timeout = max(1, int(timeout or 10))
        self.profile_name = profile or "cisco_ios"
        factory = SSH_PROFILE_REGISTRY.get(self.profile_name)
        if factory is None:
            raise SSHError("Unsupported SSH switch profile: " + self.profile_name)
        self.profile = factory(profile_config or {}) if self.profile_name == "custom_cli" else factory()
        self.expected_host_key = expected_host_key
        self.trust_on_first_use = bool(trust_on_first_use)
        self.trusted_host_key = ""

    def _load_private_key(self):
        if not self.private_key.strip():
            return None
        key_data = io.StringIO(self.private_key)
        key_types = [paramiko.RSAKey, paramiko.ECDSAKey]
        if hasattr(paramiko, "Ed25519Key"):
            key_types.append(paramiko.Ed25519Key)
        for key_type in key_types:
            key_data.seek(0)
            try:
                return key_type.from_private_key(
                    key_data, password=self.key_passphrase or None,
                )
            except Exception:
                continue
        raise SSHError("Private key could not be read; use a supported PEM or OpenSSH key")

    def _run(self, command):
        if paramiko is None:
            raise SSHError("SSH support is unavailable; install Paramiko")
        client = paramiko.SSHClient()
        host_key_policy = _ExpectedHostKeyPolicy(
            self.expected_host_key, trust_on_first_use=self.trust_on_first_use,
        )
        client.set_missing_host_key_policy(host_key_policy)
        try:
            client.connect(
                hostname=self.host, port=self.port, username=self.username,
                password=self.password or None, pkey=self._load_private_key(),
                timeout=self.timeout,
                banner_timeout=self.timeout, auth_timeout=self.timeout,
                look_for_keys=False, allow_agent=False,
            )
            self.trusted_host_key = host_key_policy.observed_fingerprint
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
