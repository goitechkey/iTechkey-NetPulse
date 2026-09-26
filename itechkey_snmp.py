"""
itechkey_snmp.py — Minimal pure-Python SNMP v1/v2c client.
Part of iTechkey NetPulse.
Author : iTechkey
Contact: admin@itechkey.com
Build  : 1.0.0
"""
import socket
import time
from typing import Iterator, List, Tuple, Any


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _enc_int(n: int) -> bytes:
    if n == 0:
        return b"\x02\x01\x00"
    if n > 0:
        length = (n.bit_length() + 7) // 8
        body = n.to_bytes(length, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    else:
        length = (n.bit_length() + 8) // 8
        body = n.to_bytes(length, "big", signed=True)
    return b"\x02" + _enc_len(len(body)) + body


def _enc_octstr(b) -> bytes:
    if isinstance(b, str):
        b = b.encode()
    return b"\x04" + _enc_len(len(b)) + b


def _enc_null() -> bytes:
    return b"\x05\x00"


def _enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid}")
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 0:
            raise ValueError(f"Negative OID component: {p}")
        if p < 0x80:
            body += bytes([p])
        else:
            chunks = []
            while p > 0:
                chunks.insert(0, p & 0x7F)
                p >>= 7
            for i in range(len(chunks) - 1):
                chunks[i] |= 0x80
            body += bytes(chunks)
    return b"\x06" + _enc_len(len(body)) + body


def _enc_seq(*items: bytes) -> bytes:
    body = b"".join(items)
    return b"\x30" + _enc_len(len(body)) + body


def _dec_tlv(data: bytes, offset: int = 0):
    tag = data[offset]; offset += 1
    length = data[offset]; offset += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    content = data[offset:offset + length]
    return tag, content, offset + length


def _dec_oid(b: bytes) -> str:
    if not b:
        return ""
    first = b[0]
    parts = [first // 40, first % 40]
    i = 1
    while i < len(b):
        val = 0
        while i < len(b):
            byte = b[i]; i += 1
            val = (val << 7) | (byte & 0x7F)
            if not (byte & 0x80):
                break
        parts.append(val)
    return ".".join(str(x) for x in parts)


def _dec_value(tag: int, content: bytes):
    if tag == 0x02:
        return int.from_bytes(content, "big", signed=True)
    if tag == 0x04:
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return content.hex()
    if tag == 0x05:
        return None
    if tag == 0x06:
        return _dec_oid(content)
    if tag == 0x40:
        return ".".join(str(x) for x in content) if len(content) == 4 else content.hex()
    if tag in (0x41, 0x42, 0x43, 0x46, 0x47):
        return int.from_bytes(content, "big", signed=False)
    if tag == 0x44:
        return content.hex()
    return content.hex()


class SNMPError(Exception):
    pass


class SNMPTimeout(SNMPError):
    pass


class SNMPClient:
    def __init__(self, host: str, community: str = "public",
                 version: int = 2, port: int = 161,
                 timeout: float = 5.0, retries: int = 1):
        self.host = host
        self.community = community
        self.version = 1 if version == 2 else 0
        self.port = int(port)
        self.timeout = timeout
        self.retries = retries
        self._req_id = int(time.time()) & 0x7FFFFFFF

    def _next_reqid(self):
        self._req_id = (self._req_id + 1) & 0x7FFFFFFF
        return self._req_id

    def _build_packet(self, pdu_tag, varbinds, req_id, **kw):
        vb_bytes = b""
        for oid, val in varbinds:
            vb_bytes += _enc_seq(_enc_oid(oid), val if val else _enc_null())
        vb_list = b"\x30" + _enc_len(len(vb_bytes)) + vb_bytes
        if pdu_tag == 0xA5:
            pdu_content = (_enc_int(req_id)
                           + _enc_int(kw.get("non_repeaters", 0))
                           + _enc_int(kw.get("max_repetitions", 10))
                           + vb_list)
        else:
            pdu_content = (_enc_int(req_id) + _enc_int(0) + _enc_int(0) + vb_list)
        pdu = bytes([pdu_tag]) + _enc_len(len(pdu_content)) + pdu_content
        msg = _enc_int(self.version) + _enc_octstr(self.community) + pdu
        return b"\x30" + _enc_len(len(msg)) + msg

    def _send_recv(self, packet):
        last_exc = None
        for attempt in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(packet, (self.host, self.port))
                data, _ = sock.recvfrom(65535)
                return data
            except socket.timeout:
                last_exc = SNMPTimeout(
                    f"Timeout {self.host}:{self.port} "
                    f"({attempt + 1}/{self.retries + 1})")
            except OSError as e:
                last_exc = SNMPError(f"Network error: {e}")
                break
            finally:
                sock.close()
            time.sleep(0.3)
        raise last_exc or SNMPError("Unknown SNMP failure")

    def _parse(self, data):
        tag, content, _ = _dec_tlv(data, 0)
        if tag != 0x30:
            raise SNMPError("Malformed response")
        _, _, o = _dec_tlv(content, 0)
        _, _, o = _dec_tlv(content, o)
        pdu_tag, pdu_content, _ = _dec_tlv(content, o)
        if pdu_tag != 0xA2:
            raise SNMPError(f"Expected GetResponse, got 0x{pdu_tag:02x}")
        _, c, o2 = _dec_tlv(pdu_content, 0)
        _, c, o2 = _dec_tlv(pdu_content, o2)
        err_status = int.from_bytes(c, "big", signed=True)
        _, c, o2 = _dec_tlv(pdu_content, o2)
        err_index = int.from_bytes(c, "big", signed=True)
        _, vb_list, _ = _dec_tlv(pdu_content, o2)
        if err_status != 0:
            raise SNMPError(f"SNMP error-status={err_status} index={err_index}")
        vbs = []
        pos = 0
        while pos < len(vb_list):
            _, vb_content, pos = _dec_tlv(vb_list, pos)
            _, name_c, o4 = _dec_tlv(vb_content, 0)
            oid = _dec_oid(name_c)
            vtag, vc, _ = _dec_tlv(vb_content, o4)
            vbs.append((oid, _dec_value(vtag, vc)))
        return vbs

    def get(self, *oids):
        req_id = self._next_reqid()
        packet = self._build_packet(0xA0, [(o, None) for o in oids], req_id)
        resp = self._parse(self._send_recv(packet))
        vals = [v for _, v in resp]
        if len(oids) == 1:
            return vals[0] if vals else None
        return vals

    def getnext(self, oid):
        req_id = self._next_reqid()
        packet = self._build_packet(0xA1, [(oid, None)], req_id)
        resp = self._parse(self._send_recv(packet))
        return resp[0] if resp else (oid, None)

    def walk(self, base_oid, max_rows=20000):
        oid = base_oid
        prefix = base_oid.rstrip(".") + "."
        rows = 0
        while rows < max_rows:
            new_oid, val = self.getnext(oid)
            if not new_oid.startswith(prefix) or new_oid == oid:
                break
            yield new_oid, val
            oid = new_oid
            rows += 1

    def bulkwalk(self, base_oid, max_rows=20000):
        if self.version != 1:
            yield from self.walk(base_oid, max_rows)
            return
        prefix = base_oid.rstrip(".") + "."
        current = base_oid
        rows = 0
        while rows < max_rows:
            req_id = self._next_reqid()
            packet = self._build_packet(0xA5, [(current, None)], req_id,
                                        non_repeaters=0, max_repetitions=25)
            resp = self._parse(self._send_recv(packet))
            if not resp:
                break
            progressed = False
            for oid, val in resp:
                if not oid.startswith(prefix) or val is None:
                    return
                yield oid, val
                current = oid
                rows += 1
                progressed = True
                if rows >= max_rows:
                    break
            if not progressed:
                break

    def sysname(self):
        try:
            return self.get("1.3.6.1.2.1.1.5.0") or ""
        except SNMPError:
            return ""

    def sysdescr(self):
        try:
            return self.get("1.3.6.1.2.1.1.1.0") or ""
        except SNMPError:
            return ""


IF_MIB = {
    "ifIndex":       "1.3.6.1.2.1.2.2.1.1",
    "ifDescr":       "1.3.6.1.2.1.2.2.1.2",
    "ifType":        "1.3.6.1.2.1.2.2.1.3",
    "ifSpeed":       "1.3.6.1.2.1.2.2.1.5",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus":  "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10",
    "ifInErrors":    "1.3.6.1.2.1.2.2.1.14",
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16",
    "ifOutErrors":   "1.3.6.1.2.1.2.2.1.20",
    "ifName":        "1.3.6.1.2.1.31.1.1.1.1",
    "ifHCInOctets":  "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifHighSpeed":   "1.3.6.1.2.1.31.1.1.1.15",
    "ifAlias":       "1.3.6.1.2.1.31.1.1.1.18",
}

IF_OPER_STATUS = {
    1: "up", 2: "down", 3: "testing", 4: "unknown",
    5: "dormant", 6: "notPresent", 7: "lowerLayerDown",
}

L3_IF_TYPES = {6, 23, 53, 131, 135, 136, 137, 161}


def discover_interfaces(client, l3_only=False):
    ifaces = {}

    def _walk(base, key):
        try:
            for oid, val in client.bulkwalk(base, max_rows=5000):
                idx = oid.rsplit(".", 1)[-1]
                ifaces.setdefault(idx, {"if_index": idx})
                ifaces[idx][key] = val
        except SNMPError:
            pass

    _walk(IF_MIB["ifDescr"], "descr")
    _walk(IF_MIB["ifName"], "name")
    _walk(IF_MIB["ifAlias"], "alias")
    _walk(IF_MIB["ifType"], "if_type")
    _walk(IF_MIB["ifOperStatus"], "oper_status_raw")
    _walk(IF_MIB["ifSpeed"], "speed_bps")
    _walk(IF_MIB["ifHighSpeed"], "high_speed_mbps")

    out = []
    for idx, info in ifaces.items():
        if "oper_status_raw" in info:
            info["oper_status"] = IF_OPER_STATUS.get(
                info["oper_status_raw"], str(info["oper_status_raw"]))
        if l3_only and info.get("if_type") not in L3_IF_TYPES:
            continue
        hs = info.get("high_speed_mbps")
        sp = info.get("speed_bps")
        info["speed_mbps"] = int(hs) if hs else (
            int(sp / 1_000_000) if sp else None)
        out.append(info)
    out.sort(key=lambda x: int(x.get("if_index", "0")))
    return out