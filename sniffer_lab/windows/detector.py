from __future__ import annotations

import ipaddress
import json
import os
import re
import struct
import subprocess
import sys
import time
from dataclasses import dataclass

from ..common import format_mac, mac_from_text
from .npcap import NpcapError, PcapHandle
from .sniffer import default_interface, list_interfaces

ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ARPOP_REQUEST = 1
ARPOP_REPLY = 2
IPPROTO_ICMP = 1
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

TEST_DEST_MACS = (
    b"\xff\xff\xff\xff\xff\xff",
    b"\xff\xff\xff\xff\xff\xfe",
    b"\xff\xff\x00\x00\x00\x00",
    b"\xff\x00\x00\x00\x00\x00",
    b"\x01\x00\x00\x00\x00\x00",
    b"\x01\x00\x5e\x00\x00\x00",
    b"\x01\x00\x5e\x00\x00\x01",
    b"\x01\x00\x5e\x00\x00\x03",
)

SIGNATURES = {
    "1_____1_": ("not_promiscuous", None),
    "1_______": ("not_promiscuous", None),
    "1___1_1_": ("not_promiscuous", None),
    "11111111": ("promiscuous", "Вероятно, интерфейс работает в неразборчивом режиме"),
    "1_1___1_": ("ambiguous", "Windows с установленным libpcap; сниффер может работать, а может и нет"),
    "111___1_": ("promiscuous", "Вероятно, интерфейс работает в неразборчивом режиме"),
}


class DetectorError(RuntimeError):
    pass


@dataclass
class HostInfo:
    ip: ipaddress.IPv4Address
    mac: bytes

    @property
    def mac_text(self) -> str:
        return format_mac(self.mac)


@dataclass
class ScanResult:
    host: HostInfo
    signature: str
    verdict: str
    suspicious: bool


def build_arp_frame(dst_mac: bytes, src_mac: bytes, sender_ip: bytes, target_ip: bytes) -> bytes:
    return (
        dst_mac
        + src_mac
        + struct.pack("!H", ETH_P_ARP)
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, ARPOP_REQUEST)
        + src_mac
        + sender_ip
        + b"\x00" * 6
        + target_ip
    )


def parse_arp_packet(frame: bytes) -> tuple[int, bytes, bytes, bytes, bytes] | None:
    if len(frame) < 42 or struct.unpack("!H", frame[12:14])[0] != ETH_P_ARP:
        return None
    payload = frame[14:42]
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", payload[:8])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    return oper, payload[8:14], payload[14:18], payload[18:24], payload[24:28]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_icmp_echo_frame(
    dst_mac: bytes,
    src_mac: bytes,
    sender_ip: bytes,
    target_ip: bytes,
    ident: int,
    seq: int,
) -> bytes:
    payload = b"ABKS_SNIFFER_DETECT_ICMP"
    icmp = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq) + payload
    icmp = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum(icmp), ident, seq) + payload

    total_len = 20 + len(icmp)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        seq & 0xFFFF,
        0,
        64,
        IPPROTO_ICMP,
        0,
        sender_ip,
        target_ip,
    )
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        seq & 0xFFFF,
        0,
        64,
        IPPROTO_ICMP,
        checksum(ip_header),
        sender_ip,
        target_ip,
    )
    return dst_mac + src_mac + struct.pack("!H", ETH_P_IP) + ip_header + icmp


def parse_icmp_echo_reply(frame: bytes) -> tuple[bytes, bytes, bytes, int, int] | None:
    if len(frame) < 42 or struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    version_ihl = ip[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(ip) < ihl + 8:
        return None
    total_len = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    if proto != IPPROTO_ICMP or total_len < ihl + 8:
        return None
    src_ip = ip[12:16]
    dst_ip = ip[16:20]
    icmp = ip[ihl:total_len]
    icmp_type, code, _csum, ident, seq = struct.unpack("!BBHHH", icmp[:8])
    if icmp_type != ICMP_ECHO_REPLY or code != 0:
        return None
    return frame[6:12], src_ip, dst_ip, ident, seq


def _extract_guid(interface: str) -> str | None:
    match = re.search(r"\{([0-9a-fA-F-]{36})\}", interface)
    return match.group(1).lower() if match else None


def _powershell_json(command: str):
    for exe in ("powershell.exe", "pwsh.exe"):
        try:
            result = subprocess.run(
                [exe, "-NoProfile", "-Command", command],
                check=True,
                capture_output=True,
                text=True,
                timeout=8,
            )
            text = result.stdout.strip()
            if not text:
                return None
            return json.loads(text)
        except (FileNotFoundError, subprocess.SubprocessError, json.JSONDecodeError):
            continue
    return None


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def get_windows_adapter_info(interface: str) -> tuple[ipaddress.IPv4Address, bytes]:
    guid = _extract_guid(interface)
    if not guid:
        raise DetectorError("Не удалось извлечь GUID из имени Npcap-интерфейса")

    adapters = _powershell_json(
        "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceGuid,MacAddress,ifIndex | ConvertTo-Json -Depth 4"
    )
    for adapter in _as_list(adapters):
        if str(adapter.get("InterfaceGuid", "")).lower() != guid:
            continue
        if_index = adapter.get("ifIndex")
        mac_text = adapter.get("MacAddress")
        addresses = _powershell_json(
            f"Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex {int(if_index)} | "
            "Select-Object IPAddress | ConvertTo-Json -Depth 4"
        )
        ip_items = _as_list(addresses)
        if not ip_items:
            raise DetectorError(f"У интерфейса {interface} не найден IPv4")
        ip_text = ip_items[0].get("IPAddress")
        if not ip_text or not mac_text:
            raise DetectorError(f"Не удалось получить IP/MAC для интерфейса {interface}")
        return ipaddress.IPv4Address(ip_text), mac_from_text(mac_text)

    raise DetectorError(
        "Не удалось сопоставить Npcap-интерфейс с Windows-адаптером. "
        "Передайте --local-ip и --local-mac вручную."
    )


class NpcapArpScanner:
    def __init__(self, interface: str, local_ip: ipaddress.IPv4Address, local_mac: bytes):
        self.interface = interface
        self.if_ip = local_ip
        self.if_ip_bytes = self.if_ip.packed
        self.if_mac = local_mac
        try:
            self.handle = PcapHandle(interface, promisc=True, timeout_ms=10)
        except NpcapError as exc:
            raise DetectorError(str(exc)) from exc

    def close(self) -> None:
        self.handle.close()

    def _send(self, frame: bytes) -> None:
        try:
            self.handle.send_packet(frame)
        except NpcapError as exc:
            raise DetectorError(str(exc)) from exc

    def _recv_until(self, deadline: float) -> bytes | None:
        try:
            return self.handle.recv_until(deadline)
        except NpcapError as exc:
            raise DetectorError(str(exc)) from exc

    def _flush_matching(self, target: HostInfo, wait_seconds: float = 0.1) -> None:
        deadline = time.monotonic() + wait_seconds
        expected_l2 = self.if_mac + target.mac
        while True:
            frame = self._recv_until(deadline)
            if frame is None:
                return
            if frame[:12] != expected_l2:
                continue

    def discover_hosts(self, network: ipaddress.IPv4Network, per_host_delay: float = 0.002, receive_timeout: float = 1.5) -> list[HostInfo]:
        hosts = [ip for ip in network.hosts() if ip != self.if_ip]
        for host_ip in hosts:
            self._send(build_arp_frame(b"\xff\xff\xff\xff\xff\xff", self.if_mac, self.if_ip_bytes, host_ip.packed))
            if per_host_delay > 0:
                time.sleep(per_host_delay)

        found: dict[ipaddress.IPv4Address, HostInfo] = {}
        deadline = time.monotonic() + receive_timeout
        while True:
            frame = self._recv_until(deadline)
            if frame is None:
                break
            parsed = parse_arp_packet(frame)
            if not parsed:
                continue
            oper, sender_mac, sender_ip, _target_mac, target_ip = parsed
            if oper != ARPOP_REPLY or target_ip != self.if_ip_bytes:
                continue
            ip_addr = ipaddress.IPv4Address(sender_ip)
            if ip_addr in network and ip_addr != self.if_ip:
                found[ip_addr] = HostInfo(ip=ip_addr, mac=sender_mac)
        return [found[ip_addr] for ip_addr in sorted(found)]

    def do_test(self, target: HostInfo, dst_mac: bytes) -> str:
        frame = build_arp_frame(dst_mac, self.if_mac, self.if_ip_bytes, target.ip.packed)
        expected_l2 = self.if_mac + target.mac
        for attempt in range(1, 4):
            self._flush_matching(target, wait_seconds=0.1)
            deadline = time.monotonic() + 0.010 * attempt * attempt
            self._send(frame)
            while True:
                response = self._recv_until(deadline)
                if response is None:
                    break
                if response[:12] != expected_l2:
                    continue
                parsed = parse_arp_packet(response)
                if not parsed:
                    continue
                oper, sender_mac, sender_ip, _target_mac, target_ip = parsed
                if oper == ARPOP_REPLY and sender_mac == target.mac and sender_ip == target.ip.packed and target_ip == self.if_ip_bytes:
                    return "1"
        return "_"

    def fingerprint_host(self, target: HostInfo) -> ScanResult:
        signature = "".join(self.do_test(target, dst_mac) for dst_mac in TEST_DEST_MACS)
        kind, message = SIGNATURES.get(signature, ("unknown", "Неизвестный результат"))
        if kind == "not_promiscuous":
            verdict, suspicious = "Признаков неразборчивого режима не обнаружено", False
        elif kind == "promiscuous":
            verdict, suspicious = message or "Вероятно, интерфейс работает в неразборчивом режиме", True
        elif kind == "ambiguous":
            verdict, suspicious = message or "Неоднозначный результат", False
        else:
            verdict, suspicious = message or "Неизвестный результат", False
        return ScanResult(host=target, signature=signature, verdict=verdict, suspicious=suspicious)


class NpcapIcmpScanner:
    def __init__(self, interface: str, local_ip: ipaddress.IPv4Address, local_mac: bytes):
        self.interface = interface
        self.if_ip = local_ip
        self.if_ip_bytes = self.if_ip.packed
        self.if_mac = local_mac
        self.icmp_id = os.getpid() & 0xFFFF
        self.seq = 0
        try:
            self.handle = PcapHandle(interface, promisc=True, timeout_ms=10)
        except NpcapError as exc:
            raise DetectorError(str(exc)) from exc

    def close(self) -> None:
        self.handle.close()

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq or self._next_seq()

    def _send(self, frame: bytes) -> None:
        try:
            self.handle.send_packet(frame)
        except NpcapError as exc:
            raise DetectorError(str(exc)) from exc

    def _recv_until(self, deadline: float) -> bytes | None:
        try:
            return self.handle.recv_until(deadline)
        except NpcapError as exc:
            raise DetectorError(str(exc)) from exc

    def discover_hosts(self, network: ipaddress.IPv4Network, per_host_delay: float = 0.002, receive_timeout: float = 1.5) -> list[HostInfo]:
        sent: dict[int, ipaddress.IPv4Address] = {}
        for host_ip in [ip for ip in network.hosts() if ip != self.if_ip]:
            seq = self._next_seq()
            sent[seq] = host_ip
            frame = build_icmp_echo_frame(
                b"\xff\xff\xff\xff\xff\xff",
                self.if_mac,
                self.if_ip_bytes,
                host_ip.packed,
                self.icmp_id,
                seq,
            )
            self._send(frame)
            if per_host_delay > 0:
                time.sleep(per_host_delay)

        found: dict[ipaddress.IPv4Address, HostInfo] = {}
        deadline = time.monotonic() + receive_timeout
        while True:
            frame = self._recv_until(deadline)
            if frame is None:
                break
            parsed = parse_icmp_echo_reply(frame)
            if not parsed:
                continue
            sender_mac, sender_ip, target_ip, ident, seq = parsed
            if ident != self.icmp_id or target_ip != self.if_ip_bytes or seq not in sent:
                continue
            ip_addr = ipaddress.IPv4Address(sender_ip)
            if ip_addr == sent[seq] and ip_addr in network and ip_addr != self.if_ip:
                found[ip_addr] = HostInfo(ip=ip_addr, mac=sender_mac)
        return [found[ip_addr] for ip_addr in sorted(found)]

    def do_test(self, target: HostInfo, dst_mac: bytes) -> str:
        for attempt in range(1, 4):
            seq = self._next_seq()
            frame = build_icmp_echo_frame(dst_mac, self.if_mac, self.if_ip_bytes, target.ip.packed, self.icmp_id, seq)
            deadline = time.monotonic() + 0.050 * attempt * attempt
            self._send(frame)
            while True:
                response = self._recv_until(deadline)
                if response is None:
                    break
                parsed = parse_icmp_echo_reply(response)
                if not parsed:
                    continue
                sender_mac, sender_ip, target_ip, ident, reply_seq = parsed
                if (
                    sender_mac == target.mac
                    and sender_ip == target.ip.packed
                    and target_ip == self.if_ip_bytes
                    and ident == self.icmp_id
                    and reply_seq == seq
                ):
                    return "1"
        return "_"

    def fingerprint_host(self, target: HostInfo) -> ScanResult:
        signature = "".join(self.do_test(target, dst_mac) for dst_mac in TEST_DEST_MACS)
        kind, message = SIGNATURES.get(signature, ("unknown", "Неизвестный результат ICMP-проверки"))
        if kind == "not_promiscuous":
            verdict, suspicious = "Признаков неразборчивого режима по ICMP не обнаружено", False
        elif kind == "promiscuous":
            verdict, suspicious = message or "Вероятно, интерфейс работает в неразборчивом режиме", True
        elif kind == "ambiguous":
            verdict, suspicious = message or "Неоднозначный результат", False
        else:
            verdict, suspicious = message or "Неизвестный результат ICMP-проверки", False
        return ScanResult(host=target, signature=signature, verdict=verdict, suspicious=suspicious)


def validate_args(args) -> ipaddress.IPv4Network:
    if args.discovery_timeout <= 0:
        raise DetectorError("--discovery-timeout должен быть больше 0")
    if args.host_delay < 0:
        raise DetectorError("--host-delay не может быть отрицательным")
    try:
        network = ipaddress.ip_network(args.target, strict=False)
    except ValueError as exc:
        raise DetectorError(f"Некорректная подсеть или адрес: {args.target}") from exc
    if network.version != 4:
        raise DetectorError("Поддерживается только IPv4")
    return network


def render_results(interface: str, method: str, local_ip: ipaddress.IPv4Address, local_mac: bytes, network: ipaddress.IPv4Network, discovered: list[HostInfo], results: list[ScanResult]) -> str:
    suspicious = [item for item in results if item.suspicious]
    unknown = [item for item in results if item.verdict == "Неизвестный результат"]
    lines = [
        "=" * 72,
        "    УЗЕЛ №2 - ДЕТЕКТОР СНИФФЕРОВ ПО ПОДСЕТИ (WINDOWS/NPCAP)",
        "=" * 72,
        "",
        f"  Интерфейс        : {interface}",
        f"  Метод            : {method.upper()}",
        f"  Наш IP           : {local_ip}",
        f"  Наш MAC          : {format_mac(local_mac)}",
        f"  Сканируемая сеть : {network.with_prefixlen}",
        f"  Найдено хостов   : {len(discovered)}",
        "",
    ]
    if not discovered:
        lines.append("  Живые хосты в подсети не обнаружены.")
        lines.append("=" * 72)
        return "\n".join(lines)
    lines.append("  Результаты:")
    for item in results:
        lines.append(f"  {str(item.host.ip):15}  {item.host.mac_text:17}  {item.verdict:42} tests=\"{item.signature}\"")
    lines.extend(["", "-" * 72, f"  Подозрительных хостов : {len(suspicious)}", f"  Неоднозначных сигнатур: {len(unknown)}", "=" * 72])
    return "\n".join(lines)


def run(args) -> None:
    scanner: NpcapArpScanner | NpcapIcmpScanner | None = None
    try:
        network = validate_args(args)
        interface = args.interface or default_interface()
        if not interface:
            raise DetectorError("Npcap-интерфейсы не найдены")
        if bool(args.local_ip) != bool(args.local_mac):
            raise DetectorError("--local-ip и --local-mac нужно передавать вместе")
        if args.local_ip and args.local_mac:
            local_ip = ipaddress.IPv4Address(args.local_ip)
            local_mac = mac_from_text(args.local_mac)
        else:
            local_ip, local_mac = get_windows_adapter_info(interface)
        scanner = NpcapIcmpScanner(interface, local_ip, local_mac) if args.method == "icmp" else NpcapArpScanner(interface, local_ip, local_mac)
        if scanner.if_ip not in network:
            raise DetectorError(f"IP интерфейса {scanner.if_ip} не входит в подсеть {network.with_prefixlen}")
        discovered = scanner.discover_hosts(network, per_host_delay=args.host_delay, receive_timeout=args.discovery_timeout)
        results = [scanner.fingerprint_host(host) for host in discovered]
        print(render_results(interface, args.method, scanner.if_ip, scanner.if_mac, network, discovered, results))
    except (DetectorError, ValueError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        print("[*] Подсказка: список интерфейсов можно посмотреть командой abks-sniffer list", file=sys.stderr)
        sys.exit(2)
    finally:
        if scanner is not None:
            scanner.close()
    sys.exit(1 if any(item.suspicious for item in results) else 0)
