from __future__ import annotations

import ipaddress
import os
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass

import fcntl

from ..common import format_mac

ETH_P_ARP = 0x0806
ETH_P_IP = 0x0800
ETH_P_ALL = 0x0003
ARPOP_REQUEST = 1
ARPOP_REPLY = 2
IPPROTO_ICMP = 1
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

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


def get_interface_ipv4(interface: str) -> ipaddress.IPv4Address:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = struct.pack("256s", interface.encode("utf-8")[:15])
        response = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)
        return ipaddress.IPv4Address(response[20:24])
    except OSError as exc:
        raise DetectorError(f"Не удалось получить IPv4 для интерфейса {interface}: {exc}") from exc
    finally:
        if sock is not None:
            sock.close()


def get_interface_mac(interface: str) -> bytes:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = struct.pack("256s", interface.encode("utf-8")[:15])
        response = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, request)
        return response[18:24]
    except OSError as exc:
        raise DetectorError(f"Не удалось получить MAC для интерфейса {interface}: {exc}") from exc
    finally:
        if sock is not None:
            sock.close()


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


class RawArpScanner:
    def __init__(self, interface: str):
        self.interface = interface
        self.if_ip = get_interface_ipv4(interface)
        self.if_ip_bytes = self.if_ip.packed
        self.if_mac = get_interface_mac(interface)
        self.sock = self._open_socket()

    def _open_socket(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((self.interface, 0))
            sock.setblocking(False)
            return sock
        except PermissionError as exc:
            raise DetectorError("Нужны права root: используйте sudo") from exc
        except OSError as exc:
            raise DetectorError(f"Не удалось открыть raw socket на {self.interface}: {exc}") from exc

    def close(self) -> None:
        self.sock.close()

    def _send(self, frame: bytes) -> None:
        self.sock.send(frame)

    def _recv_until(self, deadline: float) -> bytes | None:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self.sock], [], [], remaining)
            if not ready:
                return None
            try:
                return self.sock.recv(65535)
            except BlockingIOError:
                continue

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


class RawIcmpScanner:
    def __init__(self, interface: str):
        self.interface = interface
        self.if_ip = get_interface_ipv4(interface)
        self.if_ip_bytes = self.if_ip.packed
        self.if_mac = get_interface_mac(interface)
        self.icmp_id = os.getpid() & 0xFFFF
        self.seq = 0
        self.sock = self._open_socket()

    def _open_socket(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sock.bind((self.interface, 0))
            sock.setblocking(False)
            return sock
        except PermissionError as exc:
            raise DetectorError("Нужны права root: используйте sudo") from exc
        except OSError as exc:
            raise DetectorError(f"Не удалось открыть raw socket на {self.interface}: {exc}") from exc

    def close(self) -> None:
        self.sock.close()

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq or self._next_seq()

    def _send(self, frame: bytes) -> None:
        self.sock.send(frame)

    def _recv_until(self, deadline: float) -> bytes | None:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self.sock], [], [], remaining)
            if not ready:
                return None
            try:
                return self.sock.recv(65535)
            except BlockingIOError:
                continue

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
        if any(bit == "1" for bit in signature[1:]):
            verdict = "Вероятно, хост отвечает на ICMP-кадры с чужим Ethernet dst MAC"
            suspicious = True
        elif signature.startswith("1"):
            verdict = "Признаков неразборчивого режима по ICMP не обнаружено"
            suspicious = False
        else:
            verdict = "Неизвестный результат ICMP-проверки"
            suspicious = False
        return ScanResult(host=target, signature=signature, verdict=verdict, suspicious=suspicious)


def validate_args(args) -> ipaddress.IPv4Network:
    if os.geteuid() != 0:
        raise DetectorError("Запустите с правами root: sudo abks-sniffer detect <subnet>")
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
        "    УЗЕЛ №2 - ДЕТЕКТОР СНИФФЕРОВ ПО ПОДСЕТИ",
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
    interface = args.interface or "eth0"
    scanner: RawArpScanner | RawIcmpScanner | None = None
    try:
        network = validate_args(args)
        scanner = RawIcmpScanner(interface) if args.method == "icmp" else RawArpScanner(interface)
        if scanner.if_ip not in network:
            raise DetectorError(f"IP интерфейса {scanner.if_ip} не входит в подсеть {network.with_prefixlen}")
        discovered = scanner.discover_hosts(network, per_host_delay=args.host_delay, receive_timeout=args.discovery_timeout)
        results = [scanner.fingerprint_host(host) for host in discovered]
        print(render_results(interface, args.method, scanner.if_ip, scanner.if_mac, network, discovered, results))
    except DetectorError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
    finally:
        if scanner is not None:
            scanner.close()
    sys.exit(1 if any(item.suspicious for item in results) else 0)
