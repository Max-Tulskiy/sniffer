#!/usr/bin/env python3
"""
Узел №2 — сетевой детектор снифферов по мотивам nmap sniffer-detect.nse.

Идея проверки:
  1. Находим живые хосты в указанной IPv4-подсети с помощью обычного ARP.
  2. Для каждого хоста отправляем 8 ARP-запросов с разными Ethernet dst MAC.
  3. Если цель отвечает на кадры, которые обычная NIC должна отбрасывать,
     это может указывать на promiscuous mode.

Скрипт повторяет общую эвристику NSE-скрипта:
  • сигнатуры тестов "11111111", "111___1_" и т.п.;
  • 3 попытки на каждый тест;
  • короткие таймауты ожидания ответа.

Ограничения:
  • только IPv4;
  • только локальная L2-сеть;
  • требуется root (raw socket).
"""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import os
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass

ETH_P_ARP = 0x0806
ETH_P_ALL = 0x0003
ARPOP_REQUEST = 1
ARPOP_REPLY = 2
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

TEST_DEST_MACS = (
    b"\xff\xff\xff\xff\xff\xff",  # B32
    b"\xff\xff\xff\xff\xff\xfe",  # B31
    b"\xff\xff\x00\x00\x00\x00",  # B16
    b"\xff\x00\x00\x00\x00\x00",  # B8
    b"\x01\x00\x00\x00\x00\x00",  # G
    b"\x01\x00\x5e\x00\x00\x00",  # M0
    b"\x01\x00\x5e\x00\x00\x01",  # M1
    b"\x01\x00\x5e\x00\x00\x03",  # M3
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
    """Ошибка настройки или сетевого ввода-вывода."""


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


def format_mac(mac: bytes) -> str:
    return ":".join(f"{part:02x}" for part in mac)


def mac_from_text(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def get_interface_ipv4(interface: str) -> ipaddress.IPv4Address:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = struct.pack("256s", interface.encode("utf-8")[:15])
        response = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)
    except OSError as exc:
        raise DetectorError(f"Не удалось получить IPv4 для интерфейса {interface}: {exc}") from exc
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    return ipaddress.IPv4Address(response[20:24])


def get_interface_mac(interface: str) -> bytes:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        request = struct.pack("256s", interface.encode("utf-8")[:15])
        response = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, request)
    except OSError as exc:
        raise DetectorError(f"Не удалось получить MAC для интерфейса {interface}: {exc}") from exc
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    return response[18:24]


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
    if len(frame) < 42:
        return None
    if struct.unpack("!H", frame[12:14])[0] != ETH_P_ARP:
        return None
    payload = frame[14:42]
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", payload[:8])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    sender_mac = payload[8:14]
    sender_ip = payload[14:18]
    target_mac = payload[18:24]
    target_ip = payload[24:28]
    return oper, sender_mac, sender_ip, target_mac, target_ip


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
        except PermissionError as exc:
            raise DetectorError("Нужны права root: используйте sudo") from exc
        except OSError as exc:
            raise DetectorError(f"Не удалось открыть raw socket на {self.interface}: {exc}") from exc
        return sock

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

    def discover_hosts(
        self,
        network: ipaddress.IPv4Network,
        per_host_delay: float = 0.002,
        receive_timeout: float = 1.5,
    ) -> list[HostInfo]:
        hosts = [ip for ip in network.hosts() if ip != self.if_ip]
        for host_ip in hosts:
            frame = build_arp_frame(
                b"\xff\xff\xff\xff\xff\xff",
                self.if_mac,
                self.if_ip_bytes,
                host_ip.packed,
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
            parsed = parse_arp_packet(frame)
            if not parsed:
                continue
            oper, sender_mac, sender_ip, _target_mac, target_ip = parsed
            if oper != ARPOP_REPLY:
                continue
            if target_ip != self.if_ip_bytes:
                continue
            ip_addr = ipaddress.IPv4Address(sender_ip)
            if ip_addr not in network or ip_addr == self.if_ip:
                continue
            found[ip_addr] = HostInfo(ip=ip_addr, mac=sender_mac)
        return [found[ip_addr] for ip_addr in sorted(found)]

    def do_test(self, target: HostInfo, dst_mac: bytes) -> str:
        frame = build_arp_frame(dst_mac, self.if_mac, self.if_ip_bytes, target.ip.packed)
        expected_l2 = self.if_mac + target.mac

        for attempt in range(1, 4):
            self._flush_matching(target, wait_seconds=0.1)
            timeout = 0.010 * attempt * attempt
            deadline = time.monotonic() + timeout
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
                if oper != ARPOP_REPLY:
                    continue
                if sender_mac != target.mac:
                    continue
                if sender_ip != target.ip.packed:
                    continue
                if target_ip != self.if_ip_bytes:
                    continue
                return "1"
        return "_"

    def fingerprint_host(self, target: HostInfo) -> ScanResult:
        signature = "".join(self.do_test(target, dst_mac) for dst_mac in TEST_DEST_MACS)
        kind, message = SIGNATURES.get(signature, ("unknown", "Неизвестный результат"))

        if kind == "not_promiscuous":
            verdict = "Признаков неразборчивого режима не обнаружено"
            suspicious = False
        elif kind == "promiscuous":
            verdict = message or "Вероятно, интерфейс работает в неразборчивом режиме"
            suspicious = True
        elif kind == "ambiguous":
            verdict = message or "Неоднозначный результат"
            suspicious = False
        else:
            verdict = message or "Неизвестный результат"
            suspicious = False

        return ScanResult(
            host=target,
            signature=signature,
            verdict=verdict,
            suspicious=suspicious,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Узел №2 — детектор снифферов по подсети (аналог sniffer-detect.nse)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Примеры:
  sudo python3 node2_detector.py 192.168.1.0/24 -i eth0
  sudo python3 node2_detector.py 192.168.100.42/32 -i eth0

Смысл проверки:
  Для каждого живого хоста отправляются ARP-запросы с разными Ethernet
  dst MAC. Полученная сигнатура сравнивается с таблицей из NSE-скрипта.""",
    )
    parser.add_argument(
        "target",
        help="Подсеть или одиночный IPv4-адрес, например 192.168.1.0/24",
    )
    parser.add_argument(
        "-i",
        "--interface",
        default="eth0",
        help="Сетевой интерфейс (по умолчанию: eth0)",
    )
    parser.add_argument(
        "--discovery-timeout",
        type=float,
        default=1.5,
        help="Сколько ждать ARP-ответов на этапе поиска хостов, сек (по умолчанию: 1.5)",
    )
    parser.add_argument(
        "--host-delay",
        type=float,
        default=0.002,
        help="Пауза между ARP-запросами discovery, сек (по умолчанию: 0.002)",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> ipaddress.IPv4Network:
    if os.geteuid() != 0:
        raise DetectorError("Запустите с правами root: sudo python3 node2_detector.py <subnet>")
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


def render_results(
    interface: str,
    local_ip: ipaddress.IPv4Address,
    local_mac: bytes,
    network: ipaddress.IPv4Network,
    discovered: list[HostInfo],
    results: list[ScanResult],
) -> str:
    suspicious = [item for item in results if item.suspicious]
    unknown = [item for item in results if item.verdict == "Неизвестный результат"]
    lines = [
        "=" * 72,
        "    УЗЕЛ №2 — ДЕТЕКТОР СНИФФЕРОВ ПО ПОДСЕТИ",
        "=" * 72,
        "",
        f"  Интерфейс        : {interface}",
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
        lines.append(
            f"  {str(item.host.ip):15}  {item.host.mac_text:17}  "
            f"{item.verdict:42} tests=\"{item.signature}\""
        )

    lines.extend(
        [
            "",
            "-" * 72,
            f"  Подозрительных хостов : {len(suspicious)}",
            f"  Неоднозначных сигнатур: {len(unknown)}",
            "=" * 72,
        ]
    )
    return "\n".join(lines)


def main() -> None:
    args = parse_args()

    try:
        network = validate_args(args)
        scanner = RawArpScanner(args.interface)
    except DetectorError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        if scanner.if_ip not in network:
            raise DetectorError(
                f"IP интерфейса {scanner.if_ip} не входит в подсеть {network.with_prefixlen}"
            )

        discovered = scanner.discover_hosts(
            network,
            per_host_delay=args.host_delay,
            receive_timeout=args.discovery_timeout,
        )
        results = [scanner.fingerprint_host(host) for host in discovered]
        print(
            render_results(
                args.interface,
                scanner.if_ip,
                scanner.if_mac,
                network,
                discovered,
                results,
            )
        )
    except DetectorError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
    finally:
        scanner.close()

    sys.exit(1 if any(item.suspicious for item in results) else 0)


if __name__ == "__main__":
    main()
