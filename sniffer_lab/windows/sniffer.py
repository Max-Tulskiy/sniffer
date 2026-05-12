from __future__ import annotations

import signal
import sys

from ..common import PacketPrinter, PcapWriter
from .npcap import NpcapError, PcapHandle, find_devices


def default_interface() -> str | None:
    devices = find_devices()
    for dev in devices:
        if "loopback" not in dev.description.lower() and "loopback" not in dev.name.lower():
            return dev.name
    return devices[0].name if devices else None


def list_interfaces() -> None:
    try:
        devices = find_devices()
    except NpcapError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return
    print("[*] Доступные Npcap-интерфейсы:")
    for idx, dev in enumerate(devices, 1):
        desc = f" - {dev.description}" if dev.description else ""
        print(f"    {idx}. {dev.name}{desc}")


class WindowsSniffer:
    def __init__(self, interface: str, pcap_path: str | None = None, verbose: bool = False):
        self.interface = interface
        self.handle: PcapHandle | None = None
        self.running = False
        self.pkt_count = 0
        self._pcap = PcapWriter(pcap_path) if pcap_path else None
        self._printer = PacketPrinter(verbose=verbose)

    def start(self, limit: int = 0) -> None:
        try:
            self.handle = PcapHandle(self.interface, promisc=True, timeout_ms=10)
        except NpcapError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return

        if self._pcap:
            print(f"[*] Запись в PCAP: {self._pcap.path}")

        print("[*] Npcap открыл интерфейс в promiscuous mode")
        print(f"\n[*] Захват трафика на {self.interface}  {'(лимит: ' + str(limit) + ' пакетов)' if limit else '(без лимита)'}")
        print("[*] Ctrl+C - остановить\n")
        print("-" * 72)

        self.running = True

        def _stop(_sig, _frame):
            self.running = False

        signal.signal(signal.SIGINT, _stop)

        try:
            while self.running:
                if limit and self.pkt_count >= limit:
                    print(f"\n[*] Достигнут лимит {limit} пакетов")
                    break
                packet = self.handle.next_packet()
                if packet is None:
                    continue
                data, ts = packet
                self.pkt_count += 1
                self._printer.process(data, ts, self.pkt_count)
                if self._pcap:
                    self._pcap.write_packet(data, ts)
        except NpcapError as exc:
            print(f"[!] {exc}", file=sys.stderr)
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        self.running = False
        print("\n" + "-" * 72)
        print(f"[*] Остановлено. Захвачено пакетов: {self.pkt_count}")
        if self.handle:
            self.handle.close()
        if self._pcap:
            self._pcap.close()
            print(f"[*] PCAP сохранен: {self._pcap.path}  ({self._pcap.count} пакетов)")


def run(args) -> None:
    try:
        interface = args.interface or default_interface()
    except NpcapError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)
    if not interface:
        print("[!] Npcap-интерфейсы не найдены", file=sys.stderr)
        sys.exit(2)

    print("=" * 72)
    print("       УЗЕЛ №1 - СЕТЕВОЙ СНИФФЕР (WINDOWS/NPCAP)")
    print("=" * 72)
    WindowsSniffer(interface, pcap_path=args.write, verbose=args.verbose).start(limit=args.count)
