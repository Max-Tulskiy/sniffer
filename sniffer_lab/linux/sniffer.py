from __future__ import annotations

import os
import signal
import socket
import struct
import sys
import time

import fcntl

from ..common import PacketPrinter, PcapWriter

IFF_PROMISC = 0x0100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914


class NetworkSniffer:
    def __init__(self, interface: str, pcap_path: str | None = None, verbose: bool = False):
        self.interface = interface
        self.verbose = verbose
        self.sock: socket.socket | None = None
        self.running = False
        self.pkt_count = 0
        self._pcap = PcapWriter(pcap_path) if pcap_path else None
        self._printer = PacketPrinter(verbose=verbose)

    def _set_promiscuous(self, enable: bool) -> bool:
        ctl: socket.socket | None = None
        try:
            ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack("16sh", self.interface.encode(), 0)
            flags = struct.unpack("16sh", fcntl.ioctl(ctl.fileno(), SIOCGIFFLAGS, ifreq))[1]
            flags = (flags | IFF_PROMISC) if enable else (flags & ~IFF_PROMISC)
            fcntl.ioctl(ctl.fileno(), SIOCSIFFLAGS, struct.pack("16sh", self.interface.encode(), flags))
            state = "ВКЛЮЧЕН" if enable else "выключен"
            print(f"[*] Неразборчивый режим {state} ({self.interface})")
            return True
        except PermissionError:
            print("[!] Ошибка: нужен root (sudo)")
            return False
        except OSError as exc:
            print(f"[!] Ошибка ioctl: {exc}")
            return False
        finally:
            if ctl is not None:
                ctl.close()

    def start(self, limit: int = 0) -> None:
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.sock.bind((self.interface, 0))
        except PermissionError:
            print("[!] Ошибка: нужен root (sudo)")
            return
        except OSError as exc:
            print(f"[!] Не удалось открыть сокет: {exc}")
            return

        if not self._set_promiscuous(True):
            self.sock.close()
            return

        if self._pcap:
            print(f"[*] Запись в PCAP: {self._pcap.path}")

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
                data = self.sock.recv(65535)
                ts = time.time()
                self.pkt_count += 1
                self._printer.process(data, ts, self.pkt_count)
                if self._pcap:
                    self._pcap.write_packet(data, ts)
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        self.running = False
        print("\n" + "-" * 72)
        print(f"[*] Остановлено. Захвачено пакетов: {self.pkt_count}")
        if self.sock:
            self.sock.close()
        if self._pcap:
            self._pcap.close()
            print(f"[*] PCAP сохранен: {self._pcap.path}  ({self._pcap.count} пакетов)")
        self._set_promiscuous(False)


def default_interface() -> str:
    return "eth0"


def list_interfaces() -> None:
    print("[*] Доступные интерфейсы:")
    with open("/proc/net/dev", encoding="utf-8") as f:
        for line in f.readlines()[2:]:
            name = line.split(":")[0].strip()
            if name:
                print(f"    {name}")


def run(args) -> None:
    interface = args.interface or default_interface()
    if os.geteuid() != 0:
        print("[!] Запустите с правами root: sudo abks-sniffer sniff -i <iface>")
        sys.exit(1)

    print("=" * 72)
    print("       УЗЕЛ №1 - СЕТЕВОЙ СНИФФЕР (LINUX, PROMISCUOUS MODE)")
    print("=" * 72)
    NetworkSniffer(interface, pcap_path=args.write, verbose=args.verbose).start(limit=args.count)
