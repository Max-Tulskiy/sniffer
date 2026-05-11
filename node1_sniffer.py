#!/usr/bin/env python3
"""
Узел №1 — Сетевой сниффер с переключением в неразборчивый режим.

Возможности:
  • перехват всех фреймов через AF_PACKET raw socket
  • включение / выключение promiscuous mode через ioctl
  • разбор Ethernet / IPv4 / TCP / UDP / ICMP / ARP
  • сохранение захваченных пакетов в PCAP-файл (открывается в Wireshark)
  • подробный вывод с hex-дампом payload в режиме -v

Зависимостей нет — только stdlib Python 3.
Требует запуска с правами root.
"""

import socket
import struct
import fcntl
import os
import sys
import signal
import argparse
import time
from datetime import datetime

IFF_PROMISC   = 0x0100
SIOCGIFFLAGS  = 0x8913
SIOCSIFFLAGS  = 0x8914

# ------------------------------------------------------------------ #
#  Запись PCAP                                                        #
# ------------------------------------------------------------------ #

class PcapWriter:
    """Пишет захваченные фреймы в стандартный PCAP-файл (libpcap format).
    Файл можно открыть в Wireshark / tcpdump без дополнительных конвертаций."""

    MAGIC       = 0xa1b2c3d4   # little-endian, точность — микросекунды
    VER_MAJOR   = 2
    VER_MINOR   = 4
    SNAPLEN     = 65535
    LINKTYPE    = 1             # DLT_EN10MB — Ethernet

    def __init__(self, path: str):
        self.path = path
        self._f   = open(path, 'wb')
        self._write_global_header()
        self.count = 0

    def _write_global_header(self):
        # <IHHiIII  — little-endian: magic, ver_maj, ver_min, zone, sigfigs, snaplen, linktype
        self._f.write(struct.pack('<IHHiIII',
                                  self.MAGIC,
                                  self.VER_MAJOR, self.VER_MINOR,
                                  0, 0,
                                  self.SNAPLEN,
                                  self.LINKTYPE))

    def write_packet(self, data: bytes, ts: float):
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        cap_len = min(len(data), self.SNAPLEN)
        # <IIII  — ts_sec, ts_usec, incl_len, orig_len
        self._f.write(struct.pack('<IIII', ts_sec, ts_usec, cap_len, len(data)))
        self._f.write(data[:cap_len])
        self._f.flush()
        self.count += 1

    def close(self):
        self._f.close()


# ------------------------------------------------------------------ #
#  Сниффер                                                            #
# ------------------------------------------------------------------ #

class NetworkSniffer:
    def __init__(self, interface: str, pcap_path: str | None = None,
                 verbose: bool = False):
        self.interface  = interface
        self.verbose    = verbose
        self.sock       = None
        self.running    = False
        self.pkt_count  = 0
        self._pcap      = PcapWriter(pcap_path) if pcap_path else None

    # ------------------------------------------------------------------ #
    #  Promiscuous mode                                                    #
    # ------------------------------------------------------------------ #

    def _set_promiscuous(self, enable: bool) -> bool:
        try:
            ctl   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack('16sh', self.interface.encode(), 0)
            flags = struct.unpack('16sh',
                                  fcntl.ioctl(ctl.fileno(), SIOCGIFFLAGS, ifreq))[1]
            flags = (flags | IFF_PROMISC) if enable else (flags & ~IFF_PROMISC)
            fcntl.ioctl(ctl.fileno(), SIOCSIFFLAGS,
                        struct.pack('16sh', self.interface.encode(), flags))
            ctl.close()
            state = "ВКЛЮЧЁН" if enable else "выключен"
            print(f"[*] Неразборчивый режим {state} ({self.interface})")
            return True
        except PermissionError:
            print("[!] Ошибка: нужен root (sudo)")
            return False
        except OSError as exc:
            print(f"[!] Ошибка ioctl: {exc}")
            return False

    # ------------------------------------------------------------------ #
    #  Разбор заголовков                                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _mac(raw: bytes) -> str:
        return ':'.join(f'{b:02x}' for b in raw)

    def _parse_eth(self, data: bytes):
        dst, src, eth_type = struct.unpack('!6s6sH', data[:14])
        return self._mac(dst), self._mac(src), eth_type, data[14:]

    @staticmethod
    def _parse_ip(data: bytes):
        hdr = struct.unpack('!BBHHHBBH4s4s', data[:20])
        ihl = (hdr[0] & 0xF) * 4
        total_len = hdr[2]
        return (hdr[0] >> 4, ihl, hdr[5], hdr[6],
                socket.inet_ntoa(hdr[8]), socket.inet_ntoa(hdr[9]),
                total_len, data[ihl:])

    @staticmethod
    def _parse_tcp(data: bytes):
        src_p, dst_p = struct.unpack('!HH', data[:4])
        data_offset  = (data[12] >> 4) * 4
        fl = data[13]
        bits = {0x02: 'SYN', 0x10: 'ACK', 0x01: 'FIN',
                0x04: 'RST', 0x08: 'PSH', 0x20: 'URG'}
        flags   = '|'.join(v for k, v in bits.items() if fl & k) or '-'
        payload = data[data_offset:]
        return src_p, dst_p, flags, payload

    @staticmethod
    def _parse_udp(data: bytes):
        src_p, dst_p, length = struct.unpack('!HHH', data[:6])
        return src_p, dst_p, length, data[8:]

    @staticmethod
    def _parse_icmp(data: bytes):
        t, code, _ = struct.unpack('!BBH', data[:4])
        names = {0: 'Echo Reply', 3: 'Dest Unreachable',
                 8: 'Echo Request', 11: 'Time Exceeded'}
        return t, code, names.get(t, f'type={t}'), data[4:]

    @staticmethod
    def _parse_arp(data: bytes):
        fields = struct.unpack('!HHBBH6s4s6s4s', data[:28])
        op  = 'Request' if fields[4] == 1 else 'Reply'
        sma = ':'.join(f'{b:02x}' for b in fields[5])
        sia = socket.inet_ntoa(fields[6])
        tma = ':'.join(f'{b:02x}' for b in fields[7])
        tia = socket.inet_ntoa(fields[8])
        return op, sma, sia, tma, tia

    # ------------------------------------------------------------------ #
    #  Форматирование                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _hexdump(data: bytes, max_bytes: int = 128) -> str:
        """Hex-дамп в стиле Wireshark: offset  hex  ascii."""
        lines = []
        data  = data[:max_bytes]
        for i in range(0, len(data), 16):
            chunk   = data[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"         {i:04x}  {hex_str:<47}  {asc_str}")
        if max_bytes < len(data):
            lines.append(f"         ... (показано {max_bytes} из {len(data)} байт)")
        return '\n'.join(lines)

    # ------------------------------------------------------------------ #
    #  Обработка пакета                                                    #
    # ------------------------------------------------------------------ #

    def _process(self, raw: bytes, ts: float):
        try:
            dt  = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
            dst_mac, src_mac, eth_type, payload = self._parse_eth(raw)
            self.pkt_count += 1
            n = self.pkt_count

            if eth_type == 0x0800:      # IPv4
                _, ihl, ttl, proto, sip, dip, ip_len, ip_payload = self._parse_ip(payload)

                if proto == 6:          # TCP
                    sp, dp, flags, tcp_data = self._parse_tcp(ip_payload)
                    print(f"[{dt}] #{n:5d}  TCP   {sip}:{sp} → {dip}:{dp}"
                          f"  [{flags}]  TTL={ttl}  len={ip_len}")
                    if self.verbose and tcp_data:
                        print(self._hexdump(tcp_data))

                elif proto == 17:       # UDP
                    sp, dp, ln, udp_data = self._parse_udp(ip_payload)
                    print(f"[{dt}] #{n:5d}  UDP   {sip}:{sp} → {dip}:{dp}"
                          f"  len={ln}  TTL={ttl}")
                    if self.verbose and udp_data:
                        print(self._hexdump(udp_data))

                elif proto == 1:        # ICMP
                    _, _, name, icmp_data = self._parse_icmp(ip_payload)
                    print(f"[{dt}] #{n:5d}  ICMP  {sip} → {dip}"
                          f"  [{name}]  TTL={ttl}  len={ip_len}")
                    print(f"         MAC: {src_mac} → {dst_mac}")
                    if self.verbose and icmp_data:
                        print(self._hexdump(icmp_data))

                else:
                    print(f"[{dt}] #{n:5d}  IP    {sip} → {dip}"
                          f"  proto={proto}  TTL={ttl}  len={ip_len}")

            elif eth_type == 0x0806:    # ARP
                op, sma, sia, tma, tia = self._parse_arp(payload)
                print(f"[{dt}] #{n:5d}  ARP   [{op}]  {sia} ({sma}) → {tia} ({tma})")

            elif eth_type == 0x86DD:    # IPv6
                print(f"[{dt}] #{n:5d}  IPv6  {src_mac} → {dst_mac}"
                      f"  len={len(raw)}")

            else:
                print(f"[{dt}] #{n:5d}  ETH   type=0x{eth_type:04x}"
                      f"  {src_mac} → {dst_mac}  len={len(raw)}")

            if self._pcap:
                self._pcap.write_packet(raw, ts)

        except Exception:
            pass  # некорректные фреймы пропускаем

    # ------------------------------------------------------------------ #
    #  Запуск / остановка                                                  #
    # ------------------------------------------------------------------ #

    def start(self, limit: int = 0):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                      socket.htons(0x0003))
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

        print(f"\n[*] Захват трафика на {self.interface}  "
              f"{'(лимит: ' + str(limit) + ' пакетов)' if limit else '(без лимита)'}")
        print("[*] Ctrl+C — остановить\n")
        print("─" * 72)

        self.running = True

        def _stop(sig, frame):
            self.running = False

        signal.signal(signal.SIGINT, _stop)

        try:
            while self.running:
                if limit and self.pkt_count >= limit:
                    print(f"\n[*] Достигнут лимит {limit} пакетов")
                    break
                data = self.sock.recv(65535)
                self._process(data, time.time())
        finally:
            self._shutdown()

    def _shutdown(self):
        self.running = False
        print("\n" + "─" * 72)
        print(f"[*] Остановлено. Захвачено пакетов: {self.pkt_count}")
        if self.sock:
            self.sock.close()
        if self._pcap:
            self._pcap.close()
            print(f"[*] PCAP сохранён: {self._pcap.path}  ({self._pcap.count} пакетов)")
        self._set_promiscuous(False)


# ------------------------------------------------------------------ #
#  main                                                               #
# ------------------------------------------------------------------ #

def _list_interfaces():
    print("[*] Доступные интерфейсы:")
    with open('/proc/net/dev') as f:
        for line in f.readlines()[2:]:
            name = line.split(':')[0].strip()
            if name:
                print(f"    {name}")


def main():
    parser = argparse.ArgumentParser(
        description='Узел №1 — сниффер с неразборчивым режимом',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Примеры:
  sudo python3 node1_sniffer.py -i eth0
  sudo python3 node1_sniffer.py -i eth0 -w capture.pcap
  sudo python3 node1_sniffer.py -i eth0 -w capture.pcap -n 100 -v
  wireshark capture.pcap          # открыть результат в Wireshark""")

    parser.add_argument('-i', '--interface', default='eth0',
                        help='Сетевой интерфейс (по умолчанию: eth0)')
    parser.add_argument('-n', '--count', type=int, default=0,
                        help='Число пакетов для захвата (0 = без лимита)')
    parser.add_argument('-w', '--write', metavar='FILE',
                        help='Сохранить пакеты в PCAP-файл (открывается в Wireshark)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Подробный вывод с hex-дампом payload')
    parser.add_argument('--list', action='store_true',
                        help='Показать доступные интерфейсы и выйти')
    args = parser.parse_args()

    if args.list:
        _list_interfaces()
        return

    if os.geteuid() != 0:
        print("[!] Запустите с правами root:  sudo python3 node1_sniffer.py")
        sys.exit(1)

    print("=" * 72)
    print("       УЗЕЛ №1 — СЕТЕВОЙ СНИФФЕР (НЕРАЗБОРЧИВЫЙ РЕЖИМ)")
    print("=" * 72)

    NetworkSniffer(args.interface,
                   pcap_path=args.write,
                   verbose=args.verbose).start(limit=args.count)


if __name__ == '__main__':
    main()
