#!/usr/bin/env python3
"""
Узел №2 — Детектор сниффера в сети.

Методы обнаружения:
  ICMP — отправляем ICMP Echo Request с поддельным MAC-адресом назначения.
         Нормальный NIC отбросит фрейм (MAC не совпадает).
         NIC в promiscuous-режиме передаёт ВСЕ фреймы в ядро,
         и целевой хост отвечает на запрос → сниффер обнаружен.

  ARP  — отправляем ARP Request с поддельным unicast MAC назначения
         (не broadcast). Принцип тот же: только promiscuous NIC
         передаст фрейм ядру, и хост ответит.

Работа без внешних зависимостей (только stdlib Python 3).
Требует запуска с правами root.
"""

import socket
import struct
import fcntl
import os
import sys
import time
import random
import argparse

SIOCGIFADDR = 0x8915


class SnifferDetector:
    # Fake MAC-адрес — unicast, не принадлежит ни одному устройству в сети
    FAKE_MAC = "00:de:ad:be:ef:00"

    def __init__(self, interface: str):
        self.interface = interface
        self.own_ip    = self._get_ip()
        self.own_mac   = self._get_mac()

    # ------------------------------------------------------------------ #
    #  Вспомогательные методы                                             #
    # ------------------------------------------------------------------ #

    def _get_ip(self) -> str | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            res = fcntl.ioctl(s.fileno(), SIOCGIFADDR,
                              struct.pack('256s', self.interface.encode()[:15]))
            s.close()
            return socket.inet_ntoa(res[20:24])
        except Exception:
            return None

    def _get_mac(self) -> str | None:
        try:
            with open(f'/sys/class/net/{self.interface}/address') as f:
                return f.read().strip()
        except Exception:
            return None

    @staticmethod
    def _mac_bytes(mac: str) -> bytes:
        return bytes(int(x, 16) for x in mac.split(':'))

    @staticmethod
    def _checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _raw_sock(self, timeout: float = 3.0) -> socket.socket:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((self.interface, 0))
        s.settimeout(timeout)
        return s

    # ------------------------------------------------------------------ #
    #  ARP-резолюция (чтобы знать реальный MAC цели перед ICMP-тестом)   #
    # ------------------------------------------------------------------ #

    def _resolve_mac(self, target_ip: str, timeout: float = 3.0) -> str | None:
        s = self._raw_sock(timeout)
        try:
            own_mac_b = self._mac_bytes(self.own_mac)
            # Ethernet + ARP
            arp_frame = (
                b'\xff\xff\xff\xff\xff\xff'          # dst: broadcast
                + own_mac_b                           # src
                + struct.pack('!H', 0x0806)           # EtherType ARP
                + struct.pack('!HHBBH',
                              1, 0x0800, 6, 4, 1)    # hw=Eth, proto=IPv4, op=req
                + own_mac_b
                + socket.inet_aton(self.own_ip)
                + b'\x00' * 6
                + socket.inet_aton(target_ip)
            )
            s.send(arp_frame)

            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    pkt = s.recv(65535)
                    if struct.unpack('!H', pkt[12:14])[0] != 0x0806:
                        continue
                    arp = pkt[14:]
                    if struct.unpack('!H', arp[6:8])[0] != 2:   # ARP Reply
                        continue
                    if socket.inet_ntoa(arp[14:18]) == target_ip:
                        return ':'.join(f'{b:02x}' for b in arp[8:14])
                except socket.timeout:
                    break
        finally:
            s.close()
        return None

    # ------------------------------------------------------------------ #
    #  ICMP-метод                                                         #
    # ------------------------------------------------------------------ #

    def _detect_icmp(self, target_ip: str) -> bool:
        print(f"\n  [ICMP] Цель: {target_ip}  |  fake dst MAC: {self.FAKE_MAC}")

        real_mac = self._resolve_mac(target_ip)
        if not real_mac:
            print(f"  [ICMP] Не удалось разрешить MAC для {target_ip} — пропуск")
            return False
        print(f"  [ICMP] Настоящий MAC цели : {real_mac}")
        print(f"  [ICMP] MAC в Ethernet dst : {self.FAKE_MAC}  ← поддельный")

        icmp_id  = random.randint(1, 0xFFFF)
        icmp_seq = 1
        icmp_body = b'DETECT_ICMP_PROBE'
        raw_icmp = struct.pack('!BBHHH', 8, 0, 0, icmp_id, icmp_seq) + icmp_body
        csum = self._checksum(raw_icmp)
        icmp_pkt = struct.pack('!BBHHH', 8, 0, csum, icmp_id, icmp_seq) + icmp_body

        ip_id  = random.randint(1, 0xFFFF)
        ip_len = 20 + len(icmp_pkt)
        ip_src = socket.inet_aton(self.own_ip)
        ip_dst = socket.inet_aton(target_ip)
        ip_hdr_no_cs = struct.pack('!BBHHHBBH4s4s',
                                   0x45, 0, ip_len, ip_id, 0,
                                   64, 1, 0, ip_src, ip_dst)
        ip_cs = self._checksum(ip_hdr_no_cs)
        ip_hdr = struct.pack('!BBHHHBBH4s4s',
                             0x45, 0, ip_len, ip_id, 0,
                             64, 1, ip_cs, ip_src, ip_dst)

        frame = (
            self._mac_bytes(self.FAKE_MAC)     # поддельный dst MAC
            + self._mac_bytes(self.own_mac)
            + struct.pack('!H', 0x0800)
            + ip_hdr + icmp_pkt
        )

        s = self._raw_sock(3.0)
        try:
            s.send(frame)
            print(f"  [ICMP] Запрос отправлен, ожидаем ответ (3 с)...")
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    resp = s.recv(65535)
                    if struct.unpack('!H', resp[12:14])[0] != 0x0800:
                        continue
                    rip = resp[14:]
                    if rip[9] != 1:                         # не ICMP
                        continue
                    if socket.inet_ntoa(rip[12:16]) != target_ip:
                        continue
                    ihl = (rip[0] & 0xF) * 4
                    ricmp = rip[ihl:]
                    if ricmp[0] == 0:                       # Echo Reply
                        rid = struct.unpack('!H', ricmp[4:6])[0]
                        if rid == icmp_id:
                            print(f"  [ICMP] *** ОТВЕТ ПОЛУЧЕН от {target_ip} ***")
                            return True
                except socket.timeout:
                    break
        finally:
            s.close()

        print(f"  [ICMP] Ответа нет — нормальный режим (или хост недоступен)")
        return False

    # ------------------------------------------------------------------ #
    #  ARP-метод                                                          #
    # ------------------------------------------------------------------ #

    def _detect_arp(self, target_ip: str) -> bool:
        print(f"\n  [ARP]  Цель: {target_ip}  |  fake dst MAC: {self.FAKE_MAC}")
        print(f"  [ARP]  MAC в Ethernet dst : {self.FAKE_MAC}  ← поддельный (не broadcast)")

        arp_frame = (
            self._mac_bytes(self.FAKE_MAC)          # поддельный dst MAC
            + self._mac_bytes(self.own_mac)
            + struct.pack('!H', 0x0806)
            + struct.pack('!HHBBH',
                          1, 0x0800, 6, 4, 1)       # ARP Request
            + self._mac_bytes(self.own_mac)
            + socket.inet_aton(self.own_ip)
            + b'\x00' * 6
            + socket.inet_aton(target_ip)
        )

        s = self._raw_sock(3.0)
        try:
            s.send(arp_frame)
            print(f"  [ARP]  Запрос отправлен, ожидаем ответ (3 с)...")
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    resp = s.recv(65535)
                    if struct.unpack('!H', resp[12:14])[0] != 0x0806:
                        continue
                    arp = resp[14:]
                    if struct.unpack('!H', arp[6:8])[0] != 2:   # ARP Reply
                        continue
                    sender_ip  = socket.inet_ntoa(arp[14:18])
                    sender_mac = ':'.join(f'{b:02x}' for b in arp[8:14])
                    if sender_ip == target_ip:
                        print(f"  [ARP]  *** ОТВЕТ ПОЛУЧЕН от {target_ip} ({sender_mac}) ***")
                        return True
                except socket.timeout:
                    break
        finally:
            s.close()

        print(f"  [ARP]  Ответа нет — нормальный режим (или хост недоступен)")
        return False

    # ------------------------------------------------------------------ #
    #  Основная процедура                                                  #
    # ------------------------------------------------------------------ #

    def run(self, target_ip: str, repeat: int = 1) -> bool:
        print(f"\n{'═'*60}")
        print(f"  ПРОВЕРКА ХОСТА: {target_ip}")
        print(f"  Интерфейс : {self.interface}")
        print(f"  Наш IP    : {self.own_ip}")
        print(f"  Наш MAC   : {self.own_mac}")
        print(f"{'═'*60}")
        print()
        print("  Принцип: поддельный MAC назначения → нормальный NIC отбросит")
        print("  фрейм; promiscuous NIC передаст его ядру → хост ответит.")

        icmp_hits = 0
        arp_hits  = 0

        for i in range(repeat):
            if repeat > 1:
                print(f"\n{'─'*40}  попытка {i+1}/{repeat}")
            if self._detect_icmp(target_ip):
                icmp_hits += 1
            time.sleep(0.3)
            if self._detect_arp(target_ip):
                arp_hits += 1

        detected = icmp_hits > 0 or arp_hits > 0

        print(f"\n{'═'*60}")
        print("  ИТОГОВЫЙ РЕЗУЛЬТАТ")
        print(f"{'═'*60}")
        print(f"  Цель      : {target_ip}")
        print(f"  ICMP тест : {'СНИФФЕР ОБНАРУЖЕН' if icmp_hits else 'не обнаружен':30s}"
              f"  ({icmp_hits}/{repeat})")
        print(f"  ARP  тест : {'СНИФФЕР ОБНАРУЖЕН' if arp_hits  else 'не обнаружен':30s}"
              f"  ({arp_hits}/{repeat})")
        print()
        if detected:
            print("  ⚠  ВЫВОД: Сетевой интерфейс хоста находится")
            print(f"            в НЕРАЗБОРЧИВОМ РЕЖИМЕ — на нём работает СНИФФЕР!")
        else:
            print("  ✓  ВЫВОД: Сниффер не обнаружен — интерфейс в нормальном режиме.")
        print(f"{'═'*60}\n")

        return detected


# ------------------------------------------------------------------ #
#  main                                                               #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description='Узел №2 — детектор сетевых снифферов (ICMP + ARP)')
    parser.add_argument('target_ip', help='IP-адрес проверяемого хоста')
    parser.add_argument('-i', '--interface', default='eth0',
                        help='Сетевой интерфейс (по умолчанию: eth0)')
    parser.add_argument('-n', '--repeat', type=int, default=1,
                        help='Число повторений каждого теста (по умолчанию: 1)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] Запустите с правами root:  sudo python3 node2_detector.py <IP>")
        sys.exit(1)

    print("=" * 60)
    print("    УЗЕЛ №2 — ДЕТЕКТОР СЕТЕВЫХ СНИФФЕРОВ  (ICMP + ARP)")
    print("=" * 60)

    det = SnifferDetector(args.interface)
    if not det.own_ip or not det.own_mac:
        print(f"[!] Не удалось получить параметры интерфейса «{args.interface}».")
        print(f"    Проверьте имя интерфейса: ip link show")
        sys.exit(1)

    sys.exit(0 if not det.run(args.target_ip, repeat=args.repeat) else 1)


if __name__ == '__main__':
    main()
