from __future__ import annotations

import socket
import struct
from datetime import datetime


class PcapWriter:
    """Writes captured Ethernet frames to a libpcap file."""

    MAGIC = 0xA1B2C3D4
    VER_MAJOR = 2
    VER_MINOR = 4
    SNAPLEN = 65535
    LINKTYPE = 1

    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "wb")
        self._write_global_header()
        self.count = 0

    def _write_global_header(self) -> None:
        self._f.write(
            struct.pack(
                "<IHHiIII",
                self.MAGIC,
                self.VER_MAJOR,
                self.VER_MINOR,
                0,
                0,
                self.SNAPLEN,
                self.LINKTYPE,
            )
        )

    def write_packet(self, data: bytes, ts: float) -> None:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        cap_len = min(len(data), self.SNAPLEN)
        self._f.write(struct.pack("<IIII", ts_sec, ts_usec, cap_len, len(data)))
        self._f.write(data[:cap_len])
        self._f.flush()
        self.count += 1

    def close(self) -> None:
        self._f.close()


def format_mac(mac: bytes) -> str:
    return ":".join(f"{part:02x}" for part in mac)


def mac_from_text(mac: str) -> bytes:
    normalized = mac.replace("-", ":").lower()
    parts = normalized.split(":")
    if len(parts) != 6:
        raise ValueError("MAC address must contain 6 octets")
    return bytes(int(part, 16) for part in parts)


class PacketPrinter:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    @staticmethod
    def _parse_eth(data: bytes) -> tuple[str, str, int, bytes]:
        dst, src, eth_type = struct.unpack("!6s6sH", data[:14])
        return format_mac(dst), format_mac(src), eth_type, data[14:]

    @staticmethod
    def _parse_ip(data: bytes):
        hdr = struct.unpack("!BBHHHBBH4s4s", data[:20])
        ihl = (hdr[0] & 0xF) * 4
        total_len = hdr[2]
        return (
            hdr[0] >> 4,
            ihl,
            hdr[5],
            hdr[6],
            socket.inet_ntoa(hdr[8]),
            socket.inet_ntoa(hdr[9]),
            total_len,
            data[ihl:],
        )

    @staticmethod
    def _parse_tcp(data: bytes):
        src_p, dst_p = struct.unpack("!HH", data[:4])
        data_offset = (data[12] >> 4) * 4
        fl = data[13]
        bits = {0x02: "SYN", 0x10: "ACK", 0x01: "FIN", 0x04: "RST", 0x08: "PSH", 0x20: "URG"}
        flags = "|".join(v for k, v in bits.items() if fl & k) or "-"
        payload = data[data_offset:]
        return src_p, dst_p, flags, payload

    @staticmethod
    def _parse_udp(data: bytes):
        src_p, dst_p, length = struct.unpack("!HHH", data[:6])
        return src_p, dst_p, length, data[8:]

    @staticmethod
    def _parse_icmp(data: bytes):
        t, code, _ = struct.unpack("!BBH", data[:4])
        names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
        return t, code, names.get(t, f"type={t}"), data[4:]

    @staticmethod
    def _parse_arp(data: bytes):
        fields = struct.unpack("!HHBBH6s4s6s4s", data[:28])
        op = "Request" if fields[4] == 1 else "Reply"
        sma = format_mac(fields[5])
        sia = socket.inet_ntoa(fields[6])
        tma = format_mac(fields[7])
        tia = socket.inet_ntoa(fields[8])
        return op, sma, sia, tma, tia

    @staticmethod
    def _hexdump(data: bytes, max_bytes: int = 128) -> str:
        lines = []
        original_len = len(data)
        data = data[:max_bytes]
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            asc_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"         {i:04x}  {hex_str:<47}  {asc_str}")
        if max_bytes < original_len:
            lines.append(f"         ... (показано {max_bytes} из {original_len} байт)")
        return "\n".join(lines)

    def process(self, raw: bytes, ts: float, number: int) -> None:
        try:
            if len(raw) < 14:
                return
            dt = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
            dst_mac, src_mac, eth_type, payload = self._parse_eth(raw)

            if eth_type == 0x0800 and len(payload) >= 20:
                _, _ihl, ttl, proto, sip, dip, ip_len, ip_payload = self._parse_ip(payload)

                if proto == 6 and len(ip_payload) >= 20:
                    sp, dp, flags, tcp_data = self._parse_tcp(ip_payload)
                    print(f"[{dt}] #{number:5d}  TCP   {sip}:{sp} -> {dip}:{dp}  [{flags}]  TTL={ttl}  len={ip_len}")
                    if self.verbose and tcp_data:
                        print(self._hexdump(tcp_data))
                elif proto == 17 and len(ip_payload) >= 8:
                    sp, dp, ln, udp_data = self._parse_udp(ip_payload)
                    print(f"[{dt}] #{number:5d}  UDP   {sip}:{sp} -> {dip}:{dp}  len={ln}  TTL={ttl}")
                    if self.verbose and udp_data:
                        print(self._hexdump(udp_data))
                elif proto == 1 and len(ip_payload) >= 4:
                    _, _, name, icmp_data = self._parse_icmp(ip_payload)
                    print(f"[{dt}] #{number:5d}  ICMP  {sip} -> {dip}  [{name}]  TTL={ttl}  len={ip_len}")
                    print(f"         MAC: {src_mac} -> {dst_mac}")
                    if self.verbose and icmp_data:
                        print(self._hexdump(icmp_data))
                else:
                    print(f"[{dt}] #{number:5d}  IP    {sip} -> {dip}  proto={proto}  TTL={ttl}  len={ip_len}")

            elif eth_type == 0x0806 and len(payload) >= 28:
                op, sma, sia, tma, tia = self._parse_arp(payload)
                print(f"[{dt}] #{number:5d}  ARP   [{op}]  {sia} ({sma}) -> {tia} ({tma})")

            elif eth_type == 0x86DD:
                print(f"[{dt}] #{number:5d}  IPv6  {src_mac} -> {dst_mac}  len={len(raw)}")

            else:
                print(f"[{dt}] #{number:5d}  ETH   type=0x{eth_type:04x}  {src_mac} -> {dst_mac}  len={len(raw)}")

        except Exception:
            pass
