from __future__ import annotations

import ctypes
import ctypes.util
import os
import time
from dataclasses import dataclass
from pathlib import Path


PCAP_ERRBUF_SIZE = 256
DLT_EN10MB = 1


class NpcapError(RuntimeError):
    pass


class PcapIf(ctypes.Structure):
    pass


PcapIf._fields_ = [
    ("next", ctypes.POINTER(PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]


class TimeVal(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class PcapPkthdr(ctypes.Structure):
    _fields_ = [("ts", TimeVal), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]


@dataclass
class PcapDevice:
    name: str
    description: str
    flags: int


def _decode(value: bytes | None) -> str:
    if not value:
        return ""
    for encoding in ("mbcs", "utf-8", "cp1251"):
        try:
            return value.decode(encoding)
        except Exception:
            continue
    return value.decode(errors="replace")


def _load_wpcap():
    candidates = []
    found = ctypes.util.find_library("wpcap")
    if found:
        candidates.append(found)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidates.extend(
        [
            str(Path(system_root) / "System32" / "Npcap" / "wpcap.dll"),
            "wpcap.dll",
        ]
    )

    last_error: Exception | None = None
    for candidate in candidates:
        try:
            lib = ctypes.WinDLL(candidate)
            _configure(lib)
            return lib
        except Exception as exc:
            last_error = exc
    raise NpcapError(
        "Не удалось загрузить wpcap.dll. Установите Npcap с опцией WinPcap API-compatible Mode."
    ) from last_error


def _configure(lib) -> None:
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
    lib.pcap_findalldevs.restype = ctypes.c_int
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(PcapIf)]
    lib.pcap_freealldevs.restype = None
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_close.restype = None
    lib.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(PcapPkthdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    lib.pcap_next_ex.restype = ctypes.c_int
    lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.pcap_sendpacket.restype = ctypes.c_int
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_datalink.restype = ctypes.c_int


_LIB = None


def lib():
    global _LIB
    if _LIB is None:
        _LIB = _load_wpcap()
    return _LIB


def find_devices() -> list[PcapDevice]:
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    alldevs = ctypes.POINTER(PcapIf)()
    rc = lib().pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    if rc == -1:
        raise NpcapError(_decode(errbuf.value) or "pcap_findalldevs failed")

    devices: list[PcapDevice] = []
    current = alldevs
    try:
        while current:
            item = current.contents
            devices.append(PcapDevice(_decode(item.name), _decode(item.description), item.flags))
            current = item.next
    finally:
        if alldevs:
            lib().pcap_freealldevs(alldevs)
    return devices


class PcapHandle:
    def __init__(self, device: str, promisc: bool = False, timeout_ms: int = 10):
        self.device = device
        self._handle = None
        errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        raw_device = device.encode("utf-8")
        handle = lib().pcap_open_live(raw_device, 65535, 1 if promisc else 0, timeout_ms, errbuf)
        if not handle:
            raise NpcapError(_decode(errbuf.value) or f"Не удалось открыть интерфейс {device}")
        self._handle = handle
        if lib().pcap_datalink(self._handle) != DLT_EN10MB:
            self.close()
            raise NpcapError("Поддерживаются только Ethernet-интерфейсы (DLT_EN10MB)")

    def close(self) -> None:
        if self._handle:
            lib().pcap_close(self._handle)
            self._handle = None

    def error(self) -> str:
        if not self._handle:
            return ""
        return _decode(lib().pcap_geterr(self._handle))

    def next_packet(self) -> tuple[bytes, float] | None:
        header = ctypes.POINTER(PcapPkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        rc = lib().pcap_next_ex(self._handle, ctypes.byref(header), ctypes.byref(data))
        if rc == 1:
            pkt = ctypes.string_at(data, header.contents.caplen)
            ts = float(header.contents.ts.tv_sec) + float(header.contents.ts.tv_usec) / 1_000_000
            return pkt, ts
        if rc == 0:
            return None
        if rc == -2:
            return None
        raise NpcapError(self.error() or "pcap_next_ex failed")

    def recv_until(self, deadline: float) -> bytes | None:
        while time.monotonic() < deadline:
            packet = self.next_packet()
            if packet is None:
                continue
            return packet[0]
        return None

    def send_packet(self, frame: bytes) -> None:
        buf = ctypes.create_string_buffer(frame)
        rc = lib().pcap_sendpacket(self._handle, ctypes.cast(buf, ctypes.c_void_p), len(frame))
        if rc != 0:
            raise NpcapError(self.error() or "pcap_sendpacket failed")
