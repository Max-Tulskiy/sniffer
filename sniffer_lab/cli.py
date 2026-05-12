from __future__ import annotations

import argparse
import platform
import sys


def _backend():
    system = platform.system().lower()
    if system == "linux":
        from .linux import detector, sniffer

        return sniffer, detector
    if system == "windows":
        from .windows import detector, sniffer

        return sniffer, detector
    print(f"[!] ОС {platform.system()} не поддерживается. Поддерживаются Linux и Windows 10/11.", file=sys.stderr)
    sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abks-sniffer",
        description="Общий CLI для учебного сниффера и детектора снифферов",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sniff = sub.add_parser("sniff", help="Запустить сниффер для текущей ОС")
    sniff.add_argument("-i", "--interface", help="Сетевой интерфейс")
    sniff.add_argument("-n", "--count", type=int, default=0, help="Число пакетов для захвата (0 = без лимита)")
    sniff.add_argument("-w", "--write", metavar="FILE", help="Сохранить пакеты в PCAP-файл")
    sniff.add_argument("-v", "--verbose", action="store_true", help="Подробный вывод с hex-дампом payload")
    sniff.add_argument("--list", action="store_true", help="Показать доступные интерфейсы и выйти")

    detect = sub.add_parser("detect", help="Проверить хосты на признаки promiscuous mode")
    detect.add_argument("target", help="Подсеть или одиночный IPv4-адрес, например 192.168.1.0/24")
    detect.add_argument("-i", "--interface", help="Сетевой интерфейс")
    method = detect.add_mutually_exclusive_group()
    method.add_argument("--arp", dest="method", action="store_const", const="arp", default="arp", help="Использовать ARP-механику детекта")
    method.add_argument("--icmp", dest="method", action="store_const", const="icmp", help="Использовать ICMP Echo-механику детекта")
    detect.add_argument("--discovery-timeout", type=float, default=1.5, help="Сколько ждать ответов на этапе поиска хостов, сек")
    detect.add_argument("--host-delay", type=float, default=0.002, help="Пауза между discovery-запросами, сек")
    detect.add_argument("--local-ip", help="Windows fallback: IPv4 выбранного интерфейса")
    detect.add_argument("--local-mac", help="Windows fallback: MAC выбранного интерфейса")

    sub.add_parser("list", help="Показать доступные интерфейсы для текущей ОС")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    sniffer, detector = _backend()

    if args.command == "list":
        sniffer.list_interfaces()
        return
    if args.command == "sniff":
        if args.list:
            sniffer.list_interfaces()
            return
        sniffer.run(args)
        return
    if args.command == "detect":
        detector.run(args)
        return

    raise SystemExit(2)


if __name__ == "__main__":
    main()
