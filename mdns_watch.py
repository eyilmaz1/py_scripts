from __future__ import annotations

import argparse
import ipaddress
import platform
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Iterable


MDNS_IPV4_GROUP = "224.0.0.251"
MDNS_IPV6_GROUP = "ff02::fb"
MDNS_PORT = 5353
CLASS_MASK = 0x7FFF

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

DEFAULT_QUERIES = (
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_companion-link._tcp.local",
    "_apple-mobdev2._tcp.local",
    "_hap._tcp.local",
    "_homekit._tcp.local",
    "_touch-able._tcp.local",
    "_rdlink._tcp.local",
    "_sleep-proxy._udp.local",
)


@dataclass
class DnsQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    value: object


@dataclass
class Device:
    hostname: str = ""
    ipv4: set[str] = field(default_factory=set)
    ipv6: set[str] = field(default_factory=set)
    mac: str = ""
    services: set[str] = field(default_factory=set)
    queries: set[str] = field(default_factory=set)
    model: str = ""
    last_seen: float = 0.0
    sources: set[str] = field(default_factory=set)


@dataclass
class DisplayDevice:
    hostname: str = ""
    ipv4: set[str] = field(default_factory=set)
    ipv6: set[str] = field(default_factory=set)
    mac: str = ""
    services: set[str] = field(default_factory=set)
    queries: set[str] = field(default_factory=set)
    model: str = ""
    last_seen: float = 0.0
    sources: set[str] = field(default_factory=set)


def read_name(packet: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 20:
        raise ValueError("DNS name compression loop")

    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("DNS name outside packet")

        length = packet[offset]

        if length == 0:
            offset += 1
            break

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            pointed_name, _ = read_name(packet, pointer, depth + 1)
            if pointed_name:
                labels.append(pointed_name.rstrip("."))
            offset += 2
            break

        offset += 1
        label = packet[offset : offset + length].decode("utf-8", "replace")
        labels.append(label)
        offset += length

    return ".".join(part for part in labels if part) + ".", offset


def parse_txt(rdata: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    offset = 0
    while offset < len(rdata):
        length = rdata[offset]
        offset += 1
        item = rdata[offset : offset + length].decode("utf-8", "replace")
        offset += length
        if "=" in item:
            key, value = item.split("=", 1)
            values[key] = value
        elif item:
            values[item] = ""
    return values


def parse_message(packet: bytes) -> tuple[list[DnsQuestion], list[DnsRecord]]:
    if len(packet) < 12:
        return [], []

    _, _, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", packet, 0)
    offset = 12

    try:
        questions: list[DnsQuestion] = []
        for _ in range(qdcount):
            name, offset = read_name(packet, offset)
            qtype, qclass = struct.unpack_from("!HH", packet, offset)
            offset += 4
            questions.append(DnsQuestion(name, qtype, qclass & CLASS_MASK))

        records: list[DnsRecord] = []
        for _ in range(ancount + nscount + arcount):
            name, offset = read_name(packet, offset)
            rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            rdata_start = offset
            rdata = packet[offset : offset + rdlength]
            offset += rdlength

            value: object
            if rtype == TYPE_A and len(rdata) == 4:
                value = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == TYPE_AAAA and len(rdata) == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == TYPE_PTR:
                value, _ = read_name(packet, rdata_start)
            elif rtype == TYPE_SRV and len(rdata) >= 6:
                priority, weight, port = struct.unpack_from("!HHH", rdata, 0)
                target, _ = read_name(packet, rdata_start + 6)
                value = {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                }
            elif rtype == TYPE_TXT:
                value = parse_txt(rdata)
            else:
                value = rdata

            records.append(DnsRecord(name, rtype, rclass & CLASS_MASK, ttl, value))

        return questions, records
    except (struct.error, ValueError):
        return [], []


def encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    encoded = bytearray()
    for part in parts:
        raw = part.encode("utf-8")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {part}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def build_ptr_query(names: Iterable[str]) -> bytes:
    names = tuple(names)
    header = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    questions = bytearray()
    for name in names:
        questions.extend(encode_name(name))
        questions.extend(struct.pack("!HH", TYPE_PTR, 1))
    return header + bytes(questions)


def create_ipv4_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.bind(("", MDNS_PORT))

    membership = socket.inet_aton(MDNS_IPV4_GROUP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    return sock


def create_ipv6_socket() -> socket.socket | None:
    if not socket.has_ipv6:
        return None

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
        sock.bind(("::", MDNS_PORT))

        membership = socket.inet_pton(socket.AF_INET6, MDNS_IPV6_GROUP) + struct.pack("@I", 0)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
        return sock
    except OSError:
        try:
            sock.close()
        except UnboundLocalError:
            pass
        return None


def create_sockets() -> list[socket.socket]:
    sockets = [create_ipv4_socket()]
    ipv6_sock = create_ipv6_socket()
    if ipv6_sock is not None:
        sockets.append(ipv6_sock)
    return sockets


def get_mac_for_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""

    commands = []
    if platform.system() == "Darwin":
        commands.append(("arp", "-n", ip))
    else:
        commands.append(("ip", "neigh", "show", ip))
        commands.append(("arp", "-n", ip))

    for command in commands:
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=1.5,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            continue

        match = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", result.stdout)
        if match:
            return ":".join(part.zfill(2).lower() for part in match.group(1).split(":"))

    return ""


def clean_name(name: str) -> str:
    return name.rstrip(".")


def display_key(device: Device) -> str:
    if device.mac:
        return f"mac:{device.mac}"
    if device.hostname:
        return f"host:{clean_name(device.hostname).lower()}"
    if device.ipv4:
        return f"ipv4:{sorted(device.ipv4)[0]}"
    if device.ipv6:
        return f"ipv6:{sorted(device.ipv6)[0]}"
    return "unknown"


def merge_for_display(devices: Iterable[Device]) -> list[DisplayDevice]:
    rows: dict[str, DisplayDevice] = {}
    aliases: dict[str, str] = {}

    def aliases_for(device: Device) -> set[str]:
        keys = {display_key(device)}
        if device.mac:
            keys.add(f"mac:{device.mac}")
        if device.hostname:
            keys.add(f"host:{clean_name(device.hostname).lower()}")
        keys.update(f"ipv4:{ip}" for ip in device.ipv4)
        keys.update(f"ipv6:{ip}" for ip in device.ipv6)
        return keys

    for device in devices:
        device_aliases = aliases_for(device)
        matching_row_keys = {
            aliases[key] for key in device_aliases if key in aliases and aliases[key] in rows
        }
        row_key = next(iter(matching_row_keys), None)
        if row_key is None:
            row_key = display_key(device)
            rows[row_key] = DisplayDevice()
        else:
            for old_key in matching_row_keys - {row_key}:
                old_row = rows.pop(old_key)
                row = rows[row_key]
                if old_row.hostname and (
                    not row.hostname
                    or len(old_row.hostname) < len(row.hostname)
                ):
                    row.hostname = old_row.hostname
                row.ipv4.update(old_row.ipv4)
                row.ipv6.update(old_row.ipv6)
                row.services.update(old_row.services)
                row.queries.update(old_row.queries)
                row.sources.update(old_row.sources)
                row.mac = row.mac or old_row.mac
                row.model = row.model or old_row.model
                row.last_seen = max(row.last_seen, old_row.last_seen)
                for alias, alias_row_key in list(aliases.items()):
                    if alias_row_key == old_key:
                        aliases[alias] = row_key

        row = rows[row_key]
        if device.hostname and (
            not row.hostname
            or row.hostname == row_key
            or len(device.hostname) < len(row.hostname)
        ):
            row.hostname = device.hostname
        row.ipv4.update(device.ipv4)
        row.ipv6.update(device.ipv6)
        row.services.update(device.services)
        row.queries.update(device.queries)
        row.sources.update(device.sources)
        row.mac = row.mac or device.mac
        row.model = row.model or device.model
        row.last_seen = max(row.last_seen, device.last_seen)

        for alias in device_aliases:
            aliases[alias] = row_key

    return sorted(
        rows.values(),
        key=lambda row: (
            -row.last_seen,
            clean_name(row.hostname).lower(),
            sorted(row.ipv4),
            sorted(row.ipv6),
        ),
    )


def truncate(value: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width == 1:
        return "."
    return value[: width - 1] + "."


def fit_column_widths(headers: list[str], rows: list[list[str]], max_width: int) -> list[int]:
    widths = [
        max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
        for index, header in enumerate(headers)
    ]
    minimums = [len(header) for header in headers]
    separators = 3 * (len(headers) - 1)
    available = max(max_width - separators, sum(minimums))

    while sum(widths) > available:
        candidates = [
            index
            for index, width in enumerate(widths)
            if width > minimums[index]
        ]
        if not candidates:
            break
        widest = max(candidates, key=lambda index: widths[index])
        widths[widest] -= 1

    return widths


def render_table(devices: dict[str, Device]) -> str:
    now = time.time()
    headers = ["Last Seen", "Hostname", "IPv4", "IPv6", "MAC", "Model", "Services", "Queries", "Source"]
    rows: list[list[str]] = []

    for device in merge_for_display(devices.values()):
        rows.append(
            [
                time.strftime("%H:%M:%S", time.localtime(device.last_seen)),
                clean_name(device.hostname) if device.hostname else "(unknown)",
                ", ".join(sorted(device.ipv4)) or "-",
                ", ".join(sorted(device.ipv6)) or "-",
                device.mac or "-",
                device.model or "-",
                ", ".join(sorted(clean_name(service) for service in device.services)) or "-",
                ", ".join(sorted(clean_name(query) for query in device.queries)) or "-",
                ", ".join(sorted(device.sources)) or "-",
            ]
        )

    terminal_width = shutil.get_terminal_size((140, 24)).columns
    widths = fit_column_widths(headers, rows, terminal_width)
    separator = "-+-".join("-" * width for width in widths)

    def format_row(values: list[str]) -> str:
        return " | ".join(
            truncate(value, widths[index]).ljust(widths[index])
            for index, value in enumerate(values)
        )

    lines = [
        "Listening for mDNS on 224.0.0.251/[ff02::fb]:5353. Press Ctrl-C to stop.",
        "MAC addresses come from your ARP/neighbor cache, not from mDNS.",
        f"Devices: {len(rows)}  Updated: {time.strftime('%H:%M:%S', time.localtime(now))}",
        "",
        format_row(headers),
        separator,
    ]
    lines.extend(format_row(row) for row in rows)
    if not rows:
        lines.append("(waiting for devices)")
    return "\n".join(lines)


def print_table(devices: dict[str, Device]) -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")
    print(render_table(devices), flush=True)


def merge_devices(devices: dict[str, Device], target_key: str, source_key: str) -> None:
    if target_key == source_key or source_key not in devices:
        return

    target = devices.setdefault(target_key, Device(hostname=target_key))
    source = devices.pop(source_key)
    if not target.hostname or target.hostname == target_key:
        target.hostname = source.hostname
    target.ipv4.update(source.ipv4)
    target.ipv6.update(source.ipv6)
    target.services.update(source.services)
    target.queries.update(source.queries)
    target.sources.update(source.sources)
    target.mac = target.mac or source.mac
    target.model = target.model or source.model
    target.last_seen = max(target.last_seen, source.last_seen)


def find_device_key(record: DnsRecord, devices: dict[str, Device]) -> str:
    if record.rtype in {TYPE_A, TYPE_AAAA}:
        return clean_name(record.name).lower()

    if record.rtype == TYPE_SRV and isinstance(record.value, dict):
        return clean_name(str(record.value["target"])).lower()

    if record.rtype == TYPE_TXT:
        return clean_name(record.name).lower()

    return clean_name(record.name).lower()


def update_devices(
    devices: dict[str, Device],
    service_types: dict[str, str],
    service_targets: dict[str, str],
    questions: list[DnsQuestion],
    records: list[DnsRecord],
    source_ip: str,
) -> tuple[set[str], set[str]]:
    changed: set[str] = set()
    discovered_services: set[str] = set()
    now = time.time()

    if questions and source_ip not in {"0.0.0.0", "::"}:
        source_key = f"source:{source_ip.lower()}"
        device = devices.setdefault(source_key, Device())
        before = repr(device)
        device.last_seen = now
        device.sources.add(source_ip)
        try:
            ip = ipaddress.ip_address(source_ip.split("%", 1)[0])
            if ip.version == 4:
                device.ipv4.add(str(ip))
                device.mac = device.mac or get_mac_for_ip(str(ip))
            else:
                device.ipv6.add(source_ip)
        except ValueError:
            pass
        device.queries.update(question.name for question in questions)
        if repr(device) != before:
            changed.add(source_key)

    for record in records:
        if record.rtype == TYPE_PTR and isinstance(record.value, str):
            ptr_name = clean_name(record.name)
            ptr_value = clean_name(record.value)
            if ptr_name.lower() == "_services._dns-sd._udp.local":
                discovered_services.add(ptr_value)
            else:
                service_types[ptr_value.lower()] = ptr_name

    for record in records:
        if record.rtype == TYPE_PTR:
            continue

        key = find_device_key(record, devices)
        if record.rtype == TYPE_TXT and key in service_targets:
            host_key = service_targets[key]
        elif record.rtype == TYPE_SRV and isinstance(record.value, dict):
            host_key = clean_name(str(record.value["target"])).lower()
            service_targets[clean_name(record.name).lower()] = host_key
            merge_devices(devices, host_key, key)
        else:
            host_key = key

        device = devices.setdefault(host_key, Device(hostname=host_key))
        before = repr(device)
        device.last_seen = now
        device.sources.add(source_ip)

        if record.rtype == TYPE_A and isinstance(record.value, str):
            device.hostname = clean_name(record.name)
            device.ipv4.add(record.value)
            device.mac = device.mac or get_mac_for_ip(record.value)
        elif record.rtype == TYPE_AAAA and isinstance(record.value, str):
            device.hostname = clean_name(record.name)
            device.ipv6.add(record.value)
        elif record.rtype == TYPE_SRV and isinstance(record.value, dict):
            device.hostname = clean_name(str(record.value["target"]))
            device.services.add(record.name)
        elif record.rtype == TYPE_TXT and isinstance(record.value, dict):
            device.services.add(record.name)
            if key in service_types:
                device.services.add(service_types[key])
            model = record.value.get("model") or record.value.get("am")
            if model:
                device.model = model

        if repr(device) != before:
            changed.add(host_key)

    return changed, discovered_services


def send_query(sock: socket.socket, query: bytes) -> None:
    if sock.family == socket.AF_INET6:
        sock.sendto(query, (MDNS_IPV6_GROUP, MDNS_PORT, 0, 0))
    else:
        sock.sendto(query, (MDNS_IPV4_GROUP, MDNS_PORT))


def recv_source_ip(sock: socket.socket) -> tuple[bytes, str]:
    data, address = sock.recvfrom(9000)
    if sock.family == socket.AF_INET6:
        source_ip = address[0]
        if source_ip.startswith("fe80:") and address[3]:
            source_ip = f"{source_ip}%{address[3]}"
        return data, source_ip
    return data, address[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Listen to mDNS and print discovered hostnames, IPs, MACs, models, and services."
    )
    parser.add_argument(
        "--passive",
        action="store_true",
        help="only listen; do not send periodic mDNS service discovery queries",
    )
    parser.add_argument(
        "--query-interval",
        type=float,
        default=20.0,
        help="seconds between service discovery queries when not passive",
    )
    args = parser.parse_args()

    socks = create_sockets()
    query_names = set(DEFAULT_QUERIES)
    next_query = 0.0
    devices: dict[str, Device] = {}
    service_types: dict[str, str] = {}
    service_targets: dict[str, str] = {}

    print_table(devices)

    try:
        while True:
            now = time.time()
            if not args.passive and now >= next_query:
                query = build_ptr_query(sorted(query_names))
                for sock in socks:
                    send_query(sock, query)
                next_query = now + max(args.query_interval, 1.0)

            timeout = 0.5 if args.passive else max(0.1, min(0.5, next_query - now))
            readable, _, _ = select.select(socks, [], [], timeout)
            if not readable:
                continue

            changed: set[str] = set()
            discovered_services: set[str] = set()
            for sock in readable:
                data, source_ip = recv_source_ip(sock)
                questions, records = parse_message(data)
                packet_changed, packet_services = update_devices(
                    devices,
                    service_types,
                    service_targets,
                    questions,
                    records,
                    source_ip,
                )
                changed.update(packet_changed)
                discovered_services.update(packet_services)

            new_query_names = {
                f"{service}.local" if not service.endswith(".local") else service
                for service in discovered_services
                if service.startswith("_")
            } - query_names
            if new_query_names:
                query_names.update(new_query_names)
                changed.add("queries")

            if changed:
                print_table(devices)
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
