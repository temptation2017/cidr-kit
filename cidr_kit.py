#!/usr/bin/env python3
"""CIDR calculator: info, contains, overlap, split, summarize, exclude."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from typing import Iterable, List, Optional, Sequence, Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Interface = Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]

# Refuse a split that would emit more prefixes than this (avoid huge dumps).
MAX_SPLIT = 4096

# RFC 5737 TEST-NET and RFC 3849 documentation prefixes.
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


class CidrError(Exception):
    """User-facing input or usage error."""


def parse_interface(text: str) -> Interface:
    """Parse an IP or CIDR. Bare addresses become /32 or /128."""
    raw = text.strip()
    if not raw:
        raise CidrError("empty address")
    try:
        if "/" in raw:
            return ipaddress.ip_interface(raw)
        addr = ipaddress.ip_address(raw)
        return ipaddress.ip_interface(f"{addr}/{addr.max_prefixlen}")
    except ValueError as exc:
        raise CidrError(f"invalid address or CIDR: {text}") from exc


def parse_network(text: str) -> Network:
    """Parse an IP or CIDR as a network (host bits are zeroed)."""
    return parse_interface(text).network


def parse_network_list(values: Sequence[str], allow_mixed: bool = False) -> List[Network]:
    nets = [parse_network(v) for v in values]
    if not nets:
        raise CidrError("need at least one CIDR")
    versions = {n.version for n in nets}
    if len(versions) > 1 and not allow_mixed:
        raise CidrError("cannot mix IPv4 and IPv6 in one command")
    return nets


def read_cidr_lines(stream: Iterable[str]) -> List[str]:
    out: List[str] = []
    for line in stream:
        item = line.split("#", 1)[0].strip()
        if item:
            out.append(item)
    return out


def _same_version(a: Network, b: Network) -> None:
    if a.version != b.version:
        raise CidrError("cannot mix IPv4 and IPv6 in one command")


def usable_hosts(net: Network) -> Optional[int]:
    """IPv4 usable host count (RFC 3021 for /31). IPv6 returns None."""
    if net.version != 4:
        return None
    n = net.num_addresses
    if net.prefixlen >= 31:
        return n
    return max(n - 2, 0)


def first_last_host(net: Network) -> tuple[Optional[str], Optional[str]]:
    if net.version == 4:
        if net.prefixlen >= 31:
            hosts = list(net)
            return str(hosts[0]), str(hosts[-1])
        return str(net.network_address + 1), str(net.broadcast_address - 1)
    # IPv6: no broadcast; show first and last address in the prefix.
    return str(net.network_address), str(net.broadcast_address)


def is_documentation(net: Network) -> bool:
    for doc in _DOC_NETS:
        if net.version == doc.version and net.subnet_of(doc):
            return True
    return False


def network_flags(net: Network) -> dict:
    keys = (
        "is_private",
        "is_global",
        "is_multicast",
        "is_loopback",
        "is_link_local",
        "is_reserved",
        "is_unspecified",
    )
    flags = {"is_documentation": is_documentation(net)}
    for key in keys:
        if hasattr(net, key):
            try:
                flags[key] = bool(getattr(net, key))
            except ValueError:
                flags[key] = False
    return flags


def info_data(text: str) -> dict:
    iface = parse_interface(text)
    net = iface.network
    first, last = first_last_host(net)
    usable = usable_hosts(net)
    data = {
        "input": text.strip(),
        "version": net.version,
        "address": str(iface.ip),
        "cidr": str(net),
        "network": str(net.network_address),
        "prefixlen": net.prefixlen,
        "num_addresses": net.num_addresses,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "first_host": first,
        "last_host": last,
        "usable_hosts": usable,
        "reverse_pointer": iface.ip.reverse_pointer,
        "host_bits_set": iface.ip != net.network_address,
    }
    if net.version == 4:
        data["broadcast"] = str(net.broadcast_address)
    else:
        data["last_address"] = str(net.broadcast_address)
    data.update(network_flags(net))
    return data


def format_info(data: dict) -> str:
    rows = [
        ("Input", data["input"]),
        ("Family", f"IPv{data['version']}"),
        ("Address", data["address"]),
        ("CIDR", data["cidr"]),
        ("Network", data["network"]),
        ("Prefix length", str(data["prefixlen"])),
        ("Netmask", data["netmask"]),
        ("Wildcard", data["wildcard"]),
    ]
    if "broadcast" in data:
        rows.append(("Broadcast", data["broadcast"]))
    else:
        rows.append(("Last address", data["last_address"]))
    rows.extend(
        [
            ("First host", data["first_host"] or "-"),
            ("Last host", data["last_host"] or "-"),
            ("Total addresses", str(data["num_addresses"])),
        ]
    )
    if data["usable_hosts"] is not None:
        rows.append(("Usable hosts", str(data["usable_hosts"])))
    rows.append(("PTR", data["reverse_pointer"]))
    flags = []
    for key, label in (
        ("is_private", "private"),
        ("is_global", "global"),
        ("is_documentation", "documentation"),
        ("is_multicast", "multicast"),
        ("is_loopback", "loopback"),
        ("is_link_local", "link-local"),
        ("is_reserved", "reserved"),
        ("is_unspecified", "unspecified"),
    ):
        if data.get(key):
            flags.append(label)
    rows.append(("Flags", ", ".join(flags) if flags else "-"))
    if data.get("host_bits_set"):
        rows.append(("Note", "input had host bits set; CIDR is the covering network"))
    width = max(len(k) for k, _ in rows)
    return "\n".join(f"{k + ':':<{width + 1}}  {v}" for k, v in rows)


def contains(network: Network, other: Network) -> bool:
    _same_version(network, other)
    return other.subnet_of(network)


def overlaps(a: Network, b: Network) -> bool:
    _same_version(a, b)
    return a.overlaps(b)


def split_network(network: Network, new_prefix: int) -> List[Network]:
    if new_prefix == network.prefixlen:
        return [network]
    if new_prefix < network.prefixlen:
        raise CidrError(
            f"new prefix /{new_prefix} is shorter than /{network.prefixlen}; "
            "use a longer (more specific) prefix"
        )
    max_len = network.network_address.max_prefixlen
    if new_prefix > max_len:
        raise CidrError(f"prefix /{new_prefix} is longer than /{max_len}")
    count = 1 << (new_prefix - network.prefixlen)
    if count > MAX_SPLIT:
        raise CidrError(
            f"split would emit {count} prefixes (cap is {MAX_SPLIT}); "
            "pick a shorter new prefix"
        )
    return list(network.subnets(new_prefix=new_prefix))


def summarize(networks: Sequence[Network]) -> List[Network]:
    if not networks:
        raise CidrError("need at least one CIDR")
    # collapse_addresses cannot mix families; do each family, IPv4 first.
    out: List[Network] = []
    for version in (4, 6):
        group = [n for n in networks if n.version == version]
        if group:
            out.extend(ipaddress.collapse_addresses(group))
    return out


def exclude(network: Network, holes: Sequence[Network]) -> List[Network]:
    remaining: List[Network] = [network]
    for hole in holes:
        _same_version(network, hole)
        next_remaining: List[Network] = []
        for piece in remaining:
            next_remaining.extend(_punch(piece, hole))
        remaining = next_remaining
    return remaining


def _punch(network: Network, hole: Network) -> List[Network]:
    if not network.overlaps(hole):
        return [network]
    if network.subnet_of(hole):
        return []
    # hole is a subnet of network (CIDR overlap implies containment).
    if hole == network:
        return []
    out: List[Network] = []
    for part in network.subnets(prefixlen_diff=1):
        out.extend(_punch(part, hole))
    return out


def emit_json(obj) -> None:
    json.dump(obj, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def emit_networks(nets: Sequence[Network], as_json: bool) -> None:
    if as_json:
        emit_json([str(n) for n in nets])
        return
    for n in nets:
        print(n)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cidr-kit",
        description="CIDR calculator for IPv4 and IPv6 (stdlib only).",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="show network, mask, hosts, and flags")
    p_info.add_argument("target", help="IP or CIDR, e.g. 192.0.2.15 or 2001:db8::/32")

    p_contains = sub.add_parser("contains", help="does NETWORK contain OTHER? exit 1 if not")
    p_contains.add_argument("network", help="covering CIDR")
    p_contains.add_argument("other", help="IP or CIDR to test")

    p_overlap = sub.add_parser("overlap", help="do A and B overlap? exit 1 if not")
    p_overlap.add_argument("a")
    p_overlap.add_argument("b")

    p_split = sub.add_parser("split", help="split a CIDR into longer prefixes")
    p_split.add_argument("network")
    p_split.add_argument("prefix", type=int, help="new prefix length, e.g. 26")

    p_sum = sub.add_parser("summarize", help="collapse adjacent or overlapping CIDRs")
    p_sum.add_argument(
        "networks",
        nargs="*",
        help="CIDRs; omit and pass --file or stdin (one per line)",
    )
    p_sum.add_argument(
        "-f",
        "--file",
        help="read CIDRs from a file (or - for stdin); # comments allowed",
    )

    p_ex = sub.add_parser("exclude", help="subtract one or more CIDRs from a network")
    p_ex.add_argument("network")
    p_ex.add_argument("holes", nargs="+", help="CIDRs to punch out")

    return parser


def cmd_summarize_args(args: argparse.Namespace) -> List[Network]:
    texts: List[str] = list(args.networks)
    if args.file:
        if args.file == "-":
            texts.extend(read_cidr_lines(sys.stdin))
        else:
            try:
                with open(args.file, encoding="utf-8") as fh:
                    texts.extend(read_cidr_lines(fh))
            except OSError as exc:
                raise CidrError(f"cannot read {args.file}: {exc}") from exc
    elif not texts and not sys.stdin.isatty():
        texts.extend(read_cidr_lines(sys.stdin))
    if not texts:
        raise CidrError("summarize needs CIDRs as arguments, --file, or stdin")
    return parse_network_list(texts, allow_mixed=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    as_json = bool(args.json)
    try:
        if args.cmd == "info":
            data = info_data(args.target)
            if as_json:
                emit_json(data)
            else:
                print(format_info(data))
            return 0

        if args.cmd == "contains":
            net = parse_network(args.network)
            other = parse_network(args.other)
            ok = contains(net, other)
            if as_json:
                emit_json(
                    {
                        "contains": ok,
                        "network": str(net),
                        "other": str(other),
                    }
                )
            else:
                print("yes" if ok else "no")
            return 0 if ok else 1

        if args.cmd == "overlap":
            a = parse_network(args.a)
            b = parse_network(args.b)
            ok = overlaps(a, b)
            if as_json:
                emit_json({"overlaps": ok, "a": str(a), "b": str(b)})
            else:
                print("yes" if ok else "no")
            return 0 if ok else 1

        if args.cmd == "split":
            nets = split_network(parse_network(args.network), args.prefix)
            emit_networks(nets, as_json)
            return 0

        if args.cmd == "summarize":
            nets = summarize(cmd_summarize_args(args))
            emit_networks(nets, as_json)
            return 0

        if args.cmd == "exclude":
            nets = exclude(parse_network(args.network), [parse_network(h) for h in args.holes])
            emit_networks(nets, as_json)
            return 0

        parser.error(f"unknown command: {args.cmd}")
    except CidrError as exc:
        print(f"cidr-kit: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
