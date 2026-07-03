#!/usr/bin/env python3
"""Pretty-print the mss_stats per-CPU counters maintained by the MSS-clamp
eBPF program.

It runs `bpftool map dump ... -j` under the hood, sums each counter across all
CPUs, and prints an aligned table. The map is a BPF_MAP_TYPE_PERCPU_ARRAY, so
every array index carries one value per CPU that has to be added together.

Usage:
    sudo ./mss-clamp-stats.py                       # default pinned map
    sudo ./mss-clamp-stats.py --pin /sys/fs/bpf/mss-clamp/mss_stats
    sudo ./mss-clamp-stats.py --name mss_stats      # look up by name
    sudo ./mss-clamp-stats.py --watch 1             # refresh every second
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time

DEFAULT_PIN = "/sys/fs/bpf/mss-clamp/mss_stats"

# Counter index -> (short name, human-readable description). The order and
# meaning mirror `enum mss_stat` in ebpf-tunnel-clamp-mss.c.
COUNTERS: list[tuple[str, str]] = [
    ("STAT_TOTAL", "every packet entering the program"),
    ("STAT_MTU_FALLBACK", "bpf_check_mtu() failed -> used fallback MSS"),
    ("STAT_L2_HEADER", "Ethernet header detected and skipped"),
    ("STAT_IPV4", "parsed as IPv4"),
    ("STAT_IPV6", "parsed as IPv6"),
    ("STAT_NON_IP", "neither IPv4 nor IPv6"),
    ("STAT_SHORT_L3", "packet too short for the L3 header"),
    ("STAT_BAD_VERSION", "IP version mismatch (mis-detected offset)"),
    ("STAT_NON_TCP", "L4 protocol is not TCP"),
    ("STAT_SHORT_L4", "packet too short for the TCP header"),
    ("STAT_NON_SYN", "not a SYN, nothing to clamp"),
    ("STAT_BAD_TCP_OPTS", "TCP data offset points past the packet"),
    ("STAT_OPT_END", "reached End-of-Options before finding MSS"),
    ("STAT_OPT_NOOP", "skipped a No-Op option"),
    ("STAT_OPT_BAD_LEN", "malformed option length"),
    ("STAT_MSS_FOUND", "located a well-formed MSS option"),
    ("STAT_MSS_SHORT", "MSS option value truncated at packet end"),
    ("STAT_CLAMPED", "MSS lowered to the target"),
    ("STAT_ALREADY_OK", "MSS already <= target, left unchanged"),
    ("STAT_VXLAN", "VXLAN frame detected; descended to the inner TCP"),
]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Summarise the mss_stats per-CPU eBPF counters.",
    )
    target = ap.add_mutually_exclusive_group()
    target.add_argument(
        "--pin",
        default=DEFAULT_PIN,
        help=f"pinned map path (default: {DEFAULT_PIN})",
    )
    target.add_argument(
        "--name",
        help="look the map up by name instead of a pin path",
    )
    ap.add_argument(
        "--watch",
        type=float,
        metavar="SECONDS",
        help="refresh continuously every SECONDS (Ctrl-C to stop)",
    )
    return ap.parse_args()


def bpftool_dump(args: argparse.Namespace) -> list[dict]:
    """Return the raw JSON list produced by `bpftool map dump ... -j`."""
    bpftool = shutil.which("bpftool")
    if bpftool is None:
        sys.exit("error: bpftool not found in PATH")

    if args.name:
        selector = ["name", args.name]
    else:
        selector = ["pinned", args.pin]

    cmd = [bpftool, "-j", "map", "dump", *selector]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or exc.stdout.strip()
        sys.exit(f"error: `{' '.join(cmd)}` failed: {stderr}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        sys.exit(f"error: could not parse bpftool JSON output: {exc}")


def to_int(value: object) -> int:
    """Coerce one bpftool JSON value into an int.

    Depending on the bpftool/libbpf version a value is emitted either as a plain
    integer, a hex string ("0x2a"), or a little-endian list of byte strings
    (["0x2a", "0x00", ...]). Handle all three.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    if isinstance(value, list):
        total = 0
        for i, byte in enumerate(value):
            total |= (to_int(byte) & 0xFF) << (8 * i)
        return total
    raise ValueError(f"unexpected value type: {value!r}")


def sum_percpu(entry: dict) -> int:
    """Sum a single map entry's value across all CPUs."""
    if "values" in entry:  # per-CPU map: list of {"cpu": N, "value": ...}
        return sum(to_int(v["value"]) for v in entry["values"])
    if "value" in entry:  # non per-CPU fallback
        return to_int(entry["value"])
    return 0


def collect(dump: list[dict]) -> dict[int, int]:
    """Map array index -> summed counter."""
    totals: dict[int, int] = {}
    for entry in dump:
        key = to_int(entry.get("key", 0))
        totals[key] = sum_percpu(entry)
    return totals


def render(totals: dict[int, int]) -> str:
    name_w = max(len(name) for name, _ in COUNTERS)
    max_val = max(totals.values(), default=0)
    val_w = max(len(f"{max_val:,}"), len("count"))

    lines = [
        f"{'Idx':>3}  {'Counter':<{name_w}}  {'count':>{val_w}}  Meaning",
        f"{'-' * 3}  {'-' * name_w}  {'-' * val_w}  {'-' * 7}",
    ]
    for idx, (name, desc) in enumerate(COUNTERS):
        count = totals.get(idx, 0)
        lines.append(
            f"{idx:>3}  {name:<{name_w}}  {count:>{val_w},}  {desc}",
        )

    # Flag any indices present in the map but unknown to this script.
    for idx in sorted(k for k in totals if k >= len(COUNTERS)):
        lines.append(
            f"{idx:>3}  {'<unknown>':<{name_w}}  {totals[idx]:>{val_w},}  (index beyond STAT_MAX)",
        )
    return "\n".join(lines)


def main() -> None:
    args = parse_args()

    def show() -> None:
        print(render(collect(bpftool_dump(args))))

    if args.watch is not None:
        try:
            while True:
                print("\033[2J\033[H", end="")  # clear screen, home cursor
                print(time.strftime("%Y-%m-%d %H:%M:%S"))
                show()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            pass
    else:
        show()


if __name__ == "__main__":
    main()
