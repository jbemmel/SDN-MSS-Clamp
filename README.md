# SDN-MSS-Clamp

A TC (traffic control) eBPF program that clamps the TCP **Maximum Segment Size
(MSS)** option on outgoing SYN/SYN-ACK packets. It rewrites the MSS advertised
during the TCP handshake so that segments fit inside a tunnel's reduced path MTU
(e.g. VXLAN, IPsec, or WireGuard overlays), avoiding fragmentation and PMTUD
black holes.

The program (`ebpf-tunnel-clamp-mss.c`) handles both IPv4 and IPv6 and only
lowers the MSS — it never raises it.

### MTU-aware clamping

Rather than hard-coding a per-tunnel MSS, the program derives the target from
the **egress interface's MTU** at runtime via `bpf_check_mtu()` (Linux 5.12+):

```
target MSS = interface_MTU − IP_header − TCP_header
```

so the correct value is used automatically for whichever tunnel the program is
attached to:

| Interface (example) | L3 MTU | IPv4 MSS | IPv6 MSS |
| ------------------- | ------ | -------- | -------- |
| WireGuard (`wg0`)   | 1420   | 1380     | 1360     |
| VXLAN (`vxlan0`)    | 1450   | 1410     | 1390     |
| Ethernet            | 1500   | 1460     | 1440     |

On kernels older than 5.12 (where `bpf_check_mtu()` is unavailable) it falls
back to the VXLAN-sized defaults `1410` (IPv4) / `1390` (IPv6).

### L2 and L3 interfaces

The program works on both Ethernet-style devices (physical NICs, bridges,
`veth`, VXLAN) **and** pure layer-3 tun devices such as WireGuard, which have no
Ethernet header. It uses `skb->protocol` to identify the L3 type and only skips
a link-layer header when one is actually present.

### VXLAN inner clamping

The program also clamps TCP inside **VXLAN** (RFC 7348). When the outer packet
is UDP to the VXLAN port (4789 IANA / 8472 Linux default) with the VNI flag set,
it descends through the encapsulation —
`outer IP → UDP → VXLAN → inner Ethernet → inner IP → inner TCP` — and clamps the
*inner* SYN's MSS. This is what makes it useful on a **transit / underlay**
device (e.g. attached to `eth0` on a VTEP or transit router) where the TCP flow
is already encapsulated, not just on the tunnel interface itself.

The inner MSS budget subtracts the full stack, so the encapsulated segment still
fits the underlay MTU:

```
inner MSS = underlay_MTU − outer_IP − UDP(8) − VXLAN(8) − inner_Ethernet(14) − inner_IP − TCP
```

For a 1500-byte underlay this yields 1410 (IPv4) / 1390 (IPv6). When VXLAN's
outer UDP checksum is enabled the program repairs it too (a zero/disabled UDP
checksum is left untouched).

> This uses incremental checksum fixups, which are correct for already-formed
> (forwarded) packets. It does not decapsulate GENEVE or GRE — only VXLAN.

The eBPF program is attached at the `tc` **egress** hook and returns
`TC_ACT_OK`, so it never drops traffic.

## Prerequisites

- Docker (used only to compile; no toolchain needed on the host)
- A Linux host with `iproute2` (`tc`) to load the object, kernel 4.5+ for
  `clsact`

## Building

### Option A — bind-mounted build (recommended)

Produces `ebpf-tunnel-clamp-mss.o` directly in the current directory, owned by
your user:

```bash
make            # builds the toolchain image (first run) then compiles
make clean      # removes the .o
```

Internally this builds the Dockerfile `builder` stage (toolchain only) and runs
`clang` against the bind-mounted working directory.

### Option B — self-contained image

Compiles the object inside the image and prints its sections:

```bash
docker build -t ebpf-mss-clamp .
docker run --rm ebpf-mss-clamp          # llvm-objdump -h of the object

# extract the .o from the image if you want it on the host:
id=$(docker create ebpf-mss-clamp)
docker cp "$id":/build/ebpf-tunnel-clamp-mss.o .
docker rm "$id"
```

## Loading the binary

The program lives in the ELF section `tc` and is meant for the egress path via a
`clsact` qdisc. Attach it to the **tunnel interface** (`wg0`, `vxlan0`, ...) so
the MTU lookup and clamp match that tunnel. Replace `wg0` below as appropriate.

The object uses libbpf-style BTF map definitions (`SEC(".maps")`), which
iproute2's built-in ELF loader does **not** understand. Load and pin it with
`bpftool` (libbpf), then attach the pinned program with `tc`:

```bash
# 0. Ensure the bpf filesystem is mounted (usually already is):
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# 1. Load the program + its maps and pin them:
sudo bpftool prog loadall ebpf-tunnel-clamp-mss.o /sys/fs/bpf/mss-clamp \
    type tc pinmaps /sys/fs/bpf/mss-clamp

# 2. Add the clsact qdisc (provides ingress + egress hooks). Safe to re-run.
sudo tc qdisc add dev wg0 clsact

# 3. Attach the pinned program on egress. `direct-action` is required because
#    the program returns TC_ACT_* verdicts directly.
sudo tc filter replace dev wg0 egress \
    bpf direct-action pinned /sys/fs/bpf/mss-clamp/clamp_mss_egress
```

The same object works unchanged on a VXLAN or Ethernet device — just swap the
interface name; the clamp target adapts to that device's MTU.

> The FRR image (see `Dockerfile.frr`) ships a `load-mss-clamp [iface]` helper
> that performs all of the above in one command.

### Verify

```bash
sudo tc filter show dev wg0 egress
sudo tc qdisc show dev wg0
```

Confirm real traffic gets clamped by watching a handshake:

```bash
sudo tcpdump -i wg0 -vvn 'tcp[tcpflags] & tcp-syn != 0' | grep -i mss
```

### Unload

```bash
# Remove just the filter…
sudo tc filter del dev wg0 egress

# …or tear down the whole qdisc (removes all attached filters):
sudo tc qdisc del dev wg0 clsact
```

## Statistics

The program maintains a `BPF_MAP_TYPE_PERCPU_ARRAY` named `mss_stats` that counts
how many packets took each decision branch. This is handy for confirming the
program is attached correctly and for seeing how much traffic actually gets
clamped.

The counters (array index → meaning):

| Idx | Name              | Meaning                                        |
| --- | ----------------- | ---------------------------------------------- |
| 0   | `STAT_TOTAL`      | every packet entering the program              |
| 1   | `STAT_MTU_FALLBACK` | `bpf_check_mtu()` failed → used fallback MSS  |
| 2   | `STAT_L2_HEADER`  | Ethernet header detected and skipped           |
| 3   | `STAT_IPV4`       | parsed as IPv4                                 |
| 4   | `STAT_IPV6`       | parsed as IPv6                                 |
| 5   | `STAT_NON_IP`     | neither IPv4 nor IPv6                          |
| 6   | `STAT_SHORT_L3`   | packet too short for the L3 header             |
| 7   | `STAT_BAD_VERSION`| IP version mismatch (mis-detected offset)      |
| 8   | `STAT_NON_TCP`    | L4 protocol is not TCP                         |
| 9   | `STAT_SHORT_L4`   | packet too short for the TCP header            |
| 10  | `STAT_NON_SYN`    | not a SYN, nothing to clamp                    |
| 11  | `STAT_BAD_TCP_OPTS`| TCP data offset points past the packet        |
| 12  | `STAT_OPT_END`    | reached End-of-Options before finding MSS      |
| 13  | `STAT_OPT_NOOP`   | skipped a No-Op option                         |
| 14  | `STAT_OPT_BAD_LEN`| malformed option length                        |
| 15  | `STAT_MSS_FOUND`  | located a well-formed MSS option               |
| 16  | `STAT_MSS_SHORT`  | MSS option value truncated at packet end       |
| 17  | `STAT_CLAMPED`    | MSS lowered to the target                      |
| 18  | `STAT_ALREADY_OK` | MSS already ≤ target, left unchanged           |
| 19  | `STAT_VXLAN`      | VXLAN frame detected; descended to inner TCP   |

Because it is a per-CPU array, each entry has one value per CPU that must be
summed. `bpftool` does this for you. When loaded as shown above the map is
pinned at `/sys/fs/bpf/mss-clamp/mss_stats`:

```bash
# Dump the counters (each row lists per-CPU values that you sum):
sudo bpftool map dump pinned /sys/fs/bpf/mss-clamp/mss_stats

# Or look it up by name:
sudo bpftool map dump name mss_stats
```

For a friendlier view, `mss-clamp-stats.py` wraps `bpftool`, sums each counter
across all CPUs, and prints an aligned, labelled table:

```bash
sudo ./mss-clamp-stats.py                 # default pinned map
sudo ./mss-clamp-stats.py --name mss_stats
sudo ./mss-clamp-stats.py --watch 1       # refresh once a second
```

```
Idx  Counter            count  Meaning
---  -----------------  -----  -------
  0  STAT_TOTAL         1,204  every packet entering the program
  ...
 17  STAT_CLAMPED           6  MSS lowered to the target
 18  STAT_ALREADY_OK        0  MSS already <= target, left unchanged
```

It only needs Python 3 and `bpftool`.

### Debug tracing

When a clamp happens the program emits a `bpf_printk()` line with the old and
new MSS to the kernel trace pipe. Watch it live with either:

```bash
sudo bpftool prog tracelog
# or the raw pipe:
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

You'll see one line per clamped SYN, e.g.:

```
<idle>-0  [002] ..s.1  1234.567: bpf_trace_printk: mss-clamp: old=1460 new=1410
```

This is a **debug aid only** — `bpf_printk` is slow and system-wide, so remove
the call (in `ebpf-tunnel-clamp-mss.c`) and rebuild before production use. It
requires a `GPL` program license, which this program already declares.

## FRR router image

`Dockerfile.frr` builds a router image based on the latest released
[FRRouting](https://frrouting.org/) image (`quay.io/frrouting/frr`), with
WireGuard tooling and the compiled MSS-clamp plugin baked in.

```bash
# Build (compiles the eBPF object in a builder stage, then layers it onto FRR):
docker build -f Dockerfile.frr -t frr-mss-clamp .

# Pin a different FRR release if desired:
docker build -f Dockerfile.frr --build-arg FRR_VERSION=10.6.1 -t frr-mss-clamp .
```

The image adds:

- `wireguard-tools` (`wg`, `wg-quick`), `bpftool`, and `python3`
- the plugin at `/usr/lib/bpf/ebpf-tunnel-clamp-mss.o`
- a `load-mss-clamp [interface]` helper (defaults to `wg0`, or `$MSS_CLAMP_IFACE`)
- a `mss-clamp-stats` helper that pretty-prints the per-CPU counters

Attaching the clamp needs `NET_ADMIN` and access to the bpf filesystem, so run
the container privileged (or with the appropriate capabilities) and on a network
where the tunnel interface exists:

```bash
docker run --rm -it --privileged --network host frr-mss-clamp
# inside the container, once wg0 exists:
load-mss-clamp wg0
```

FRR's own daemons start via the base image's entrypoint as usual.

## Test topology (netlab)

`topology.yml` is a [netlab](https://netlab.tools) lab that reproduces the
scenario this program targets:

```
h1 --- r1 === WireGuard tunnel === r2 --- h2
      (frr)   OSPF over the tunnel        (frr)
```

Two FRR routers build a WireGuard tunnel (MTU 1440) over a routed underlay and
run OSPF across it; a Linux host hangs off each router. The built-in validation
starts an HTTP server on `h2` and uses `wget` on `h1` to pull an 8 MiB test
file, so the TCP flow crosses the tunnel — where the smaller tunnel MTU makes
MSS clamping relevant.

```bash
netlab up topology.yml       # build + start the lab
netlab validate             # run the OSPF / wget checks

# Load the eBPF clamp on the routers' WireGuard interface, then re-test:
#   (copy ebpf-tunnel-clamp-mss.o onto r1/r2 and attach it on wg egress)
netlab down                 # tear down
```

Requires netlab, containerlab/Docker, and `wireguard-tools` on the netlab host
(tunnel keys are pinned in the topology, so key generation is not needed).

## Files

| File                        | Purpose                                                      |
| --------------------------- | ----------------------------------------------------------- |
| `ebpf-tunnel-clamp-mss.c`   | The eBPF TC program (MSS clamp logic)                       |
| `mss-clamp-stats.py`        | Pretty-prints `mss_stats`, summing counters across all CPUs |
| `Dockerfile`                | Multi-stage: `builder` (toolchain) + `compiled` (in-image)  |
| `Dockerfile.frr`            | Latest FRR + WireGuard + the eBPF plugin + `load-mss-clamp` |
| `Makefile`                  | Host-local build via a bind-mounted current directory       |
| `topology.yml`              | netlab test bed: WireGuard tunnel + Linux hosts (wget test) |
| `ebpf-tunnel-clamp-mss.o`   | Build artifact (generated)                                   |

## Tuning the clamp values

Normally you don't need to: the clamp target follows the egress interface MTU.
To change the MTU of a WireGuard tunnel, set it on the interface itself
(`ip link set wg0 mtu 1420` or the `MTU =` option in the `wg-quick` config) and
the clamp adjusts accordingly.

Only the *fallback* values (used on kernels without `bpf_check_mtu()`, < 5.12)
are compile-time constants at the top of `ebpf-tunnel-clamp-mss.c`:

```c
#define FALLBACK_MSS_IPV4 1410
#define FALLBACK_MSS_IPV6 1390
```
