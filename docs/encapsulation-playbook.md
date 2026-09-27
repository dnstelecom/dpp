# Encapsulation Conversion Guide

Use this guide to convert captures with MPLS or another unsupported outer encapsulation into flat
Ethernet plus IPv4 or IPv6 captures that DPP can read directly.

- [Decide whether conversion is needed](#decide-whether-conversion-is-needed)
- [Convert a capture on Linux](#convert-a-capture-on-linux)
- [Validate the output](#validate-the-output)
- [Add native support](#add-native-support)

## Decide whether conversion is needed

| Capture layers | Action |
| --- | --- |
| Ethernet → IPv4 or IPv6 → UDP → DNS | Read directly; no conversion needed. |
| Ethernet with VLAN or QinQ tags | Read directly; TPIDs `0x8100`, `0x88a8`, and `0x9100` are supported natively. |
| MPLS labels or another unsupported shim between Ethernet and IP | Inspect the capture, then normalize supported labels with the script below. |

A typical symptom of unsupported encapsulation is that DPP runs, but query or response counts are
lower than expected because the current fast path does not extract the labeled packets.

Native VLAN and QinQ handling preserves the complete ordered TPID/VLAN-ID stack in matching and
IPv4 reassembly. Overlapping IP endpoints on different tagged segments remain separate. PCP and
DEI changes do not affect this identity, and exported records do not gain a VLAN column.

> The normalization script removes VLAN and QinQ tags as well as MPLS labels. VLAN or
> provider-bridging layers alone do not require conversion.

## Convert a capture on Linux

Keep the original capture unchanged for audit and debugging. Write to a separate output file and
treat the normalized capture as derived data; do not overwrite the source in place.

### 1. Install the tools

Install `tshark` and Python support:

```bash
sudo apt-get update
sudo apt-get install -y tshark python3 python3-pip
python3 -m pip install --user scapy
```

### 2. Inspect the capture

Use `tshark` to check for VLAN, QinQ, MPLS, or other outer layers:

```bash
tshark -r input.pcap -q -z io,phs
```

If you see `mpls` or another unsupported layer before `ip` or `ipv6`, continue with normalization.
VLAN and provider-bridging layers alone do not require this step.

If the capture is `pcapng` and a downstream tool expects classic `pcap`, convert it first:

```bash
editcap -F libpcap input.pcapng input.pcap
```

### 3. Normalize the capture

The script preserves Ethernet source and destination MAC addresses and packet timestamps. It strips
outer VLAN, QinQ, and MPLS layers, then writes only packets that resolve cleanly to IPv4 or IPv6.

It does not decode or rewrite DNS contents, preserve unsupported non-IP payloads after stripping,
or guarantee support for every proprietary shim layer. If too many packets are skipped, inspect
the protocol hierarchy again for a layer the script cannot handle.

Save the following as `normalize_encapsulation.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import sys

from scapy.all import Ether, IP, IPv6, PcapReader, PcapWriter
from scapy.layers.l2 import Dot1Q

try:
    from scapy.layers.l2 import Dot1AD
except ImportError:
    Dot1AD = None

try:
    from scapy.contrib.mpls import MPLS
except ImportError:
    MPLS = None


def is_vlan_layer(layer) -> bool:
    if Dot1AD is not None and isinstance(layer, Dot1AD):
        return True
    return isinstance(layer, Dot1Q)


def is_mpls_layer(layer) -> bool:
    return MPLS is not None and isinstance(layer, MPLS)


def strip_outer_labels(packet):
    if Ether not in packet:
        return None

    ether = packet[Ether]
    payload = ether.payload

    while payload is not None and (is_vlan_layer(payload) or is_mpls_layer(payload)):
        payload = payload.payload

    if payload is None:
        return None

    if isinstance(payload, IP):
        normalized = Ether(src=ether.src, dst=ether.dst, type=0x0800) / payload.copy()
    elif isinstance(payload, IPv6):
        normalized = Ether(src=ether.src, dst=ether.dst, type=0x86DD) / payload.copy()
    else:
        return None

    normalized.time = packet.time
    return normalized


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: normalize_encapsulation.py <input.pcap> <output.pcap>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    total = 0
    written = 0
    skipped = 0

    with PcapReader(input_path) as reader, PcapWriter(output_path, sync=False) as writer:
        for packet in reader:
            total += 1

            normalized = strip_outer_labels(packet)
            if normalized is None:
                skipped += 1
                continue

            writer.write(normalized)
            written += 1

    print(f"total={total} written={written} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run it with separate input and output paths:

```bash
python3 normalize_encapsulation.py input.pcap normalized.pcap
```

## Validate the output

### 1. Check the protocol hierarchy

```bash
tshark -r normalized.pcap -q -z io,phs
```

DNS packets should now appear under plain IPv4 or IPv6 instead of outer VLAN or MPLS labels.

### 2. Run DPP

For CSV:

```bash
target/release/dpp normalized.pcap normalized.csv --format csv
```

For Parquet:

```bash
target/release/dpp normalized.pcap normalized.pq --format pq
```

### 3. Check the results

- Confirm the expected output packet count, order, and timestamps.
- Check that DPP query and response counts move in the expected direction.
- Inspect representative DNS flows that were previously missing.
- Confirm that repeated DPP runs on the normalized capture remain deterministic.

## Add native support

If normalization is not acceptable operationally, native support belongs in
[`src/dns_processor/parser.rs`](../src/dns_processor/parser.rs) and, for fragmented IPv4,
[`reassembly.rs`](../src/dns_processor/reassembly.rs).

Any such change requires:

- unit tests for every newly supported encapsulation layer;
- determinism checks on representative captures;
- benchmark runs to confirm that plain Ethernet plus IP traffic does not regress materially.
