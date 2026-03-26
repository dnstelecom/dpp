# Encapsulation Conversion Guide

## Goal

This document explains how to convert a capture that contains VLAN, QinQ, MPLS, or similar outer
encapsulation layers into a flat Ethernet plus IPv4 or IPv6 capture that the current community
edition DPP can read directly.

Target output shape:

1. Ethernet
2. IPv4 or IPv6
3. UDP
4. DNS payload

If the input capture already has that shape, no conversion is needed.

## When to Use This Guide

Use this guide when the original capture contains any of the following before the IP header:

- 802.1Q VLAN
- 802.1ad QinQ
- MPLS label stacks
- similar shim layers between Ethernet and IP

Typical symptom:

- DPP runs, but query or response counts are lower than expected because tagged or labeled packets
  are not being extracted by the current fast path.

## Linux Workflow

### 1. Inspect the Capture

Use `tshark` to confirm whether the capture contains VLAN, QinQ, MPLS, or other outer layers.

```bash
tshark -r input.pcap -q -z io,phs
```

If you see protocol hierarchy entries such as `vlan`, `mpls`, or provider-bridging layers before
`ip` or `ipv6`, continue with normalization.

### 2. Install the Required Tools

Install `tshark` and Python support on Linux:

```bash
sudo apt-get update
sudo apt-get install -y tshark python3 python3-pip
python3 -m pip install --user scapy
```

If the capture is `pcapng` and a downstream tool expects classic `pcap`, convert it first:

```bash
editcap -F libpcap input.pcapng input.pcap
```

### 3. Normalize the Capture

Save the following script as `normalize_encapsulation.py`:

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

Run it:

```bash
python3 normalize_encapsulation.py input.pcap normalized.pcap
```

What this does:

- preserves Ethernet source and destination MAC addresses;
- removes outer VLAN, QinQ, and MPLS layers;
- keeps the original packet timestamp;
- writes only packets that resolve cleanly to IPv4 or IPv6 after stripping the outer labels.

What it does **not** do:

- it does not preserve unsupported non-IP payloads after label stripping;
- it does not decode or rewrite DNS contents;
- it does not guarantee support for every possible proprietary shim layer.

### 4. Validate the Result

Check that the normalized capture now has the expected protocol hierarchy:

```bash
tshark -r normalized.pcap -q -z io,phs
```

You should now see the DNS packets under plain IPv4 or IPv6 instead of under outer VLAN or MPLS
labels.

### 5. Run DPP on the Normalized Capture

```bash
target/release/dpp normalized.pcap normalized.csv --format csv
```

Or for Parquet:

```bash
target/release/dpp normalized.pcap normalized.pq --format pq
```

## Optional Shortcut for Simple VLAN-Only Captures

If the capture contains only simple VLAN tagging and you already use `tcprewrite`, you can strip
VLAN tags with a smaller workflow such as:

```bash
tcprewrite --enet-vlan=del --infile=input.pcap --outfile=normalized.pcap
```

That shortcut is convenient, but it is not the preferred general-purpose recipe here because it is
less explicit for mixed or MPLS-tagged captures.

## Validation Checklist

After conversion, validate all of the following:

- the output capture still preserves the expected packet count order and timestamps;
- DPP query and response counts move in the expected direction;
- representative DNS flows that were previously missing are now present;
- repeated DPP runs on the normalized capture remain deterministic.

## Safety Notes

- Keep the original capture unchanged for audit and debugging.
- Do not overwrite the source file in place.
- Treat the normalized capture as derived data from the original packet stream.
- If the conversion script skips too many packets, inspect the protocol hierarchy again; the
  capture may contain an encapsulation layer that is still unsupported by the script.

## If Native Support Is Needed

If normalization is not acceptable operationally and DPP must read those captures directly, native
support should be added only inside:

- [parser.rs](/Users/kam/RustroverProjects/dpp-public/src/dns_processor/parser.rs)

That change must be accompanied by:

- unit tests for every newly supported encapsulation layer;
- determinism checks on representative captures;
- benchmark runs to confirm that plain Ethernet plus IP traffic does not regress materially.
