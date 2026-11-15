"""Features that can be derived from live OpenFlow flow statistics AND exist in UNSW-NB15.

OpenFlow 1.3 flow stats give per-direction counters only (duration, packet_count, byte_count)
plus the match (ip proto). Pairing a flow A->B with its reverse flow B->A gives a bidirectional
record like a UNSW-NB15 row, from which these 11 UNSW columns can be computed with the same
definitions the dataset uses (checked on the CSV: rate = (spkts+dpkts-1)/dur, sload ~= sbytes*8/dur,
smean = sbytes/spkts).

Known mismatch (documented, not hidden): OpenFlow byte_count counts whole Ethernet frames and a
flow entry aggregates every connection between the same two hosts/protocol for its lifetime,
while a UNSW row is one transport connection. The live model is therefore an approximation.

This module is pure Python (no sklearn import) so the controller can use it cheaply.
"""

LIVE_FEATURES = ["proto", "dur", "spkts", "dpkts", "sbytes", "dbytes",
                 "rate", "sload", "dload", "smean", "dmean"]
LIVE_CATEGORICAL = ["proto"]

# IANA protocol number -> UNSW-NB15 'proto' string
IP_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 132: "sctp"}


def proto_name(ip_proto):
    try:
        return IP_PROTO_NAMES.get(int(ip_proto), "unas")
    except (TypeError, ValueError):
        return "unas"


def unsw_features(ip_proto, fwd_dur, fwd_pkts, fwd_bytes, rev_dur=0.0, rev_pkts=0, rev_bytes=0):
    """Build one UNSW-style feature dict from forward (+ optional reverse) OpenFlow counters."""
    dur = max(float(fwd_dur), float(rev_dur))
    spkts, dpkts = int(fwd_pkts), int(rev_pkts)
    sbytes, dbytes = int(fwd_bytes), int(rev_bytes)
    return {
        "proto": proto_name(ip_proto),
        "dur": dur,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": (spkts + dpkts - 1) / dur if dur > 0 and spkts + dpkts > 1 else 0.0,
        "sload": sbytes * 8 / dur if dur > 0 else 0.0,
        "dload": dbytes * 8 / dur if dur > 0 else 0.0,
        "smean": sbytes // spkts if spkts else 0,
        "dmean": dbytes // dpkts if dpkts else 0,
    }
