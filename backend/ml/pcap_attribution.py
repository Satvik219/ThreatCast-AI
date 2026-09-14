from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import math


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_LIMIT = 20
MAX_LIMIT = 100

# A flow is considered evidence-bearing when its observable
# packet/port/flag indicators produce this score or higher.
#
# IMPORTANT:
# This is NOT a machine-learning probability.
# It is deterministic telemetry evidence scoring.
MIN_FLAG_SCORE = 2.0


# ============================================================
# SCAPY
# ============================================================

def _load_scapy():
    try:
        from scapy.all import (
            IP,
            IPv6,
            TCP,
            UDP,
            PcapReader,
        )

        return {
            "IP": IP,
            "IPv6": IPv6,
            "TCP": TCP,
            "UDP": UDP,
            "PcapReader": PcapReader,
        }

    except ImportError as exc:
        raise RuntimeError(
            "PCAP attribution requires Scapy. "
            "Install it with: pip install scapy"
        ) from exc


# ============================================================
# HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        number = float(value)

        if not math.isfinite(number):
            return default

        return number

    except (TypeError, ValueError):
        return default


def _flag_present(
    flags: Any,
    flag: str,
) -> bool:
    if flags is None:
        return False

    try:
        return flag in flags

    except TypeError:
        return False


def _flow_key(
    packet: dict[str, Any],
) -> tuple[Any, ...]:
    return (
        packet["src_ip"],
        packet["dst_ip"],
        packet["src_port"],
        packet["dst_port"],
        packet["protocol"],
    )


# ============================================================
# PACKET EXTRACTION
# ============================================================

def _extract_packet(
    packet,
    scapy: dict,
) -> dict[str, Any] | None:

    IP = scapy["IP"]
    IPv6 = scapy["IPv6"]
    TCP = scapy["TCP"]
    UDP = scapy["UDP"]

    timestamp = _safe_float(
        getattr(packet, "time", None),
        default=float("nan"),
    )

    if not math.isfinite(timestamp):
        return None

    # --------------------------------------------------------
    # IP / IPv6
    # --------------------------------------------------------

    if packet.haslayer(IP):

        ip_layer = packet[IP]

        src_ip = str(
            getattr(
                ip_layer,
                "src",
                "",
            )
        )

        dst_ip = str(
            getattr(
                ip_layer,
                "dst",
                "",
            )
        )

        protocol_number = int(
            getattr(
                ip_layer,
                "proto",
                0,
            )
        )

        ttl = _safe_float(
            getattr(
                ip_layer,
                "ttl",
                0,
            )
        )

    elif packet.haslayer(IPv6):

        ip_layer = packet[IPv6]

        src_ip = str(
            getattr(
                ip_layer,
                "src",
                "",
            )
        )

        dst_ip = str(
            getattr(
                ip_layer,
                "dst",
                "",
            )
        )

        protocol_number = int(
            getattr(
                ip_layer,
                "nh",
                0,
            )
        )

        ttl = _safe_float(
            getattr(
                ip_layer,
                "hlim",
                0,
            )
        )

    else:
        return None

    # --------------------------------------------------------
    # Packet size
    # --------------------------------------------------------

    try:
        packet_size = int(
            len(packet)
        )

    except Exception:
        packet_size = 0

    # --------------------------------------------------------
    # Transport fields
    # --------------------------------------------------------

    src_port = 0
    dst_port = 0

    syn = False
    ack = False
    rst = False
    fin = False
    psh = False

    tcp_window = 0.0

    if packet.haslayer(TCP):

        tcp = packet[TCP]

        src_port = int(
            getattr(
                tcp,
                "sport",
                0,
            )
        )

        dst_port = int(
            getattr(
                tcp,
                "dport",
                0,
            )
        )

        tcp_window = _safe_float(
            getattr(
                tcp,
                "window",
                0,
            )
        )

        flags = getattr(
            tcp,
            "flags",
            None,
        )

        syn = _flag_present(
            flags,
            "S",
        )

        ack = _flag_present(
            flags,
            "A",
        )

        rst = _flag_present(
            flags,
            "R",
        )

        fin = _flag_present(
            flags,
            "F",
        )

        psh = _flag_present(
            flags,
            "P",
        )

        protocol = "TCP"

    elif packet.haslayer(UDP):

        udp = packet[UDP]

        src_port = int(
            getattr(
                udp,
                "sport",
                0,
            )
        )

        dst_port = int(
            getattr(
                udp,
                "dport",
                0,
            )
        )

        protocol = "UDP"

    else:

        protocol = str(
            protocol_number
        )

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "protocol_number": protocol_number,
        "packet_size": packet_size,
        "ttl": ttl,
        "tcp_window": tcp_window,
        "syn": syn,
        "ack": ack,
        "rst": rst,
        "fin": fin,
        "psh": psh,
    }


# ============================================================
# FLOW CREATION
# ============================================================

def _new_flow(
    packet: dict[str, Any],
) -> dict[str, Any]:

    return {
        "src_ip": packet["src_ip"],
        "dst_ip": packet["dst_ip"],
        "src_port": packet["src_port"],
        "dst_port": packet["dst_port"],
        "protocol": packet["protocol"],
        "protocol_number": packet[
            "protocol_number"
        ],

        "first_seen": packet[
            "timestamp"
        ],

        "last_seen": packet[
            "timestamp"
        ],

        "packet_count": 0,
        "byte_count": 0,

        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "psh_count": 0,
    }


def _update_flow(
    flow: dict[str, Any],
    packet: dict[str, Any],
) -> None:

    timestamp = packet[
        "timestamp"
    ]

    flow["first_seen"] = min(
        flow["first_seen"],
        timestamp,
    )

    flow["last_seen"] = max(
        flow["last_seen"],
        timestamp,
    )

    flow["packet_count"] += 1

    flow["byte_count"] += int(
        packet["packet_size"]
    )

    if packet["syn"]:
        flow["syn_count"] += 1

    if packet["ack"]:
        flow["ack_count"] += 1

    if packet["rst"]:
        flow["rst_count"] += 1

    if packet["fin"]:
        flow["fin_count"] += 1

    if packet["psh"]:
        flow["psh_count"] += 1


# ============================================================
# EVIDENCE SCORING
# ============================================================

def _score_flow(
    flow: dict[str, Any],
    ports_per_source: dict[
        str,
        set[int],
    ],
    destinations_per_source: dict[
        str,
        set[str],
    ],
) -> tuple[float, list[str]]:

    score = 0.0

    reasons: list[str] = []

    src_ip = flow["src_ip"]

    packet_count = int(
        flow["packet_count"]
    )

    syn_count = int(
        flow["syn_count"]
    )

    ack_count = int(
        flow["ack_count"]
    )

    rst_count = int(
        flow["rst_count"]
    )

    unique_ports = len(
        ports_per_source.get(
            src_ip,
            set(),
        )
    )

    unique_destinations = len(
        destinations_per_source.get(
            src_ip,
            set(),
        )
    )

    # --------------------------------------------------------
    # SYN without ACK
    # --------------------------------------------------------

    if (
        syn_count > 0
        and ack_count == 0
    ):

        score += 3.0

        reasons.append(
            "SYN packets without ACK responses"
        )

    # --------------------------------------------------------
    # Destination-port diversity
    # --------------------------------------------------------

    if unique_ports >= 3:

        score += min(
            4.0,
            1.0
            + (
                unique_ports - 3
            ) * 0.5,
        )

        reasons.append(
            f"source contacted "
            f"{unique_ports} distinct "
            f"destination ports"
        )

    # --------------------------------------------------------
    # Destination-IP diversity
    # --------------------------------------------------------

    if unique_destinations >= 3:

        score += min(
            2.0,
            0.5
            + (
                unique_destinations - 3
            ) * 0.25,
        )

        reasons.append(
            f"source contacted "
            f"{unique_destinations} "
            f"destination IPs"
        )

    # --------------------------------------------------------
    # RST
    # --------------------------------------------------------

    if rst_count > 0:

        score += 1.0

        reasons.append(
            f"TCP RST observed "
            f"({rst_count} packets)"
        )

    # --------------------------------------------------------
    # Repeated SYN
    # --------------------------------------------------------

    if syn_count >= 3:

        score += 1.0

        reasons.append(
            f"repeated SYN activity "
            f"({syn_count} packets)"
        )

    # --------------------------------------------------------
    # High SYN ratio
    # --------------------------------------------------------

    if (
        packet_count > 0
        and syn_count >= 2
        and (
            syn_count
            / packet_count
        ) >= 0.5
    ):

        score += 1.0

        reasons.append(
            "high SYN-to-packet ratio"
        )

    return (
        float(score),
        reasons,
    )


# ============================================================
# SERIALIZATION
# ============================================================

def _serialize_flow(
    flow: dict[str, Any],
    score: float,
    reasons: list[str],
) -> dict[str, Any]:

    duration = max(
        0.0,
        float(
            flow["last_seen"]
            - flow["first_seen"]
        ),
    )

    packet_count = int(
        flow["packet_count"]
    )

    syn_count = int(
        flow["syn_count"]
    )

    ack_count = int(
        flow["ack_count"]
    )

    return {
        "src_ip": flow[
            "src_ip"
        ],

        "src_port": int(
            flow["src_port"]
        ),

        "dst_ip": flow[
            "dst_ip"
        ],

        "dst_port": int(
            flow["dst_port"]
        ),

        "protocol": flow[
            "protocol"
        ],

        "protocol_number": int(
            flow["protocol_number"]
        ),

        "first_seen": float(
            flow["first_seen"]
        ),

        "last_seen": float(
            flow["last_seen"]
        ),

        "duration_seconds": float(
            duration
        ),

        "packet_count": packet_count,

        "byte_count": int(
            flow["byte_count"]
        ),

        "tcp_flags": {
            "SYN": syn_count,
            "ACK": ack_count,
            "RST": int(
                flow["rst_count"]
            ),
            "FIN": int(
                flow["fin_count"]
            ),
            "PSH": int(
                flow["psh_count"]
            ),
        },

        "syn_without_ack": bool(
            syn_count > 0
            and ack_count == 0
        ),

        "syn_ratio": float(
            syn_count
            / max(
                1,
                packet_count,
            )
        ),

        "evidence_score": float(
            score
        ),

        "flagged": bool(
            score >= MIN_FLAG_SCORE
        ),

        "evidence_reasons": reasons,
    }


# ============================================================
# MAIN
# ============================================================

def analyze_pcap_attribution(
    path: str | Path,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"PCAP file not found: {path}"
        )

    if path.suffix.lower() not in {
        ".pcap",
        ".pcapng",
        ".cap",
    }:

        raise ValueError(
            "PCAP attribution supports "
            ".pcap, .pcapng, and .cap."
        )

    limit = int(limit)

    if (
        limit < 1
        or limit > MAX_LIMIT
    ):

        raise ValueError(
            f"limit must be between "
            f"1 and {MAX_LIMIT}."
        )

    scapy = _load_scapy()

    PcapReader = scapy[
        "PcapReader"
    ]

    flows: dict[
        tuple[Any, ...],
        dict[str, Any],
    ] = {}

    ports_per_source: dict[
        str,
        set[int],
    ] = defaultdict(set)

    destinations_per_source: dict[
        str,
        set[str],
    ] = defaultdict(set)

    packet_count = 0

    first_timestamp = None
    last_timestamp = None

    # --------------------------------------------------------
    # Read PCAP
    # --------------------------------------------------------

    try:

        with PcapReader(
            str(path)
        ) as reader:

            for packet in reader:

                record = _extract_packet(
                    packet,
                    scapy,
                )

                if record is None:
                    continue

                packet_count += 1

                timestamp = record[
                    "timestamp"
                ]

                if (
                    first_timestamp
                    is None
                ):
                    first_timestamp = timestamp

                last_timestamp = timestamp

                key = _flow_key(
                    record
                )

                if key not in flows:

                    flows[key] = (
                        _new_flow(
                            record
                        )
                    )

                _update_flow(
                    flows[key],
                    record,
                )

                if int(
                    record["dst_port"]
                ) > 0:

                    ports_per_source[
                        record["src_ip"]
                    ].add(
                        int(
                            record[
                                "dst_port"
                            ]
                        )
                    )

                destinations_per_source[
                    record["src_ip"]
                ].add(
                    record["dst_ip"]
                )

    except Exception as exc:

        raise RuntimeError(
            f"Unable to analyze PCAP "
            f"'{path}': {exc}"
        ) from exc

    # --------------------------------------------------------
    # No usable traffic
    # --------------------------------------------------------

    if not flows:

        return {
            "available": False,

            "source": (
                "PCAP packet/flow attribution"
            ),

            "method": (
                "Deterministic packet/flow "
                "evidence attribution"
            ),

            "model_attribution": False,

            "packet_count": 0,

            "flow_count": 0,

            "flagged_flow_count": 0,

            "top_flows": [],

            "flagged_flows": [],

            "note": (
                "No usable IP/IPv6 flows "
                "were found in the PCAP."
            ),
        }

    # --------------------------------------------------------
    # Score every flow
    # --------------------------------------------------------

    serialized_flows = []

    for flow in flows.values():

        score, reasons = (
            _score_flow(
                flow,
                ports_per_source,
                destinations_per_source,
            )
        )

        serialized_flows.append(
            _serialize_flow(
                flow,
                score,
                reasons,
            )
        )

    # --------------------------------------------------------
    # Rank
    # --------------------------------------------------------

    serialized_flows.sort(
        key=lambda item: (
            item["evidence_score"],
            item["packet_count"],
            item["byte_count"],
        ),
        reverse=True,
    )

    flagged_flows = [
        flow
        for flow in serialized_flows
        if flow["flagged"]
    ]

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    duration = 0.0

    if (
        first_timestamp is not None
        and last_timestamp is not None
    ):

        duration = max(
            0.0,
            float(
                last_timestamp
                - first_timestamp
            ),
        )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "available": True,

        "source": (
            "PCAP packet/flow attribution"
        ),

        "method": (
            "Deterministic packet/flow "
            "evidence attribution"
        ),

        "model_attribution": False,

        "packet_count": int(
            packet_count
        ),

        "flow_count": int(
            len(serialized_flows)
        ),

        "flagged_flow_count": int(
            len(flagged_flows)
        ),

        "capture_duration_seconds": (
            float(duration)
        ),

        "first_packet_timestamp": (
            float(first_timestamp)
            if first_timestamp is not None
            else None
        ),

        "last_packet_timestamp": (
            float(last_timestamp)
            if last_timestamp is not None
            else None
        ),

        "top_flows": (
            serialized_flows[:limit]
        ),

        "flagged_flows": (
            flagged_flows[:limit]
        ),

        "scoring": {
            "minimum_flag_score": (
                MIN_FLAG_SCORE
            ),

            "indicators": [
                {
                    "name": (
                        "SYN without ACK"
                    ),
                    "score": 3.0,
                    "meaning": (
                        "SYN activity without "
                        "an observed ACK response "
                        "within the flow."
                    ),
                },

                {
                    "name": (
                        "destination-port diversity"
                    ),
                    "score": (
                        "up to 4.0"
                    ),
                    "meaning": (
                        "A source contacting "
                        "multiple destination ports."
                    ),
                },

                {
                    "name": (
                        "destination-IP diversity"
                    ),
                    "score": (
                        "up to 2.0"
                    ),
                    "meaning": (
                        "A source contacting "
                        "multiple destination IPs."
                    ),
                },

                {
                    "name": (
                        "TCP RST activity"
                    ),
                    "score": 1.0,
                    "meaning": (
                        "TCP reset packets "
                        "were observed."
                    ),
                },

                {
                    "name": (
                        "repeated SYN activity"
                    ),
                    "score": 1.0,
                    "meaning": (
                        "Multiple SYN packets "
                        "occurred in the flow."
                    ),
                },

                {
                    "name": (
                        "high SYN ratio"
                    ),
                    "score": 1.0,
                    "meaning": (
                        "SYN packets form a large "
                        "fraction of the flow."
                    ),
                },
            ],
        },

        "limitations": [
            (
                "This is packet/flow evidence "
                "attribution, not SHAP attribution."
            ),

            (
                "The evidence score is deterministic "
                "and is not a maliciousness probability."
            ),

            (
                "The trained CTU13 world model "
                "continues to use only its existing "
                "12 aggregated input features."
            ),
        ],
    }