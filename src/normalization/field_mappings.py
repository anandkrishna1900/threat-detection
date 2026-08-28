"""Field mapping definitions and schemas for heterogeneous security datasets."""

from __future__ import annotations

from dataclasses import dataclass, field

# Mapping of canonical SecurityEvent fields to lists of known aliases across datasets
DEFAULT_FIELD_ALIASES: dict[str, list[str]] = {
    "timestamp": [
        "timestamp",
        "time",
        "ts",
        "@timestamp",
        "datetime",
        "event_time",
        "start_time",
        "flow_start_time",
        "Date",
        "Time",
        "Timestamp",
    ],
    "source_ip": [
        "source_ip",
        "src_ip",
        "srcip",
        "source_address",
        "source_addr",
        "src_addr",
        "saddr",
        "src",
        "Source IP",
        "id.orig_h",
        "c-ip",
    ],
    "destination_ip": [
        "destination_ip",
        "dst_ip",
        "dstip",
        "destination_address",
        "destination_addr",
        "dst_addr",
        "daddr",
        "dst",
        "Destination IP",
        "id.resp_h",
        "cs-ip",
    ],
    "source_port": [
        "source_port",
        "src_port",
        "sport",
        "srcport",
        "s_port",
        "Source Port",
        "id.orig_p",
        "c-port",
    ],
    "destination_port": [
        "destination_port",
        "dst_port",
        "dsport",
        "dstport",
        "d_port",
        "Destination Port",
        "id.resp_p",
        "cs-port",
    ],
    "protocol": [
        "protocol",
        "proto",
        "prot",
        "Protocol",
        "network_protocol",
        "ip_proto",
    ],
    "bytes_sent": [
        "bytes_sent",
        "bytes_in",
        "sbytes",
        "src_bytes",
        "orig_bytes",
        "out_bytes",
        "Total Length of Fwd Packets",
        "fwd_bytes",
    ],
    "bytes_received": [
        "bytes_received",
        "bytes_out",
        "dbytes",
        "dst_bytes",
        "resp_bytes",
        "in_bytes",
        "Total Length of Bwd Packets",
        "bwd_bytes",
    ],
    "duration": [
        "duration",
        "dur",
        "flow_duration",
        "Flow Duration",
        "session_duration",
        "time_taken",
    ],
    "username": [
        "username",
        "user",
        "user_name",
        "account",
        "account_name",
        "src_user",
        "target_username",
        "User",
        "suser",
    ],
    "hostname": [
        "hostname",
        "host",
        "computer_name",
        "device_name",
        "dst_host",
        "src_host",
        "endpoint",
    ],
    "event_type": [
        "event_type",
        "type",
        "category",
        "event_category",
        "attack_cat",
        "service",
        "proto_service",
    ],
    "action": [
        "action",
        "act",
        "verdict",
        "disposition",
        "event_action",
    ],
    "status": [
        "status",
        "result",
        "outcome",
        "state",
        "event_outcome",
    ],
}


@dataclass
class MappingProfile:
    """Explicit mapping configuration for a known log or dataset schema."""

    name: str
    field_map: dict[str, str] = field(default_factory=dict)
    custom_transforms: dict[str, str] = field(default_factory=dict)


# Predefined mapping profiles for prominent security datasets
PROFILES: dict[str, MappingProfile] = {
    "cic_ids": MappingProfile(
        name="cic_ids",
        field_map={
            "Timestamp": "timestamp",
            "Source IP": "source_ip",
            "Destination IP": "destination_ip",
            "Source Port": "source_port",
            "Destination Port": "destination_port",
            "Protocol": "protocol",
            "Flow Duration": "duration",
            "Total Length of Fwd Packets": "bytes_sent",
            "Total Length of Bwd Packets": "bytes_received",
            "Label": "metadata.label",
        },
    ),
    "unsw_nb15": MappingProfile(
        name="unsw_nb15",
        field_map={
            "srcip": "source_ip",
            "dstip": "destination_ip",
            "sport": "source_port",
            "dsport": "destination_port",
            "proto": "protocol",
            "dur": "duration",
            "sbytes": "bytes_sent",
            "dbytes": "bytes_received",
            "state": "status",
            "attack_cat": "event_type",
            "label": "metadata.label",
        },
    ),
    "zeek_conn": MappingProfile(
        name="zeek_conn",
        field_map={
            "ts": "timestamp",
            "id.orig_h": "source_ip",
            "id.resp_h": "destination_ip",
            "id.orig_p": "source_port",
            "id.resp_p": "destination_port",
            "proto": "protocol",
            "duration": "duration",
            "orig_bytes": "bytes_sent",
            "resp_bytes": "bytes_received",
            "conn_state": "status",
            "service": "event_type",
        },
    ),
}
