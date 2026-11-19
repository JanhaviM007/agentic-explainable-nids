"""
Mock Alert Generation Script for Agentic Explainable NIDS.

Generates 40+ reproducible, realistic network flow detection alerts covering:
1. Modern stealthy attacks (C2 Beaconing, DNS Tunneling, Lateral Movement, LotL, Encrypted Anomaly).
2. Multi-step attack chains sharing internal host IPs.
3. Baseline attacks (DoS, Brute Force, PortScan, Web Attacks, Botnet).
4. Benign traffic / false-positive looking telemetry.

All alerts conform strictly to the DetectionAlert schema and include ground-truth
expected_techniques and expected_severity for downstream evaluation.
"""

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.schemas import DetectionAlert

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "tests" / "mock_alerts.json"
LABEL_MAPPING_PATH = Path(__file__).resolve().parent.parent / "src" / "mitre" / "label_mapping.json"


def generate_alerts(count: int = 45, seed: int = 42) -> List[Dict[str, Any]]:
    """Generates a reproducible list of realistic detection alerts."""
    random.seed(seed)

    with open(LABEL_MAPPING_PATH, "r", encoding="utf-8") as f:
        label_mapping = json.load(f)

    alerts: List[Dict[str, Any]] = []
    base_time = datetime(2026, 9, 29, 8, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # 1. Multi-Step Attack Chain 1: Compromised Workstation (192.168.1.180)
    # C2 Beaconing -> LotL PowerShell -> Lateral Movement -> DNS Tunneling
    # -------------------------------------------------------------------------
    chain_1_steps = [
        {
            "label": "C2_Beaconing",
            "dst_ip": "185.220.101.5",
            "dst_port": 443,
            "protocol": "TCP",
            "confidence": 0.95,
            "minutes_offset": 5,
            "top_features": [
                {"name": "fwd_iat_mean", "shap_value": 0.48, "value": 30.01, "description": "Rigid 30-second beacon interval"},
                {"name": "flow_duration", "shap_value": 0.35, "value": 120000000.0, "description": "Persistent C2 session"},
                {"name": "flow_bytes_s", "shap_value": 0.22, "value": 15.4, "description": "Low throughput heartbeat polling"}
            ],
            "metadata": {"hostname": "WS-FIN-180", "process_name": "powershell.exe", "beacon_interval_sec": 30.0, "chain_id": "CHAIN-01", "chain_step": 1}
        },
        {
            "label": "LotL_PowerShell",
            "dst_ip": "192.168.1.10",
            "dst_port": 5985,
            "protocol": "TCP",
            "confidence": 0.89,
            "minutes_offset": 18,
            "top_features": [
                {"name": "dst_port", "shap_value": 0.44, "value": 5985, "description": "WinRM remote execution port"},
                {"name": "init_win_bytes_forward", "shap_value": 0.31, "value": 8192, "description": "Remote shell invocation window size"}
            ],
            "metadata": {"hostname": "WS-FIN-180", "process_name": "powershell.exe", "chain_id": "CHAIN-01", "chain_step": 2}
        },
        {
            "label": "Lateral_Movement",
            "dst_ip": "192.168.1.10",
            "dst_port": 445,
            "protocol": "TCP",
            "confidence": 0.92,
            "minutes_offset": 24,
            "top_features": [
                {"name": "dst_port", "shap_value": 0.50, "value": 445, "description": "SMB administrative share IPC$ probe"},
                {"name": "flow_duration", "shap_value": 0.32, "value": 650000.0, "description": "Interactive SMB command session"}
            ],
            "metadata": {"hostname": "WS-FIN-180", "target_hostname": "DC-PRIMARY-01", "chain_id": "CHAIN-01", "chain_step": 3}
        },
        {
            "label": "DNS_Tunneling",
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "confidence": 0.94,
            "minutes_offset": 45,
            "top_features": [
                {"name": "packet_length_mean", "shap_value": 0.55, "value": 490.2, "description": "Excessive TXT DNS query payload length"},
                {"name": "total_fwd_packets", "shap_value": 0.38, "value": 1600, "description": "Volumetric burst of 1600 tunneling requests"}
            ],
            "metadata": {"hostname": "WS-FIN-180", "dns_query_length": 210, "bytes_exfiltrated": 450000, "chain_id": "CHAIN-01", "chain_step": 4}
        }
    ]

    for step in chain_1_steps:
        flow_id = f"FLOW-2026-{len(alerts) + 1:03d}"
        t_info = label_mapping[step["label"]]
        alert_dict = {
            "flow_id": flow_id,
            "timestamp": (base_time + timedelta(minutes=step["minutes_offset"])).isoformat(),
            "src_ip": "192.168.1.180",
            "dst_ip": step["dst_ip"],
            "src_port": random.randint(49152, 65000),
            "dst_port": step["dst_port"],
            "protocol": step["protocol"],
            "predicted_label": step["label"],
            "confidence": step["confidence"],
            "top_features": step["top_features"],
            "metadata": {**step["metadata"], "model_source": "XGBoost-Ensemble-v1"},
            "expected_techniques": t_info["technique_ids"],
            "expected_severity": t_info["default_severity"]
        }
        alerts.append(alert_dict)

    # -------------------------------------------------------------------------
    # 2. Multi-Step Attack Chain 2: DMZ Web Server Breach (10.0.4.77)
    # Web Attack Sql Injection -> LotL WMI -> Encrypted Traffic Anomaly
    # -------------------------------------------------------------------------
    chain_2_steps = [
        {
            "label": "Web Attack Sql Injection",
            "src_ip": "198.51.100.24",
            "dst_ip": "10.0.4.77",
            "dst_port": 443,
            "protocol": "TCP",
            "confidence": 0.91,
            "minutes_offset": 60,
            "top_features": [
                {"name": "fwd_packet_length_mean", "shap_value": 0.45, "value": 680.0, "description": "SQL statement payload in HTTP POST"},
                {"name": "flow_duration", "shap_value": 0.30, "value": 150000.0, "description": "Quick injection response"}
            ],
            "metadata": {"hostname": "WEB-SRV-01", "uri": "/api/v1/login", "chain_id": "CHAIN-02", "chain_step": 1}
        },
        {
            "label": "LotL_WMI",
            "src_ip": "10.0.4.77",
            "dst_ip": "10.0.4.10",
            "dst_port": 135,
            "protocol": "TCP",
            "confidence": 0.88,
            "minutes_offset": 75,
            "top_features": [
                {"name": "dst_port", "shap_value": 0.42, "value": 135, "description": "DCOM/RPC endpoint mapping port"},
                {"name": "flow_duration", "shap_value": 0.28, "value": 420000.0, "description": "Remote WMI invocation"}
            ],
            "metadata": {"hostname": "WEB-SRV-01", "target_hostname": "DB-INTERNAL-01", "chain_id": "CHAIN-02", "chain_step": 2}
        },
        {
            "label": "Encrypted_Traffic_Anomaly",
            "src_ip": "10.0.4.77",
            "dst_ip": "91.108.56.120",
            "dst_port": 8443,
            "protocol": "TCP",
            "confidence": 0.93,
            "minutes_offset": 90,
            "top_features": [
                {"name": "init_win_bytes_backward", "shap_value": 0.46, "value": 256, "description": "Non-standard TLS cipher negotiation"},
                {"name": "flow_duration", "shap_value": 0.34, "value": 85000000.0, "description": "Persistent encrypted tunnel"}
            ],
            "metadata": {"hostname": "WEB-SRV-01", "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1", "chain_id": "CHAIN-02", "chain_step": 3}
        }
    ]

    for step in chain_2_steps:
        flow_id = f"FLOW-2026-{len(alerts) + 1:03d}"
        t_info = label_mapping[step["label"]]
        alert_dict = {
            "flow_id": flow_id,
            "timestamp": (base_time + timedelta(minutes=step["minutes_offset"])).isoformat(),
            "src_ip": step["src_ip"],
            "dst_ip": step["dst_ip"],
            "src_port": random.randint(49152, 65000),
            "dst_port": step["dst_port"],
            "protocol": step["protocol"],
            "predicted_label": step["label"],
            "confidence": step["confidence"],
            "top_features": step["top_features"],
            "metadata": {**step["metadata"], "model_source": "RandomForest-v1"},
            "expected_techniques": t_info["technique_ids"],
            "expected_severity": t_info["default_severity"]
        }
        alerts.append(alert_dict)

    # -------------------------------------------------------------------------
    # 3. Diverse Standalone Alerts (Stealth, Baseline, Benign)
    # -------------------------------------------------------------------------
    stealth_pool = [
        "C2_Beaconing", "DNS_Tunneling", "Lateral_Movement",
        "LotL_PowerShell", "LotL_WMI", "LotL_PsExec", "Encrypted_Traffic_Anomaly"
    ]
    baseline_pool = [
        "PortScan", "DDoS", "DoS Hulk", "DoS GoldenEye",
        "FTP-Patator", "SSH-Patator", "Web Attack Brute Force",
        "Web Attack XSS", "Bot", "Infiltration"
    ]
    benign_pool = ["BENIGN"]

    external_ips = [
        "185.220.101.5", "194.26.29.112", "45.154.255.88", "103.208.220.12",
        "91.108.56.120", "198.51.100.42", "203.0.113.89", "8.8.8.8", "1.1.1.1"
    ]
    internal_ips = [f"192.168.1.{i}" for i in range(20, 90)]

    while len(alerts) < count:
        idx = len(alerts) + 1
        flow_id = f"FLOW-2026-{idx:03d}"
        time_offset = random.randint(100, 1440)
        timestamp = (base_time + timedelta(minutes=time_offset)).isoformat()

        # Distribution: 50% stealth, 30% baseline, 20% benign
        roll = random.random()
        if roll < 0.50:
            label = random.choice(stealth_pool)
            conf = round(random.uniform(0.85, 0.98), 2)
        elif roll < 0.80:
            label = random.choice(baseline_pool)
            conf = round(random.uniform(0.78, 0.95), 2)
        else:
            label = "BENIGN"
            conf = round(random.uniform(0.05, 0.35), 2)

        t_info = label_mapping[label]

        # Port and IP logic based on label
        if label == "DNS_Tunneling":
            dst_port = 53
            protocol = "UDP"
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "194.26.29.112"])
            top_feats = [
                {"name": "packet_length_mean", "shap_value": 0.51, "value": 475.0, "description": "Abnormally large DNS query length"},
                {"name": "total_fwd_packets", "shap_value": 0.36, "value": 1200, "description": "High query frequency"}
            ]
        elif label in ("Lateral_Movement", "LotL_PsExec"):
            dst_port = random.choice([445, 139, 22])
            protocol = "TCP"
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(internal_ips)
            top_feats = [
                {"name": "dst_port", "shap_value": 0.47, "value": dst_port, "description": f"Internal port {dst_port} probe"},
                {"name": "flow_duration", "shap_value": 0.29, "value": 350000.0, "description": "Short burst connection"}
            ]
        elif label == "LotL_PowerShell":
            dst_port = random.choice([5985, 5986, 443])
            protocol = "TCP"
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(internal_ips)
            top_feats = [
                {"name": "flow_duration", "shap_value": 0.40, "value": 450000.0, "description": "PowerShell command execution flow"},
                {"name": "init_win_bytes_forward", "shap_value": 0.28, "value": 8192, "description": "Script window signature"}
            ]
        elif label in ("C2_Beaconing", "Encrypted_Traffic_Anomaly"):
            dst_port = random.choice([443, 8443, 8080])
            protocol = "TCP"
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            top_feats = [
                {"name": "fwd_iat_mean", "shap_value": 0.44, "value": round(random.choice([15.0, 30.0, 60.0]), 2), "description": "Periodic beaconing rhythm"},
                {"name": "flow_duration", "shap_value": 0.32, "value": 90000000.0, "description": "Persistent external channel"}
            ]
        elif label == "PortScan":
            dst_port = random.randint(20, 1024)
            protocol = "TCP"
            src_ip = random.choice(external_ips)
            dst_ip = random.choice(internal_ips)
            top_feats = [
                {"name": "flow_duration", "shap_value": 0.48, "value": 12000.0, "description": "Rapid port sweep"},
                {"name": "packet_length_std", "shap_value": 0.31, "value": 0.0, "description": "Uniform SYN scan packets"}
            ]
        elif label in ("DDoS", "DoS Hulk", "DoS GoldenEye"):
            dst_port = random.choice([80, 443])
            protocol = "TCP"
            src_ip = random.choice(external_ips)
            dst_ip = "192.168.1.100"  # Target server
            top_feats = [
                {"name": "flow_packets_s", "shap_value": 0.58, "value": 45000.0, "description": "Extreme volumetric packet rate"},
                {"name": "flow_bytes_s", "shap_value": 0.39, "value": 12000000.0, "description": "High throughput resource exhaustion"}
            ]
        elif label == "BENIGN":
            dst_port = random.choice([80, 443, 53])
            protocol = "TCP" if dst_port != 53 else "UDP"
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            top_feats = [
                {"name": "flow_duration", "shap_value": -0.42, "value": 15000.0, "description": "Normal human browser transaction"},
                {"name": "fwd_iat_mean", "shap_value": -0.38, "value": 1.25, "description": "Aperiodic human typing/browsing"}
            ]
        else:
            # Baseline brute force / web attacks
            dst_port = random.choice([22, 21, 80, 443])
            protocol = "TCP"
            src_ip = random.choice(external_ips)
            dst_ip = random.choice(internal_ips)
            top_feats = [
                {"name": "flow_duration", "shap_value": 0.38, "value": 50000.0, "description": "Repeated auth attempt"},
                {"name": "dst_port", "shap_value": 0.30, "value": dst_port, "description": "Authentication service port"}
            ]

        alert_dict = {
            "flow_id": flow_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65000),
            "dst_port": dst_port,
            "protocol": protocol,
            "predicted_label": label,
            "confidence": conf,
            "top_features": top_feats,
            "metadata": {
                "hostname": f"HOST-{src_ip.split('.')[-1]}",
                "bytes": random.randint(500, 2500000),
                "duration": random.randint(10000, 60000000),
                "model_source": "EnsembleDetector"
            },
            "expected_techniques": t_info["technique_ids"],
            "expected_severity": t_info["default_severity"]
        }
        alerts.append(alert_dict)

    # Validate all alerts against DetectionAlert schema
    validated_alerts = []
    for item in alerts:
        validated = DetectionAlert(**item)
        validated_alerts.append(validated.model_dump(mode="json"))

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(validated_alerts, f, indent=2)

    return validated_alerts


if __name__ == "__main__":
    result = generate_alerts(count=45, seed=42)
    print(f"Successfully generated {len(result)} mock alerts to {OUTPUT_PATH}")
    labels = {}
    for r in result:
        lbl = r["predicted_label"]
        labels[lbl] = labels.get(lbl, 0) + 1
    print("\nAlert Distribution:")
    for lbl, cnt in sorted(labels.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {lbl}: {cnt}")
