"""
Unit and Integration Tests for Phase 1: Decoupling from ML Model.
"""

import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.api.schemas import AlertInput, DetectionAlert, FeatureContribution
from src.detector import MockDetector, SklearnModelDetector, get_detector
from src.mitre.service import MitreAttackService

client = TestClient(app)

MOCK_ALERTS_PATH = Path(__file__).resolve().parent / "mock_alerts.json"
LABEL_MAPPING_PATH = Path(__file__).resolve().parent.parent / "src" / "mitre" / "label_mapping.json"


# ============================================================================
# 1. DetectionAlert Schema & Validator Tests
# ============================================================================

def test_detection_alert_valid():
    """Verify that a properly constructed DetectionAlert validates successfully."""
    alert = DetectionAlert(
        flow_id="FLOW-TEST-001",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=49152,
        dst_port=443,
        protocol="TCP",
        predicted_label="C2_Beaconing",
        confidence=0.92,
        top_features=[FeatureContribution(name="fwd_iat_mean", shap_value=0.45, value=30.0)],
        metadata={"hostname": "WS-TEST"}
    )
    assert alert.flow_id == "FLOW-TEST-001"
    assert alert.src_port == 49152
    assert alert.confidence == 0.92


def test_detection_alert_ipv6_valid():
    """Verify that IPv6 addresses are accepted."""
    alert = DetectionAlert(
        flow_id="FLOW-TEST-002",
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        src_port=53,
        dst_port=53,
        protocol="UDP",
        predicted_label="DNS_Tunneling",
        confidence=0.85
    )
    assert alert.src_ip == "2001:db8::1"


def test_detection_alert_invalid_ip():
    """Verify that invalid IP addresses are rejected with ValueError."""
    with pytest.raises(ValueError, match="Invalid IPv4/IPv6 address"):
        DetectionAlert(
            flow_id="FLOW-FAIL",
            src_ip="999.999.999.999",
            dst_ip="10.0.0.1",
            src_port=1000,
            dst_port=80,
            predicted_label="C2_Beaconing",
            confidence=0.9
        )


def test_detection_alert_invalid_port():
    """Verify that out-of-range ports are rejected."""
    with pytest.raises(ValueError):
        DetectionAlert(
            flow_id="FLOW-FAIL",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=70000,
            dst_port=80,
            predicted_label="C2_Beaconing",
            confidence=0.9
        )


def test_detection_alert_invalid_confidence():
    """Verify that confidence out of [0.0, 1.0] is rejected."""
    with pytest.raises(ValueError):
        DetectionAlert(
            flow_id="FLOW-FAIL",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=80,
            predicted_label="C2_Beaconing",
            confidence=1.5
        )


def test_detection_alert_bidirectional_conversion():
    """Verify bidirectional conversion between DetectionAlert and legacy AlertInput."""
    alert = DetectionAlert(
        flow_id="FLOW-CONV",
        src_ip="192.168.1.42",
        dst_ip="192.168.1.10",
        src_port=50000,
        dst_port=445,
        protocol="TCP",
        predicted_label="Lateral_Movement",
        confidence=0.88,
        top_features=[FeatureContribution(name="dst_port", shap_value=0.48, value=445)],
        metadata={"hostname": "WS-01", "model_source": "TestModel"}
    )
    # Convert to legacy
    legacy = alert.to_alert_input()
    assert isinstance(legacy, AlertInput)
    assert legacy.alert_id == "FLOW-CONV"
    assert legacy.network_metadata.src_ip == "192.168.1.42"
    assert legacy.detected_attack == "Lateral_Movement"
    assert legacy.shap_explanations[0].feature_name == "dst_port"

    # Convert back to DetectionAlert
    reconstructed = legacy.to_detection_alert()
    assert isinstance(reconstructed, DetectionAlert)
    assert reconstructed.flow_id == "FLOW-CONV"
    assert reconstructed.src_ip == "192.168.1.42"
    assert reconstructed.top_features[0].name == "dst_port"


# ============================================================================
# 2. Detector Adapter Tests
# ============================================================================

def test_mock_detector_load_and_replay():
    """Verify MockDetector loads fixture alerts and replays them correctly."""
    detector = MockDetector(MOCK_ALERTS_PATH)
    assert len(detector.alerts) >= 40

    # Specific flow_id lookup
    target_flow = detector.alerts[0].flow_id
    alert = detector.detect({"flow_id": target_flow})
    assert alert.flow_id == target_flow

    # Specific label lookup
    dns_alert = detector.detect({"predicted_label": "DNS_Tunneling"})
    assert dns_alert.predicted_label == "DNS_Tunneling"


def test_sklearn_detector_missing_model_raises_clear_error():
    """Verify SklearnModelDetector raises explicit FileNotFoundError when model path is missing."""
    with pytest.raises(FileNotFoundError, match="Student 1 must export their trained model"):
        SklearnModelDetector(model_path="data/models/nonexistent_model.joblib")


def test_get_detector_factory(monkeypatch):
    """Verify get_detector factory respects backend argument and environment variable."""
    # Explicit argument
    mock_det = get_detector("mock")
    assert isinstance(mock_det, MockDetector)

    # Via environment variable
    monkeypatch.setenv("DETECTOR_BACKEND", "mock")
    env_mock = get_detector()
    assert isinstance(env_mock, MockDetector)

    # Invalid backend
    with pytest.raises(ValueError, match="Unsupported DETECTOR_BACKEND"):
        get_detector("invalid_backend")


# ============================================================================
# 3. Label Mapping & MITRE ATT&CK Consistency
# ============================================================================

def test_label_mapping_covers_all_required_categories():
    """Verify that all CICIDS2017/2018 and stealth categories are defined in label_mapping.json."""
    required_labels = [
        "BENIGN", "Bot", "PortScan", "Infiltration", "DoS Hulk", "DoS GoldenEye",
        "DDoS", "FTP-Patator", "SSH-Patator", "Web Attack Brute Force",
        "Web Attack XSS", "Web Attack Sql Injection", "Heartbleed",
        "C2_Beaconing", "DNS_Tunneling", "Lateral_Movement",
        "LotL_PowerShell", "LotL_WMI", "LotL_PsExec", "Encrypted_Traffic_Anomaly"
    ]
    with open(LABEL_MAPPING_PATH, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    for label in required_labels:
        assert label in mapping, f"Missing required label '{label}' in label_mapping.json"
        entry = mapping[label]
        assert "technique_ids" in entry
        assert "tactic" in entry
        assert "default_severity" in entry
        assert entry["default_severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_all_mapped_techniques_exist_in_mitre_catalog():
    """Verify that every technique ID in label_mapping.json resolves in the MITRE catalog."""
    mitre_svc = MitreAttackService()
    catalog_tech_ids = {t.technique_id for t in mitre_svc.get_all_techniques()}

    with open(LABEL_MAPPING_PATH, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    for label, data in mapping.items():
        for tid in data["technique_ids"]:
            assert tid in catalog_tech_ids, (
                f"Technique ID '{tid}' mapped under label '{label}' was not found in the MITRE catalog!"
            )


# ============================================================================
# 4. API Endpoints & Multi-Agent Investigation
# ============================================================================

def test_api_get_mock_alerts_returns_40_plus():
    """Verify that GET /api/v1/alerts/mock returns 40+ validated alerts."""
    response = client.get("/api/v1/alerts/mock")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 40
    # Verify structure of first item
    first = data[0]
    assert "flow_id" in first
    assert "predicted_label" in first
    assert "confidence" in first
    assert "src_ip" in first


def test_api_post_investigate_with_detection_alert():
    """Verify that POST /api/v1/investigate accepts a DetectionAlert and runs multi-agent workflow."""
    alert_payload = {
        "flow_id": "FLOW-TEST-API",
        "timestamp": "2026-09-29T12:00:00Z",
        "src_ip": "192.168.1.180",
        "dst_ip": "185.220.101.5",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "TCP",
        "predicted_label": "C2_Beaconing",
        "confidence": 0.95,
        "top_features": [
            {"name": "fwd_iat_mean", "shap_value": 0.45, "value": 30.0, "description": "Beaconing interval"}
        ],
        "metadata": {"hostname": "WS-180"}
    }
    response = client.post("/api/v1/investigate", json=alert_payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["success"] is True
    assert res_data["alert_id"] == "FLOW-TEST-API"
    assert "plan" in res_data
    assert "investigation" in res_data
    assert "response_proposals" in res_data
    assert len(res_data["response_proposals"]) >= 2
    # Verify human-in-the-loop requirement: all proposals must be PENDING_APPROVAL
    for proposal in res_data["response_proposals"]:
        assert proposal["approval_status"] == "PENDING_APPROVAL"
