"""
Unit and Integration Tests for Phase 2: Official MITRE ATT&CK STIX Integration.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.mitre.service import MitreAttackService
from src.mitre.stix_parser import load_mitre_catalog

client = TestClient(app)

LABEL_MAPPING_PATH = Path(__file__).resolve().parent.parent / "src" / "mitre" / "label_mapping.json"
STIX_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre" / "enterprise-attack.json"
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre" / "parsed_catalog.json"


# ============================================================================
# 1. STIX Bundle & Catalog Tests
# ============================================================================

def test_official_stix_bundle_loaded_successfully():
    """Verify that the official STIX catalog loads with 600+ Enterprise techniques."""
    svc = MitreAttackService()
    techniques = svc.get_all_techniques()
    assert len(techniques) >= 600, f"Expected 600+ techniques from STIX, got {len(techniques)}"


def test_required_phase2_techniques_present():
    """Verify that all specific techniques requested in Phase 2c are present and resolvable."""
    required_ids = [
        ("T1071.001", "Web Protocols"),
        ("T1071.004", "DNS"),
        ("T1573", "Encrypted Channel"),
        ("T1048", "Exfiltration Over Alternative Protocol"),
        ("T1021.002", "SMB/Windows Admin Shares"),
        ("T1059.001", "PowerShell"),
        ("T1047", "Windows Management Instrumentation"),
        ("T1569.002", "Service Execution"),
        ("T1046", "Network Service Discovery"),
        ("T1110", "Brute Force"),
        ("T1190", "Exploit Public-Facing Application"),
    ]
    svc = MitreAttackService()

    for tid, expected_name_substring in required_ids:
        tech = svc.get_technique_by_id(tid)
        assert tech is not None, f"Required technique '{tid}' was not found in catalog!"
        assert tech.technique_id == tid
        assert expected_name_substring.lower() in tech.technique_name.lower(), (
            f"Expected '{expected_name_substring}' in '{tech.technique_name}'"
        )
        assert tech.tactic_name, f"Technique '{tid}' missing tactic name"
        assert tech.url.startswith("https://attack.mitre.org/techniques/"), f"Technique '{tid}' invalid URL"


def test_every_technique_in_label_mapping_resolves():
    """Acceptance Test: Every technique ID in label_mapping.json must resolve in catalog."""
    svc = MitreAttackService()
    with open(LABEL_MAPPING_PATH, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    for label, data in mapping.items():
        for tid in data.get("technique_ids", []):
            tech = svc.get_technique_by_id(tid)
            assert tech is not None, f"Technique ID '{tid}' from label '{label}' did not resolve in catalog!"


# ============================================================================
# 2. Service Lookup & Relevance Search Tests
# ============================================================================

def test_lookup_by_dataset_label():
    """Verify get_techniques_for_label returns mapped techniques."""
    svc = MitreAttackService()

    c2_techs = svc.get_techniques_for_label("C2_Beaconing")
    assert len(c2_techs) >= 2
    c2_ids = {t.technique_id for t in c2_techs}
    assert "T1071.001" in c2_ids

    lotl_techs = svc.get_techniques_for_label("LotL_PowerShell")
    assert any(t.technique_id == "T1059.001" for t in lotl_techs)

    dns_techs = svc.get_techniques_for_label("DNS_Tunneling")
    assert any(t.technique_id == "T1071.004" for t in dns_techs)


def test_relevance_search_keywords():
    """Verify search_techniques ranks highly relevant results first."""
    svc = MitreAttackService()

    # Exact ID search
    results_id = svc.search_techniques("T1059.001", limit=3)
    assert len(results_id) > 0
    assert results_id[0].technique_id == "T1059.001"

    # Name search
    results_ps = svc.search_techniques("PowerShell", limit=5)
    assert len(results_ps) > 0
    assert results_ps[0].technique_id == "T1059.001"

    # Keyword search for SMB
    results_smb = svc.search_techniques("SMB", limit=5)
    assert any(t.technique_id == "T1021.002" for t in results_smb)


def test_correlate_alert_ranking():
    """Verify correlate_alert correctly boosts port and SHAP features."""
    svc = MitreAttackService()

    # Alert on port 53 with DNS length features
    correlated_dns = svc.correlate_alert(
        attack_type="DNS_Tunneling",
        shap_feature_names=["packet_length_mean", "dst_port"],
        dst_port=53
    )
    assert len(correlated_dns) > 0
    assert correlated_dns[0].technique_id in ("T1071.004", "T1048.003", "T1048")

    # Alert on port 445 (SMB)
    correlated_smb = svc.correlate_alert(
        attack_type="Lateral_Movement",
        shap_feature_names=["dst_port", "flow_duration"],
        dst_port=445
    )
    assert len(correlated_smb) > 0
    assert correlated_smb[0].technique_id == "T1021.002"


# ============================================================================
# 3. Offline Fallback Strategy Tests
# ============================================================================

def test_offline_fallback_when_stix_missing(tmp_path):
    """Verify that when STIX and cache are missing, the service falls back to attack_data.json."""
    bogus_stix = tmp_path / "nonexistent.json"
    bogus_cache = tmp_path / "nonexistent_cache.json"

    fallback_catalog = load_mitre_catalog(
        stix_path=bogus_stix,
        cache_path=bogus_cache
    )
    assert len(fallback_catalog) >= 12
    assert "T1071.001" in fallback_catalog
    assert "T1071.004" in fallback_catalog


# ============================================================================
# 4. API Endpoints for MITRE ATT&CK
# ============================================================================

def test_api_mitre_techniques_endpoint():
    """Verify GET /api/v1/mitre/techniques returns full catalog."""
    response = client.get("/api/v1/mitre/techniques")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 600


def test_api_mitre_search_endpoint():
    """Verify GET /api/v1/mitre/search?query=PowerShell returns filtered results."""
    response = client.get("/api/v1/mitre/search?query=PowerShell")
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]["technique_id"] == "T1059.001"
