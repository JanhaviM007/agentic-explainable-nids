"""
Investigation Agent Node for LangGraph.

Correlates flagged alerts and SHAP feature importance with the MITRE ATT&CK framework,
assesses contextual threat severity, and compiles forensic evidence.
"""

from typing import Any, Dict, List
from src.agents.state import AgentState
from src.api.schemas import InvestigationFinding, SeverityLevel
from src.mitre.service import MitreAttackService

# Initialize shared singleton service instance
_mitre_service = MitreAttackService()


def investigation_node(state: AgentState) -> Dict[str, Any]:
    """
    Investigation Agent executes deep correlation with MITRE ATT&CK and assesses severity.
    """
    alert = state.get("alert", {})
    detected_attack = alert.get("detected_attack", "Unknown Threat")
    confidence = alert.get("confidence", 0.0)
    net = alert.get("network_metadata", {})
    shap_list = alert.get("shap_explanations", [])

    src_ip = net.get("src_ip", "Unknown Source")
    dst_ip = net.get("dst_ip", "Unknown Dest")
    dst_port = net.get("dst_port")

    # Extract feature names from SHAP
    shap_feature_names = [s.get("feature_name", "") for s in shap_list]

    # Query MITRE ATT&CK correlation engine
    matched_techniques = _mitre_service.correlate_alert(
        attack_type=detected_attack,
        shap_feature_names=shap_feature_names,
        dst_port=dst_port
    )

    # Fallback to general category search if no specific score match
    if not matched_techniques:
        matched_techniques = _mitre_service.find_by_attack_category(detected_attack)

    # Contextual Severity Assessment
    attack_lower = detected_attack.lower()
    if ("c2" in attack_lower or "tunneling" in attack_lower or "exfiltration" in attack_lower) and confidence >= 0.85:
        severity = SeverityLevel.CRITICAL
    elif "lateral" in attack_lower or "lotl" in attack_lower or "living-off" in attack_lower or confidence >= 0.85:
        severity = SeverityLevel.HIGH
    elif "dos" in attack_lower or "brute" in attack_lower or "scan" in attack_lower:
        severity = SeverityLevel.MEDIUM
    else:
        severity = SeverityLevel.LOW

    # Build key evidence summaries
    evidence: List[str] = [
        f"Flow connection 5-tuple: {src_ip} -> {dst_ip}:{dst_port} ({net.get('protocol', 'TCP')})",
        f"Classifier detection: {detected_attack} with confidence {confidence * 100:.1f}% ({alert.get('model_source', 'ML Model')})"
    ]

    for s in sorted(shap_list, key=lambda x: abs(x.get("shap_value", 0.0)), reverse=True)[:3]:
        fname = s.get("feature_name")
        fval = s.get("feature_value")
        sval = s.get("shap_value")
        desc = s.get("description")
        desc_str = f" - {desc}" if desc else ""
        evidence.append(f"SHAP indicator [{fname} = {fval}, weight: {sval:+.2f}]{desc_str}")

    # Build attack chain context
    primary_tech = matched_techniques[0] if matched_techniques else None
    if primary_tech:
        attack_chain_context = (
            f"Observed telemetry strongly aligns with MITRE ATT&CK tactic '{primary_tech.tactic_name}' "
            f"utilizing technique '{primary_tech.technique_name}' ({primary_tech.technique_id}). "
            f"Adversary activity observed between internal host {src_ip} and {dst_ip}. "
            f"If uncontained, this posture enables sustained operational access or data leakage."
        )
    else:
        attack_chain_context = (
            f"Anomalous telemetry detected from {src_ip} inconsistent with enterprise baseline profiles."
        )

    confidence_assessment = (
        f"High investigation confidence ({confidence * 100:.1f}%). Corroborated by {len(matched_techniques)} "
        f"MITRE ATT&CK technique profiles and multiple anomalous SHAP feature distributions."
    )

    finding = InvestigationFinding(
        matched_techniques=matched_techniques[:3],  # top 3 relevant techniques
        assessed_severity=severity,
        attack_chain_context=attack_chain_context,
        key_evidence=evidence,
        confidence_assessment=confidence_assessment
    )

    current_steps = list(state.get("steps_completed", []))
    current_steps.append("Investigation Agent (MITRE ATT&CK)")

    return {
        "investigation": finding.model_dump(),
        "steps_completed": current_steps
    }
