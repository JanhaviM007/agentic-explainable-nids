"""
Reporting Agent Node for LangGraph.

Synthesizes findings from Planner, Investigation, and Response agents into a
standardized, analyst-ready incident brief with an immutable audit footprint.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict
from src.agents.state import AgentState
from src.api.schemas import IncidentReport, MitigationProposal


def reporting_node(state: AgentState) -> Dict[str, Any]:
    """
    Reporting Agent compiles the final incident report for SOC analysts.
    """
    alert = state.get("alert", {})
    alert_id = alert.get("alert_id", "ALT-000")
    detected_attack = alert.get("detected_attack", "Unknown Threat")
    confidence = alert.get("confidence", 0.0)
    net = alert.get("network_metadata", {})
    src_ip = net.get("src_ip", "0.0.0.0")
    dst_ip = net.get("dst_ip", "0.0.0.0")
    dst_port = net.get("dst_port", 0)

    investigation = state.get("investigation", {})
    severity = investigation.get("assessed_severity", "MEDIUM")
    matched_techs = investigation.get("matched_techniques", [])
    key_evidence = investigation.get("key_evidence", [])
    raw_mitigations = state.get("mitigations", [])

    # Format MITRE summary
    if matched_techs:
        mitre_lines = [
            f"- [{t.get('technique_id')}] {t.get('technique_name')} (Tactic: {t.get('tactic_name')})"
            for t in matched_techs
        ]
        mitre_summary = "\n".join(mitre_lines)
    else:
        mitre_summary = "- No direct MITRE ATT&CK technique mapped."

    # Executive Summary
    exec_summary = (
        f"CRITICALITY: {severity} | ALERT: {detected_attack}\n"
        f"Anomalous network communication detected originating from {src_ip} towards {dst_ip}:{dst_port} "
        f"with {confidence * 100:.1f}% classifier confidence. Multi-agent analysis corroborated the pattern "
        f"against {len(matched_techs)} MITRE ATT&CK technique profile(s). "
        f"{len(raw_mitigations)} mitigation action(s) have been generated and are awaiting analyst authorization."
    )

    # Technical Analysis
    evidence_bullets = "\n".join([f"  • {ev}" for ev in key_evidence])
    tech_analysis = (
        f"### Technical Incident Breakdown\n"
        f"- **Flow 5-Tuple**: {src_ip} -> {dst_ip}:{dst_port} ({net.get('protocol', 'TCP')})\n"
        f"- **Detection Engine**: {alert.get('model_source', 'Supervised Classifier')} (Confidence: {confidence * 100:.1f}%)\n"
        f"- **Key Evidence & SHAP Attributions**:\n{evidence_bullets}\n\n"
        f"### Threat Context\n"
        f"{investigation.get('attack_chain_context', 'N/A')}"
    )

    # Convert raw mitigations into validated MitigationProposal objects
    proposals = [MitigationProposal(**m) for m in raw_mitigations]

    # Generate immutable audit signature (SHA-256 hash of core incident facts)
    audit_payload = f"{alert_id}:{detected_attack}:{src_ip}:{dst_ip}:{severity}"
    audit_hash = hashlib.sha256(audit_payload.encode()).hexdigest()[:16]
    audit_notes = (
        f"Audit Trail ID: AUD-{audit_hash.upper()} | Generated under HITL Mandate. "
        f"AI auto-execution disabled. Human review required for containment deployment."
    )

    report = IncidentReport(
        incident_id=f"INC-{alert_id}",
        generated_at=datetime.now(timezone.utc),
        executive_summary=exec_summary,
        technical_analysis=tech_analysis,
        mitre_summary=mitre_summary,
        recommended_mitigations=proposals,
        audit_notes=audit_notes
    )

    current_steps = list(state.get("steps_completed", []))
    current_steps.append("Reporting Agent (SOC Summary)")

    return {
        "report": report.model_dump(),
        "steps_completed": current_steps
    }
