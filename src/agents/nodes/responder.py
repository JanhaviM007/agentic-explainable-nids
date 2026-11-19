"""
Response Agent Node for LangGraph.

Synthesizes prioritized, risk-ranked mitigation proposals based on the
investigation findings and official MITRE ATT&CK mitigations.
All proposals strictly mandate Human-in-the-Loop approval before execution.
"""

from typing import Any, Dict, List
from src.agents.state import AgentState
from src.api.schemas import ActionType, ApprovalStatus, MitigationProposal, SeverityLevel


def response_node(state: AgentState) -> Dict[str, Any]:
    """
    Response Agent formulates risk-ranked containment options for human analyst sign-off.
    """
    alert = state.get("alert", {})
    alert_id = alert.get("alert_id", "ALT")
    net = alert.get("network_metadata", {})
    src_ip = net.get("src_ip", "0.0.0.0")
    dst_ip = net.get("dst_ip", "0.0.0.0")
    dst_port = net.get("dst_port", 0)

    investigation = state.get("investigation", {})
    severity = investigation.get("assessed_severity", SeverityLevel.MEDIUM)
    matched_techs = investigation.get("matched_techniques", [])

    proposals: List[MitigationProposal] = []

    # Action 1: Immediate Perimeter / Flow Containment
    if dst_port == 53 or "dns" in alert.get("detected_attack", "").lower():
        action_1 = MitigationProposal(
            action_id=f"ACT-{alert_id}-01",
            action_type=ActionType.DNS_SINKHOLE,
            target=f"DNS Traffic to {dst_ip}",
            priority=1,
            rationale="Divert outbound suspicious DNS queries to an internal sinkhole to halt data exfiltration immediately.",
            estimated_impact="Low operational impact. Affects only unapproved external DNS resolver traffic from host.",
            approval_status=ApprovalStatus.PENDING_APPROVAL,
            execution_command_preview=f"dnsmasq --address=/#/127.0.0.1 --server={dst_ip}"
        )
    elif "lateral" in alert.get("detected_attack", "").lower():
        action_1 = MitigationProposal(
            action_id=f"ACT-{alert_id}-01",
            action_type=ActionType.ISOLATE_HOST,
            target=src_ip,
            priority=1,
            rationale=f"Quarantine compromised internal host {src_ip} from the subnet to halt lateral spread via SMB/RPC.",
            estimated_impact="Moderate operational impact. Host will be restricted from internal file shares and servers.",
            approval_status=ApprovalStatus.PENDING_APPROVAL,
            execution_command_preview=f"iptables -I FORWARD -s {src_ip} -j DROP"
        )
    else:
        # Default C2 / External threat
        action_1 = MitigationProposal(
            action_id=f"ACT-{alert_id}-01",
            action_type=ActionType.BLOCK_IP,
            target=dst_ip,
            priority=1,
            rationale=f"Block outbound egress traffic to external suspicious destination {dst_ip}:{dst_port} to sever C2 channel.",
            estimated_impact="Minimal operational impact. Only traffic destined for external adversary IP is dropped.",
            approval_status=ApprovalStatus.PENDING_APPROVAL,
            execution_command_preview=f"iptables -A OUTPUT -d {dst_ip} -p tcp --dport {dst_port} -j DROP"
        )
    proposals.append(action_1)

    # Action 2: MITRE-Informed Defensive Hardening
    mitre_name = matched_techs[0].get("technique_name") if matched_techs else "Threat Activity"
    action_2 = MitigationProposal(
        action_id=f"ACT-{alert_id}-02",
        action_type=ActionType.TERMINATE_CONNECTION,
        target=f"Active sessions between {src_ip} and {dst_ip}",
        priority=2,
        rationale=f"Force TCP RST on existing stateful connection table to disrupt current adversary session ({mitre_name}).",
        estimated_impact="Zero impact on unaffected workstations; closes active anomalous session.",
        approval_status=ApprovalStatus.PENDING_APPROVAL,
        execution_command_preview=f"ss -K dst {dst_ip}"
    )
    proposals.append(action_2)

    # Action 3: Tier 2 / Incident Escalation
    action_3 = MitigationProposal(
        action_id=f"ACT-{alert_id}-03",
        action_type=ActionType.ESCALATE_TO_SENIOR_ANALYST,
        target=f"Incident Ticket #{alert_id}",
        priority=3,
        rationale=f"Severity assessed as {severity}. Escalate telemetry, SHAP weights, and PCAP to Senior SOC Incident Response for memory forensics.",
        estimated_impact="No network disruption. Alerts Tier 2 on-call analyst.",
        approval_status=ApprovalStatus.PENDING_APPROVAL,
        execution_command_preview=f"curl -X POST https://soc-ticketing.internal/api/escalate -d '{{\"incident_id\": \"{alert_id}\"}}'"
    )
    proposals.append(action_3)

    current_steps = list(state.get("steps_completed", []))
    current_steps.append("Response Agent (Mitigation Recommendations)")

    return {
        "mitigations": [p.model_dump() for p in proposals],
        "steps_completed": current_steps
    }
