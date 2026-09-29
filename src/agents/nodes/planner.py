"""
Planner Agent Node for LangGraph.

Evaluates incoming detection alerts and SHAP explanation weights,
synthesizes initial threat context, and coordinates downstream investigation steps.
"""

from typing import Any, Dict
from src.agents.state import AgentState
from src.api.schemas import InvestigationPlan


def planner_node(state: AgentState) -> Dict[str, Any]:
    """
    Planner Agent evaluates the alert and sets the strategic investigation agenda.
    """
    alert = state.get("alert", {})
    alert_id = alert.get("alert_id", "UNKNOWN-ALERT")
    detected_attack = alert.get("detected_attack", "Unknown Threat")
    confidence = alert.get("confidence", 0.0)
    net = alert.get("network_metadata", {})
    shap_list = alert.get("shap_explanations", [])

    src_ip = net.get("src_ip", "N/A")
    dst_ip = net.get("dst_ip", "N/A")
    dst_port = net.get("dst_port", "N/A")

    # Extract top contributing features from SHAP
    top_shap_desc = []
    for s in sorted(shap_list, key=lambda x: abs(x.get("shap_value", 0.0)), reverse=True)[:3]:
        name = s.get("feature_name", "")
        val = s.get("feature_value", "")
        weight = s.get("shap_value", 0.0)
        top_shap_desc.append(f"{name}={val} (SHAP: {weight:+.2f})")

    shap_summary = ", ".join(top_shap_desc) if top_shap_desc else "Standard network flow anomaly"

    objective = (
        f"Investigate suspected {detected_attack} from {src_ip} towards {dst_ip}:{dst_port} "
        f"flagged with {confidence*100:.1f}% model confidence."
    )

    reasoning = (
        f"Detection layer flagged potential stealthy activity ({detected_attack}). "
        f"Primary SHAP attribution drivers: [{shap_summary}]. "
        f"Dispatching specialized investigation to correlate with MITRE ATT&CK framework, "
        f"assess true-positive confidence, and formulate containment proposals for human approval."
    )

    steps = [
        f"1. Query MITRE ATT&CK database for technique correlation matching {detected_attack} on port {dst_port}.",
        f"2. Evaluate SHAP feature significance to verify stealth characteristics (e.g. low-and-slow timing or payload anomalies).",
        f"3. Generate risk-ranked mitigation playbooks (quarantine, firewall rules, credential reset) with impact analysis.",
        f"4. Synthesize comprehensive SOC incident brief for Tier 1/2 analyst sign-off."
    ]

    plan = InvestigationPlan(
        plan_id=f"PLAN-{alert_id}",
        objective=objective,
        reasoning=reasoning,
        steps=steps
    )

    current_steps = list(state.get("steps_completed", []))
    current_steps.append("Planner Agent")

    return {
        "plan": plan.model_dump(),
        "steps_completed": current_steps
    }
