"""
Interactive CLI Demo for Agentic Explainable NIDS Pipeline.

Demonstrates Student 2's complete implementation:
1. Loads mock stealthy network intrusion alerts (C2 Beaconing, DNS Tunneling, Lateral Movement).
2. Executes the LangGraph Multi-Agent workflow (Planner -> Investigator -> Responder -> Reporter).
3. Displays the MITRE ATT&CK correlation, feature evidence, mitigation proposals, and incident report.
4. Demonstrates the Human-in-the-Loop approval gate.
"""

import json
from pathlib import Path
from src.agents import run_nids_pipeline
from src.api.schemas import AlertInput, ApprovalActionRequest, ApprovalStatus, DetectionAlert
from src.api.main import record_action_decision

MOCK_PATH = Path(__file__).parent / "tests" / "mock_alerts.json"


def main():
    print("=" * 70)
    print("  AGENTIC EXPLAINABLE NIDS - MULTI-AGENT PIPELINE DEMO (STUDENT 2)")
    print("=" * 70)

    with open(MOCK_PATH, "r", encoding="utf-8") as f:
        raw_alerts = json.load(f)

    alerts = []
    for item in raw_alerts:
        if "flow_id" in item:
            alerts.append(DetectionAlert(**item))
        else:
            alerts.append(AlertInput(**item))

    print(f"\n[+] Loaded {len(alerts)} alert test scenarios from mock fixtures:")
    for idx, a in enumerate(alerts[:5], 1):
        lbl = a.predicted_label if isinstance(a, DetectionAlert) else a.detected_attack
        print(f"    {idx}. [{lbl}] Confidence: {a.confidence * 100:.1f}%")
    if len(alerts) > 5:
        print(f"    ... and {len(alerts) - 5} more alerts (including multi-step chains & benign traffic)")

    # Pick Scenario 1: C2 Beaconing (Chain 1, Step 1)
    selected_alert = alerts[0]
    attack_label = selected_alert.predicted_label if isinstance(selected_alert, DetectionAlert) else selected_alert.detected_attack
    alert_id = selected_alert.flow_id if isinstance(selected_alert, DetectionAlert) else selected_alert.alert_id
    src_ip = selected_alert.src_ip if isinstance(selected_alert, DetectionAlert) else selected_alert.network_metadata.src_ip
    dst_ip = selected_alert.dst_ip if isinstance(selected_alert, DetectionAlert) else selected_alert.network_metadata.dst_ip
    dst_port = selected_alert.dst_port if isinstance(selected_alert, DetectionAlert) else selected_alert.network_metadata.dst_port

    print(f"\n>>> Running LangGraph Pipeline for: '{attack_label}'")
    print(f"    Alert ID: {alert_id}")
    print(f"    Connection: {src_ip} -> {dst_ip}:{dst_port}")

    # Run LangGraph pipeline
    response = run_nids_pipeline(selected_alert)

    print("\n" + "-" * 70)
    print(f"[*] 1. PLANNER AGENT OUTPUT")
    print(f"    Objective: {response.plan.objective}")
    print(f"    Steps Dispatched: {len(response.plan.steps)} tasks")

    print("\n" + "-" * 70)
    print(f"[*] 2. INVESTIGATION AGENT OUTPUT (MITRE ATT&CK)")
    print(f"    Assessed Severity: {response.investigation.assessed_severity.value}")
    print("    Matched MITRE Techniques:")
    for tech in response.investigation.matched_techniques:
        print(f"      • [{tech.technique_id}] {tech.technique_name} (Tactic: {tech.tactic_name})")
    print("    Key Evidence:")
    for ev in response.investigation.key_evidence:
        print(f"      • {ev}")

    print("\n" + "-" * 70)
    print(f"[*] 3. RESPONSE AGENT OUTPUT (HUMAN-IN-THE-LOOP PROPOSALS)")
    for prop in response.response_proposals:
        print(f"    Priority {prop.priority}: [{prop.action_type.value}] -> Target: {prop.target}")
        print(f"      Rationale: {prop.rationale}")
        print(f"      Status: {prop.approval_status.value}")
        if prop.execution_command_preview:
            print(f"      Preview: `{prop.execution_command_preview}`")

    print("\n" + "-" * 70)
    print(f"[*] 4. REPORTING AGENT OUTPUT (SOC INCIDENT SUMMARY)")
    print(f"    Incident ID: {response.report.incident_id}")
    print(f"    Executive Summary:\n{response.report.executive_summary}")
    print(f"    {response.report.audit_notes}")

    # Demonstrate Human-in-the-Loop decision
    print("\n" + "=" * 70)
    print("[*] 5. HUMAN-IN-THE-LOOP APPROVAL SIMULATION")
    action_to_approve = response.response_proposals[0]
    print(f"    Simulating Analyst Review for Action: {action_to_approve.action_id}...")
    decision_req = ApprovalActionRequest(
        action_id=action_to_approve.action_id,
        decision=ApprovalStatus.APPROVED,
        analyst_id="analyst_soc_lead",
        analyst_notes="Confirmed C2 beaconing via anomalous forward IAT mean (30.02s)."
    )
    decision_res = record_action_decision(decision_req)
    print(f"    Result: {decision_res.message}")
    print(f"    Audit Trail Reference: {decision_res.audit_log_id}")
    print(f"    Pipeline Execution Time: {response.execution_time_seconds:.4f} seconds")
    print("=" * 70)


if __name__ == "__main__":
    main()
