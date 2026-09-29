"""
FastAPI Backend for Agentic Explainable NIDS.

Serves as the core API connecting:
- ML Detection & SHAP Explainability (Student 1 & Student 3)
- LangGraph Multi-Agent Orchestration & MITRE ATT&CK (Student 2)
- Streamlit SOC Dashboard & Human-in-the-Loop Approval Gate (Student 3)
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from src.agents import get_agent_pipeline, run_nids_pipeline
from src.api.schemas import (
    AlertInput,
    ApprovalActionRequest,
    ApprovalActionResponse,
    ApprovalStatus,
    DetectionAlert,
    MitreTechnique,
    PipelineExecutionResponse,
)
from src.mitre import MitreAttackService

# ---------------------------------------------------------------------------
# App Initialization & Middleware
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Agentic Explainable NIDS API",
    description=(
        "Backend orchestration API for multi-agent network intrusion investigation, "
        "MITRE ATT&CK correlation, and Human-in-the-Loop mitigation approval."
    ),
    version="1.0.0",
)

# Enable CORS for Streamlit / external frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory services and stores
mitre_service = MitreAttackService()
audit_log_store: List[Dict[str, Any]] = []
action_approval_store: Dict[str, Dict[str, Any]] = {}

# Path to mock alerts for easy testing and demoing
MOCK_ALERTS_PATH = Path(__file__).resolve().parent.parent.parent / "tests" / "mock_alerts.json"


# ---------------------------------------------------------------------------
# Health & Status Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/health", tags=["System"])
def health_check():
    """System health check and pipeline status."""
    return {
        "status": "online",
        "service": "Agentic Explainable NIDS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agents_active": [
            "Planner Agent",
            "Investigation Agent (MITRE ATT&CK)",
            "Response Agent (Human-in-the-Loop)",
            "Reporting Agent (SOC Incident Brief)",
        ],
        "mitre_database_techniques_count": len(mitre_service.get_all_techniques()),
    }


# ---------------------------------------------------------------------------
# Multi-Agent Investigation Endpoint
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/investigate",
    response_model=PipelineExecutionResponse,
    tags=["Agentic Pipeline"],
    summary="Run full LangGraph multi-agent investigation on a detected alert",
)
def investigate_alert(alert: Union[DetectionAlert, AlertInput]):
    """
    Ingests an alert payload (ML detection + SHAP features) and runs the
    LangGraph multi-agent workflow:
    1. Planner Agent analyzes context and sets investigation agenda.
    2. Investigation Agent queries MITRE ATT&CK and assesses severity.
    3. Response Agent formulates risk-ranked mitigation proposals.
    4. Reporting Agent synthesizes the SOC incident report.
    """
    try:
        response = run_nids_pipeline(alert)
        alert_id = alert.flow_id if isinstance(alert, DetectionAlert) else alert.alert_id

        # Pre-register proposed actions into the approval store
        for prop in response.response_proposals:
            action_approval_store[prop.action_id] = {
                "action_id": prop.action_id,
                "action_type": prop.action_type.value,
                "target": prop.target,
                "status": ApprovalStatus.PENDING_APPROVAL.value,
                "alert_id": alert_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing agentic pipeline: {str(e)}",
        )


# ---------------------------------------------------------------------------
# Mock Alerts (for testing and Streamlit Dashboard demos)
# ---------------------------------------------------------------------------
@app.get(
    "/api/v1/alerts/mock",
    response_model=List[DetectionAlert],
    tags=["Alerts & Telemetry"],
    summary="Get pre-configured test alerts for live demonstration",
)
def get_mock_alerts() -> List[DetectionAlert]:
    """
    Returns 40+ realistic sample alerts covering stealth, baseline, and benign traffic.
    Used by Student 3's Streamlit dashboard for instant demo simulation.
    """
    if not MOCK_ALERTS_PATH.exists():
        raise HTTPException(status_code=404, detail="Mock alerts fixture file not found.")

    with open(MOCK_ALERTS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts: List[DetectionAlert] = []
    for item in data:
        if "flow_id" in item:
            alerts.append(DetectionAlert(**item))
        elif "alert_id" in item:
            legacy = AlertInput(**item)
            alerts.append(legacy.to_detection_alert())

    return alerts


# ---------------------------------------------------------------------------
# MITRE ATT&CK Endpoints
# ---------------------------------------------------------------------------
@app.get(
    "/api/v1/mitre/techniques",
    response_model=List[MitreTechnique],
    tags=["MITRE ATT&CK"],
    summary="List all mapped MITRE ATT&CK techniques",
)
def list_mitre_techniques():
    """Returns the entire curated catalog of mapped techniques."""
    return mitre_service.get_all_techniques()


@app.get(
    "/api/v1/mitre/search",
    response_model=List[MitreTechnique],
    tags=["MITRE ATT&CK"],
    summary="Search techniques by keyword, ID, or tactic",
)
def search_mitre(query: str = Query("", description="Keyword to search")):
    """Searches MITRE ATT&CK techniques by keyword."""
    return mitre_service.search_techniques(query)


# ---------------------------------------------------------------------------
# Human-in-the-Loop Approval Endpoints
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/actions/decision",
    response_model=ApprovalActionResponse,
    tags=["Human-in-the-Loop"],
    summary="Record human analyst approval or rejection for a mitigation action",
)
def record_action_decision(request: ApprovalActionRequest):
    """
    Mandatory Human Approval Gate:
    Records analyst decision (APPROVED or REJECTED) for a proposed action.
    Creates an immutable audit log entry.
    """
    action = action_approval_store.get(request.action_id)
    if not action:
        # If action not in memory yet, allow creating a valid decision entry
        action = {
            "action_id": request.action_id,
            "status": ApprovalStatus.PENDING_APPROVAL.value,
        }

    action["status"] = request.decision.value
    action["analyst_id"] = request.analyst_id
    action["analyst_notes"] = request.analyst_notes
    action["decision_timestamp"] = datetime.now(timezone.utc).isoformat()
    action_approval_store[request.action_id] = action

    # Record into audit trail
    audit_id = f"AUD-{request.action_id}-{int(datetime.now(timezone.utc).timestamp())}"
    audit_entry = {
        "audit_id": audit_id,
        "action_id": request.action_id,
        "decision": request.decision.value,
        "analyst_id": request.analyst_id,
        "analyst_notes": request.analyst_notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    audit_log_store.append(audit_entry)

    message = (
        f"Action '{request.action_id}' successfully {request.decision.value.lower()} by analyst '{request.analyst_id}'."
        if request.decision == ApprovalStatus.APPROVED
        else f"Action '{request.action_id}' REJECTED with notes: '{request.analyst_notes}'."
    )

    return ApprovalActionResponse(
        success=True,
        action_id=request.action_id,
        status=request.decision,
        audit_log_id=audit_id,
        message=message,
    )


@app.get(
    "/api/v1/audit/logs",
    tags=["Audit & Compliance"],
    summary="Fetch full immutable audit trail of analyst decisions",
)
def get_audit_logs():
    """Returns chronological audit records of all human decisions."""
    return {
        "count": len(audit_log_store),
        "logs": audit_log_store,
    }
