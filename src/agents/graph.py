"""
LangGraph Multi-Agent Workflow Definition and Pipeline Runner.

Orchestrates the 4 agents:
1. Planner Agent
2. Investigation Agent (MITRE ATT&CK Correlation)
3. Response Agent (Risk-Ranked Mitigations)
4. Reporting Agent (SOC Incident Brief)
"""

import time
from typing import Optional, Union
from langgraph.graph import END, StateGraph

from src.agents.nodes import (
    investigation_node,
    planner_node,
    reporting_node,
    response_node,
)
from src.agents.state import AgentState
from src.api.schemas import (
    AlertInput,
    DetectionAlert,
    IncidentReport,
    InvestigationFinding,
    InvestigationPlan,
    MitigationProposal,
    PipelineExecutionResponse,
)


def build_nids_agent_graph():
    """
    Compiles the stateful multi-agent directed graph using LangGraph.
    """
    workflow = StateGraph(AgentState)

    # 1. Register agent nodes
    workflow.add_node("planner", planner_node)
    workflow.add_node("investigator", investigation_node)
    workflow.add_node("responder", response_node)
    workflow.add_node("reporter", reporting_node)

    # 2. Define sequential execution flow
    workflow.set_entry_point("planner")
    workflow.add_edge("planner", "investigator")
    workflow.add_edge("investigator", "responder")
    workflow.add_edge("responder", "reporter")
    workflow.add_edge("reporter", END)

    return workflow.compile()


# Singleton compiled graph instance for reuse
_compiled_pipeline = None


def get_agent_pipeline():
    """Returns or lazily initializes the compiled LangGraph pipeline."""
    global _compiled_pipeline
    if _compiled_pipeline is None:
        _compiled_pipeline = build_nids_agent_graph()
    return _compiled_pipeline


def run_nids_pipeline(alert: Union[DetectionAlert, AlertInput]) -> PipelineExecutionResponse:
    """
    Executes the multi-agent pipeline for a single network detection alert.

    Args:
        alert: Validated DetectionAlert or legacy AlertInput object.

    Returns:
        PipelineExecutionResponse containing all agent outputs and the final report.
    """
    start_time = time.perf_counter()
    pipeline = get_agent_pipeline()

    # Normalize to legacy AlertInput structure for internal agent node compatibility
    if isinstance(alert, DetectionAlert):
        legacy_alert = alert.to_alert_input()
        alert_id = alert.flow_id
    else:
        legacy_alert = alert
        alert_id = alert.alert_id

    # Initialize shared graph state
    initial_state: AgentState = {
        "alert": legacy_alert.model_dump(mode="json"),
        "steps_completed": [],
        "plan": None,
        "investigation": None,
        "mitigations": None,
        "report": None,
        "error": None,
    }

    # Execute workflow through LangGraph
    final_state = pipeline.invoke(initial_state)
    elapsed_seconds = round(time.perf_counter() - start_time, 4)

    # Parse and validate outputs into Pydantic models
    plan_obj = InvestigationPlan(**final_state["plan"])
    investigation_obj = InvestigationFinding(**final_state["investigation"])
    mitigation_objs = [MitigationProposal(**m) for m in (final_state.get("mitigations") or [])]
    report_obj = IncidentReport(**final_state["report"])

    return PipelineExecutionResponse(
        success=True,
        alert_id=alert_id,
        execution_time_seconds=elapsed_seconds,
        plan=plan_obj,
        investigation=investigation_obj,
        response_proposals=mitigation_objs,
        report=report_obj,
    )
