"""
State Definition for the LangGraph Multi-Agent Pipeline.

Defines the shared memory and context passed across:
- Planner Agent
- Investigation Agent (MITRE ATT&CK)
- Response Agent (Mitigation Recommendations)
- Reporting Agent (SOC Incident Summary)
"""

from typing import Any, Dict, List, Optional, TypedDict


class AgentState(TypedDict, total=False):
    """
    Shared state schema used across all nodes in the LangGraph workflow.
    """
    # 1. Incoming Alert (Dictionary serializable from AlertInput)
    alert: Dict[str, Any]

    # 2. Execution Tracing / Step Logs
    steps_completed: List[str]

    # 3. Agent 1: Planner Output
    plan: Optional[Dict[str, Any]]

    # 4. Agent 2: Investigation Output (MITRE Correlation & Evidence Analysis)
    investigation: Optional[Dict[str, Any]]

    # 5. Agent 3: Response Output (Prioritized Mitigation Proposals)
    mitigations: Optional[List[Dict[str, Any]]]

    # 6. Agent 4: Reporting Output (Analyst Brief & Technical Summary)
    report: Optional[Dict[str, Any]]

    # 7. Error Handling / Diagnostic Flag
    error: Optional[str]
