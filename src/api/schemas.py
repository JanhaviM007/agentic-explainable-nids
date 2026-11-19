"""
Pydantic Schemas and Data Contracts for the Agentic Explainable NIDS.

This module defines the central data contracts between:
- Student 1: Machine Learning Detection layer (Random Forest, XGBoost, Isolation Forest)
- Student 2: LangGraph Multi-Agent Pipeline & FastAPI Backend (Planner, Investigator, Responder, Reporter)
- Student 3: SHAP Explainability & Streamlit SOC Dashboard (Human-in-the-Loop Gate & Audit Trail)
"""

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator


# ============================================================================
# 1. Enums for Categorization, Severity, and Approvals
# ============================================================================

class AttackCategory(str, Enum):
    """Categorization of detected network activity."""
    # Modern stealthy attacks (Core focus of 2025-26 research)
    C2_BEACONING = "Command-and-Control (C2) Beaconing"
    DNS_TUNNELING = "DNS Tunneling / Data Exfiltration"
    LATERAL_MOVEMENT = "Lateral Movement"
    LIVING_OFF_THE_LAND = "Living-off-the-Land (LotL)"
    ENCRYPTED_ANOMALY = "Encrypted Traffic Anomaly"

    # Classical & baseline benchmark attacks (CICIDS2017 / 2018)
    DOS_DDOS = "DoS/DDoS"
    BRUTE_FORCE = "Brute Force"
    PORT_SCAN = "Port Scan / Reconnaissance"
    WEB_ATTACK = "Web Attack / Injection"
    BOTNET = "Botnet"
    INFILTRATION = "Infiltration"

    # Benign / Unsupervised
    BENIGN = "Benign Traffic"
    UNKNOWN_ANOMALY = "Unknown Anomaly (Isolation Forest)"


class SeverityLevel(str, Enum):
    """Incident severity classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(str, Enum):
    """Types of mitigation actions proposed by Response Agent."""
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    RATE_LIMIT = "RATE_LIMIT"
    TERMINATE_CONNECTION = "TERMINATE_CONNECTION"
    DNS_SINKHOLE = "DNS_SINKHOLE"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    ESCALATE_TO_SENIOR_ANALYST = "ESCALATE_TO_SENIOR_ANALYST"


class ApprovalStatus(str, Enum):
    """Status for Human-in-the-Loop gate."""
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


# ============================================================================
# 2. Ingestion Models (Input from ML Detection + SHAP)
# ============================================================================

class NetworkFlowMetadata(BaseModel):
    """Network flow 5-tuple and connection statistics."""
    src_ip: str = Field(..., description="Source IP address", examples=["192.168.1.105"])
    dst_ip: str = Field(..., description="Destination IP address", examples=["185.220.101.5"])
    src_port: int = Field(..., description="Source port number", ge=0, le=65535, examples=[49821])
    dst_port: int = Field(..., description="Destination port number", ge=0, le=65535, examples=[443])
    protocol: str = Field("TCP", description="Protocol used (TCP, UDP, ICMP, DNS)", examples=["TCP"])
    flow_duration: Optional[float] = Field(None, description="Flow duration in microseconds")
    total_fwd_packets: Optional[int] = Field(None, description="Total forward packets")
    total_bwd_packets: Optional[int] = Field(None, description="Total backward packets")


class SHAPFeatureContribution(BaseModel):
    """Feature-level explanation provided by Student 3's SHAP module."""
    feature_name: str = Field(..., description="Name of the flow/packet feature", examples=["fwd_iat_mean"])
    feature_value: Any = Field(..., description="Observed raw or scaled feature value", examples=[30.2])
    shap_value: float = Field(..., description="SHAP contribution score (+ raises risk, - lowers risk)", examples=[0.42])
    description: Optional[str] = Field(None, description="Human-readable description of why this feature matters")


class AlertInput(BaseModel):
    """
    Standard Alert Payload (Legacy / Interoperability format).
    Student 1 (ML) and Student 3 (SHAP) produce this object to trigger the agentic pipeline.
    """
    alert_id: str = Field(..., description="Unique alert identifier", examples=["ALT-2026-001"])
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the detected flow"
    )
    network_metadata: NetworkFlowMetadata
    detected_attack: str = Field(..., description="Attack name or label predicted by ML model", examples=["Command-and-Control (C2) Beaconing"])
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from model", examples=[0.94])
    model_source: str = Field("XGBoost + Isolation Forest", description="Model identifier", examples=["XGBoost v1.0"])
    shap_explanations: List[SHAPFeatureContribution] = Field(
        default_factory=list,
        description="Top contributing features explaining the prediction"
    )
    raw_features: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional full feature vector for deep inspection"
    )

    def to_detection_alert(self) -> "DetectionAlert":
        """Converts legacy AlertInput into standardized DetectionAlert."""
        return DetectionAlert(
            flow_id=self.alert_id,
            timestamp=self.timestamp,
            src_ip=self.network_metadata.src_ip,
            dst_ip=self.network_metadata.dst_ip,
            src_port=self.network_metadata.src_port,
            dst_port=self.network_metadata.dst_port,
            protocol=self.network_metadata.protocol,
            predicted_label=self.detected_attack,
            confidence=self.confidence,
            top_features=[
                FeatureContribution(
                    name=s.feature_name,
                    shap_value=s.shap_value,
                    value=s.feature_value,
                    description=s.description
                )
                for s in self.shap_explanations
            ],
            metadata={
                "model_source": self.model_source,
                "flow_duration": self.network_metadata.flow_duration,
                "total_fwd_packets": self.network_metadata.total_fwd_packets,
                "total_bwd_packets": self.network_metadata.total_bwd_packets,
                **(self.raw_features or {})
            }
        )


class FeatureContribution(BaseModel):
    """Normalized feature-level contribution entry."""
    name: str = Field(..., description="Feature name", examples=["fwd_iat_mean"])
    shap_value: float = Field(..., description="SHAP attribution value", examples=[0.45])
    value: Optional[Any] = Field(None, description="Observed raw or scaled feature value", examples=[30.02])
    description: Optional[str] = Field(None, description="Human-readable interpretation")


class DetectionAlert(BaseModel):
    """
    Standardized Detector-to-Agents Contract (Phase 1).
    Decouples ML detection output from LangGraph multi-agent investigation.
    """
    flow_id: str = Field(..., description="Unique flow/alert identifier", examples=["FLOW-2026-001"])
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the detected flow event"
    )
    src_ip: str = Field(..., description="Source IPv4 or IPv6 address", examples=["192.168.1.105"])
    dst_ip: str = Field(..., description="Destination IPv4 or IPv6 address", examples=["185.220.101.5"])
    src_port: int = Field(..., description="Source port", ge=0, le=65535, examples=[49821])
    dst_port: int = Field(..., description="Destination port", ge=0, le=65535, examples=[443])
    protocol: str = Field("TCP", description="Transport/Network protocol", examples=["TCP"])
    predicted_label: str = Field(..., description="Attack category label or BENIGN", examples=["C2_Beaconing"])
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model prediction confidence score", examples=[0.94])
    top_features: List[FeatureContribution] = Field(
        default_factory=list,
        description="Top contributing features explaining the prediction"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata (hostname, duration, bytes, dns_query_length, beacon_interval_sec, process_name, etc.)"
    )
    expected_techniques: Optional[List[str]] = Field(
        default=None,
        description="Ground-truth MITRE techniques for evaluation"
    )
    expected_severity: Optional[str] = Field(
        default=None,
        description="Ground-truth severity for evaluation"
    )

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate that IP address is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError as err:
            raise ValueError(f"Invalid IPv4/IPv6 address: '{v}'") from err

    @field_validator("src_port", "dst_port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Validate port range 0 to 65535."""
        if not (0 <= v <= 65535):
            raise ValueError(f"Port must be between 0 and 65535, got {v}")
        return v

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence range 0.0 to 1.0."""
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {v}")
        return v

    def to_alert_input(self) -> AlertInput:
        """Converts DetectionAlert to legacy AlertInput for backward compatibility."""
        net = NetworkFlowMetadata(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            flow_duration=float(self.metadata.get("flow_duration") or self.metadata.get("duration") or 0.0),
            total_fwd_packets=self.metadata.get("total_fwd_packets"),
            total_bwd_packets=self.metadata.get("total_bwd_packets")
        )
        shap_list = [
            SHAPFeatureContribution(
                feature_name=f.name,
                feature_value=f.value if f.value is not None else 0.0,
                shap_value=f.shap_value,
                description=f.description
            )
            for f in self.top_features
        ]
        return AlertInput(
            alert_id=self.flow_id,
            timestamp=self.timestamp,
            network_metadata=net,
            detected_attack=self.predicted_label,
            confidence=self.confidence,
            model_source=str(self.metadata.get("model_source", "Detector")),
            shap_explanations=shap_list,
            raw_features=self.metadata
        )


# ============================================================================
# 3. MITRE ATT&CK Data Models
# ============================================================================

class MitreMitigation(BaseModel):
    """MITRE ATT&CK mitigation reference."""
    id: str = Field(..., description="Mitigation ID", examples=["M1037"])
    name: str = Field(..., description="Mitigation name", examples=["Filter Network Traffic"])
    description: str = Field(..., description="Description of the mitigation strategy")


class MitreTechnique(BaseModel):
    """MITRE ATT&CK Technique mapped to the detected threat."""
    technique_id: str = Field(..., description="MITRE Technique ID", examples=["T1071.001"])
    technique_name: str = Field(..., description="Technique name", examples=["Web Protocols"])
    tactic_id: str = Field(..., description="MITRE Tactic ID", examples=["TA0011"])
    tactic_name: str = Field(..., description="MITRE Tactic name", examples=["Command and Control"])
    description: str = Field(..., description="Technical explanation of the technique")
    url: Optional[str] = Field(None, description="Official MITRE ATT&CK documentation URL")
    mitigations: List[MitreMitigation] = Field(default_factory=list)


# ============================================================================
# 4. Agent Outputs & State Contracts
# ============================================================================

class InvestigationPlan(BaseModel):
    """Output from the Planner Agent."""
    plan_id: str = Field(..., description="Unique plan identifier")
    objective: str = Field(..., description="Goal of the multi-agent investigation")
    reasoning: str = Field(..., description="Planner's thought process evaluating the alert + SHAP values")
    steps: List[str] = Field(..., description="Ordered list of investigation tasks dispatched to sub-agents")


class InvestigationFinding(BaseModel):
    """Output from the Investigation Agent."""
    matched_techniques: List[MitreTechnique] = Field(..., description="MITRE ATT&CK mappings identified")
    assessed_severity: SeverityLevel = Field(..., description="Contextual severity level")
    attack_chain_context: str = Field(..., description="Where this fits in the kill-chain / enterprise context")
    key_evidence: List[str] = Field(..., description="Bullet points combining flow metadata and SHAP contributions")
    confidence_assessment: str = Field(..., description="Agent confidence and assessment of potential false positive")


class MitigationProposal(BaseModel):
    """Output from the Response Agent (Requires Human Approval)."""
    action_id: str = Field(..., description="Unique action ID", examples=["ACT-001"])
    action_type: ActionType = Field(..., description="Type of mitigation proposed")
    target: str = Field(..., description="Target host, IP, or network entity", examples=["185.220.101.5"])
    priority: int = Field(1, description="Ranked execution priority (1 = highest)")
    rationale: str = Field(..., description="Why this action is recommended")
    estimated_impact: str = Field(..., description="Business or operational impact of executing this action")
    approval_status: ApprovalStatus = Field(ApprovalStatus.PENDING_APPROVAL, description="Current approval status")
    execution_command_preview: Optional[str] = Field(
        None,
        description="Safe preview of the firewall command or containment script",
        examples=["iptables -A OUTPUT -d 185.220.101.5 -j DROP"]
    )


class IncidentReport(BaseModel):
    """Output from the Reporting Agent."""
    incident_id: str = Field(..., description="Unique incident report ID")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executive_summary: str = Field(..., description="High-level executive summary for management/SOC Lead")
    technical_analysis: str = Field(..., description="Deep-dive analysis for Tier 2/3 analysts")
    mitre_summary: str = Field(..., description="MITRE ATT&CK matrix alignment summary")
    recommended_mitigations: List[MitigationProposal] = Field(..., description="Proposals awaiting human signoff")
    audit_notes: str = Field(..., description="Integrity / audit record string for compliance")


# ============================================================================
# 5. Full Pipeline Response & Human-in-the-Loop Requests
# ============================================================================

class PipelineExecutionResponse(BaseModel):
    """Complete response returned by POST /api/v1/investigate endpoint."""
    success: bool = True
    alert_id: str
    execution_time_seconds: float
    plan: InvestigationPlan
    investigation: InvestigationFinding
    response_proposals: List[MitigationProposal]
    report: IncidentReport


class ApprovalActionRequest(BaseModel):
    """Request payload sent when analyst clicks Approve/Reject in Streamlit."""
    action_id: str = Field(..., description="Action ID to approve or reject")
    decision: ApprovalStatus = Field(..., description="APPROVED or REJECTED")
    analyst_id: str = Field(..., description="Identifier or name of human analyst", examples=["analyst_sam"])
    analyst_notes: Optional[str] = Field(None, description="Optional justification or reason for decision")


class ApprovalActionResponse(BaseModel):
    """Response returned after processing human analyst decision."""
    success: bool
    action_id: str
    status: ApprovalStatus
    audit_log_id: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
