"""
Detector Adapter and Ingestion Abstraction Layer.

Decouples upstream ML detection (Student 1) from the downstream LangGraph
multi-agent investigation pipeline (Student 2).
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib

from src.api.schemas import AlertInput, DetectionAlert, FeatureContribution

logger = logging.getLogger(__name__)

DEFAULT_MOCK_PATH = Path(__file__).resolve().parent.parent.parent / "tests" / "mock_alerts.json"
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "models" / "detector_model.joblib"


def normalize_detection_alert(raw_alert: Union[DetectionAlert, AlertInput, Dict[str, Any]]) -> DetectionAlert:
    """Normalize raw model payloads or legacy alert inputs into a validated DetectionAlert.

    This is the project-wide contract boundary between the ML detection layer and the
    agent orchestration layer. It guarantees every downstream tool sees a schema-valid
    object even when the upstream model emits a looser dictionary structure.
    """
    if isinstance(raw_alert, DetectionAlert):
        return raw_alert

    if isinstance(raw_alert, AlertInput):
        return raw_alert.to_detection_alert()

    if not isinstance(raw_alert, dict):
        raise TypeError(
            "Expected DetectionAlert, AlertInput, or raw model dict, "
            f"got {type(raw_alert).__name__}"
        )

    payload = dict(raw_alert)

    if "flow_id" not in payload and "alert_id" in payload:
        payload["flow_id"] = payload["alert_id"]

    if "predicted_label" not in payload and "detected_attack" in payload:
        payload["predicted_label"] = payload["detected_attack"]

    if "network_metadata" in payload and "src_ip" not in payload:
        network_metadata = payload["network_metadata"] or {}
        payload["src_ip"] = network_metadata.get("src_ip")
        payload["dst_ip"] = network_metadata.get("dst_ip")
        payload["src_port"] = network_metadata.get("src_port")
        payload["dst_port"] = network_metadata.get("dst_port")
        payload["protocol"] = network_metadata.get("protocol", payload.get("protocol", "TCP"))

    if "top_features" not in payload and "shap_explanations" in payload:
        features = []
        for feature in payload["shap_explanations"]:
            if isinstance(feature, dict):
                features.append(
                    FeatureContribution(
                        name=feature.get("feature_name") or feature.get("name") or "unknown_feature",
                        shap_value=float(feature.get("shap_value", 0.0)),
                        value=feature.get("feature_value", feature.get("value")),
                        description=feature.get("description"),
                    )
                )
        payload["top_features"] = features

    if "metadata" not in payload and "raw_features" in payload:
        payload["metadata"] = payload["raw_features"]

    if "confidence" not in payload and "score" in payload:
        payload["confidence"] = payload["score"]

    if "model_source" not in payload and "metadata" in payload and isinstance(payload["metadata"], dict):
        payload["model_source"] = payload["metadata"].get("model_source", "Unknown")

    # Backward-compatibility fallback for dicts coming directly from raw ML models.
    if "flow_id" in payload and "predicted_label" in payload and "src_ip" in payload and "dst_ip" in payload:
        return DetectionAlert(**payload)

    raise ValueError("Raw model output does not contain the required fields for a DetectionAlert schema.")


class DetectorAdapter(ABC):
    """Abstract interface defining the detection-to-investigation contract."""

    @abstractmethod
    def detect(self, flow_features: Dict[str, Any]) -> DetectionAlert:
        """
        Accept raw or preprocessed network flow features and return a validated DetectionAlert.

        Args:
            flow_features: Dictionary containing network flow telemetry and feature values.

        Returns:
            Validated DetectionAlert object ready for agent orchestration.
        """
        pass


class MockDetector(DetectorAdapter):
    """
    Mock detection adapter that replays pre-recorded realistic alerts.
    Enables pipeline development, tests, and UI integration without requiring a trained model.
    """

    def __init__(self, alerts_path: Optional[Union[Path, str]] = None):
        self.alerts_path = Path(alerts_path) if alerts_path else DEFAULT_MOCK_PATH
        self._alerts: List[DetectionAlert] = []
        self._index: int = 0
        self._load_alerts()

    def _load_alerts(self) -> None:
        """Loads and parses mock alerts from JSON fixtures."""
        if not self.alerts_path.exists():
            logger.warning("Mock alerts file not found at %s. Initializing empty list.", self.alerts_path)
            self._alerts = []
            return

        with open(self.alerts_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        self._alerts = []
        for idx, item in enumerate(raw_data):
            # Support both DetectionAlert format and legacy AlertInput format
            if "flow_id" in item:
                self._alerts.append(DetectionAlert(**item))
            elif "alert_id" in item:
                from src.api.schemas import AlertInput
                legacy = AlertInput(**item)
                self._alerts.append(legacy.to_detection_alert())

        logger.info("MockDetector loaded %d mock alerts from %s", len(self._alerts), self.alerts_path)

    @property
    def alerts(self) -> List[DetectionAlert]:
        """Return the loaded mock alerts."""
        return list(self._alerts)

    def detect(self, flow_features: Dict[str, Any]) -> DetectionAlert:
        """
        Return a mock alert matching requested flow_id/label, or cycle sequentially.

        Args:
            flow_features: Feature dict, optionally specifying 'flow_id' or 'predicted_label'.
        """
        if not self._alerts:
            # Fallback inline alert if mock file is empty
            return DetectionAlert(
                flow_id="FLOW-MOCK-FALLBACK",
                timestamp=datetime.now(timezone.utc),
                src_ip="192.168.1.100",
                dst_ip="185.220.101.5",
                src_port=49152,
                dst_port=443,
                protocol="TCP",
                predicted_label="C2_Beaconing",
                confidence=0.92,
                top_features=[FeatureContribution(name="fwd_iat_mean", shap_value=0.45, value=30.0)],
                metadata={"model_source": "MockDetector-Fallback"}
            )

        # Match by specific flow_id if requested
        requested_flow_id = flow_features.get("flow_id")
        if requested_flow_id:
            for alert in self._alerts:
                if alert.flow_id == requested_flow_id:
                    return alert

        # Match by requested label if provided
        requested_label = flow_features.get("predicted_label") or flow_features.get("attack_type")
        if requested_label:
            for alert in self._alerts:
                if alert.predicted_label.lower() == str(requested_label).lower():
                    return alert

        # Otherwise replay in round-robin fashion
        alert = self._alerts[self._index % len(self._alerts)]
        self._index += 1
        return alert


class SklearnModelDetector(DetectorAdapter):
    """
    Detector adapter that loads Student 1's trained Scikit-learn / XGBoost model artifact (.joblib).
    Raises an explicit FileNotFoundError with clear instructions if the model artifact is missing.
    """

    def __init__(self, model_path: Optional[Union[Path, str]] = None):
        env_path = os.getenv("SKLEARN_MODEL_PATH")
        self.model_path = Path(model_path or env_path or DEFAULT_MODEL_PATH)
        self.model: Any = None
        self._load_model()

    def _load_model(self) -> None:
        """Attempts to load the serialized joblib model."""
        if not self.model_path.exists():
            error_msg = (
                f"Model artifact not found at '{self.model_path}'. "
                "Student 1 must export their trained model using: "
                "`import joblib; joblib.dump(trained_model, 'data/models/detector_model.joblib')` "
                "or set the SKLEARN_MODEL_PATH environment variable."
            )
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        try:
            self.model = joblib.load(self.model_path)
            logger.info("Successfully loaded sklearn model from %s", self.model_path)
        except Exception as e:
            logger.error("Failed to load model from %s: %s", self.model_path, str(e))
            raise RuntimeError(f"Failed to deserialize model at '{self.model_path}': {str(e)}") from e

    def detect(self, flow_features: Dict[str, Any]) -> DetectionAlert:
        """
        Execute prediction on flow features using the loaded Scikit-learn model.

        Args:
            flow_features: Dictionary of raw/scaled flow features.
        """
        if self.model is None:
            raise RuntimeError("Model is not initialized.")

        # Ingest and format feature vector
        # (Assuming model expects 2D array or DataFrame of features)
        import pandas as pd
        df = pd.DataFrame([flow_features])
        prediction = self.model.predict(df)[0]
        confidence = 0.90
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(df)[0]
            confidence = float(max(proba))

        flow_id = str(flow_features.get("flow_id", f"FLOW-{int(datetime.now(timezone.utc).timestamp())}"))
        src_ip = str(flow_features.get("src_ip", "192.168.1.100"))
        dst_ip = str(flow_features.get("dst_ip", "10.0.0.1"))
        src_port = int(flow_features.get("src_port", 49152))
        dst_port = int(flow_features.get("dst_port", 80))
        protocol = str(flow_features.get("protocol", "TCP"))

        return DetectionAlert(
            flow_id=flow_id,
            timestamp=datetime.now(timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            predicted_label=str(prediction),
            confidence=round(confidence, 4),
            top_features=[],
            metadata={"model_source": "SklearnModelDetector", "model_path": str(self.model_path)}
        )


def get_detector(backend: Optional[str] = None, **kwargs: Any) -> DetectorAdapter:
    """
    Factory function to instantiate the configured detector backend.

    Args:
        backend: 'mock' or 'sklearn'. Defaults to DETECTOR_BACKEND env var or 'mock'.

    Returns:
        Configured DetectorAdapter instance.
    """
    selected_backend = (backend or os.getenv("DETECTOR_BACKEND", "mock")).strip().lower()

    if selected_backend == "mock":
        return MockDetector(**kwargs)
    elif selected_backend in ("sklearn", "scikit-learn"):
        return SklearnModelDetector(**kwargs)
    else:
        raise ValueError(
            f"Unsupported DETECTOR_BACKEND '{selected_backend}'. Supported options are: 'mock', 'sklearn'."
        )
