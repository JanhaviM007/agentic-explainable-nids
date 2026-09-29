# Agentic Explainable NIDS

## Agentic Explainable AI-Based Network Intrusion Detection System for Detecting Modern Stealthy Network Attacks

This project aims to develop an explainable and agentic Network Intrusion Detection System (NIDS) capable of detecting modern stealthy network attacks.

## Core Components

- Machine Learning-based intrusion detection
- Random Forest
- XGBoost
- Isolation Forest
- SHAP-based explainability
- LangGraph multi-agent investigation
- MITRE ATT&CK correlation
- Human-in-the-loop response approval
- FastAPI backend
- Streamlit SOC dashboard
- Audit logging

## Datasets

- CICIDS2017
- CSE-CIC-IDS2018
- CICIoT2023
- UNSW-NB15 for secondary validation

## Status

🚧 Under development

## Plugging In Student 1's ML Model
1. Train your scikit-learn / XGBoost model on preprocessed flow features.
2. Export your model artifact: `import joblib; joblib.dump(model, "data/models/detector_model.joblib")`.
3. In your environment or `.env`, set: `DETECTOR_BACKEND=sklearn` (optionally set `SKLEARN_MODEL_PATH=path/to/model.joblib`).
4. The system's `SklearnModelDetector` automatically ingests flow features, classifies traffic, and feeds validated `DetectionAlert` objects into the LangGraph multi-agent pipeline.

## Changelog

### Phase 1: Decouple from Missing Detection Model
- Defined canonical `DetectionAlert` and `FeatureContribution` schemas in `src/api/schemas.py` with IPv4/IPv6, port, and confidence validators, plus bidirectional conversion to legacy `AlertInput`.
- Created `DetectorAdapter` in `src/detector/adapter.py` supporting `MockDetector` and `SklearnModelDetector`, toggled via `DETECTOR_BACKEND`.
- Built `src/mitre/label_mapping.json` mapping 20 CICIDS2017/2018 and modern stealth categories to verified MITRE ATT&CK technique IDs and default severities.
- Created `scripts/generate_mock_alerts.py` and populated `tests/mock_alerts.json` with 45 realistic alerts, including multi-step attack chains and benign traffic.
- Updated `src/api/main.py`, `src/agents/graph.py`, and `run_demo.py` to seamlessly accept `DetectionAlert` with 100% backward compatibility.
- Added comprehensive pytest suite in `tests/test_phase1.py` with 13/13 passing tests.