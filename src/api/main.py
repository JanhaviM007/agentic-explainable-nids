from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.explainability.shap_explainer import (
    explain_prediction,
    feature_columns
)


app = FastAPI(
    title="Agentic Explainable NIDS API",
    description="ML detection and SHAP explainability API for network intrusion detection.",
    version="1.0.0"
)


class PredictionRequest(BaseModel):
    features: dict


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NIDS ML Detection API"
    }


@app.post("/api/predict")
def predict(request: PredictionRequest):

    received_features = set(request.features.keys())
    required_features = set(feature_columns)

    missing_features = sorted(
        required_features - received_features
    )

    extra_features = sorted(
        received_features - required_features
    )

    if missing_features or extra_features:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Invalid feature set.",
                "missing_features": missing_features,
                "extra_features": extra_features
            }
        )

    result = explain_prediction(
        request.features
    )

    return {
        "model": "XGBoost",
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "top_features": result["top_features"]
    }