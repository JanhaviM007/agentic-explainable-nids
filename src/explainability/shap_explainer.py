import json
from pathlib import Path

import joblib
import pandas as pd
import shap


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODELS_DIR = PROJECT_ROOT / "models"

MODEL_PATH = MODELS_DIR / "xgboost_nids.joblib"
ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"
FEATURES_PATH = MODELS_DIR / "feature_columns.json"


# ---------------------------------------------------------
# Load model artifacts
# ---------------------------------------------------------

model = joblib.load(MODEL_PATH)

label_encoder = joblib.load(ENCODER_PATH)

with open(FEATURES_PATH, "r") as f:
    feature_columns = json.load(f)


# ---------------------------------------------------------
# Create SHAP explainer
# ---------------------------------------------------------

explainer = shap.TreeExplainer(model)


# ---------------------------------------------------------
# Prediction + SHAP explanation
# ---------------------------------------------------------

def explain_prediction(
    features: dict,
    top_k: int = 10
) -> dict:

    # Create dataframe using the exact training feature order
    sample = pd.DataFrame(
        [features],
        columns=feature_columns
    )

    # Make prediction
    predicted_encoded = int(
        model.predict(sample)[0]
    )

    predicted_label = label_encoder.inverse_transform(
        [predicted_encoded]
    )[0]

    # Prediction probabilities
    probabilities = model.predict_proba(sample)[0]

    confidence = float(
        probabilities[predicted_encoded]
    )

    # Calculate SHAP values
    shap_values = explainer.shap_values(sample)

    # Multiclass SHAP output:
    # (samples, features, classes)
    sample_shap_values = shap_values[
        0,
        :,
        predicted_encoded
    ]

    # Build explanation dataframe
    explanation_df = pd.DataFrame({
        "feature": feature_columns,
        "value": sample.iloc[0].values,
        "shap_value": sample_shap_values
    })

    explanation_df["absolute_shap"] = (
        explanation_df["shap_value"].abs()
    )

    # Get strongest contributors
    explanation_df = explanation_df.sort_values(
        "absolute_shap",
        ascending=False
    )

    top_features = []

    for _, row in explanation_df.head(top_k).iterrows():

        top_features.append({
            "feature": row["feature"],
            "value": float(row["value"]),
            "shap_value": float(row["shap_value"])
        })

    return {
        "prediction": predicted_label,
        "confidence": confidence,
        "top_features": top_features
    }