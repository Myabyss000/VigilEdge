"""
Training script for WAF alert severity models.

Usage examples:
    python train_alert_model.py --input alerts_labeled.csv --output alert_model.joblib
    python train_alert_model.py --input alerts_sample.csv --unsupervised --output anomaly_model.joblib

Recommended CSV columns:
    timestamp, source_ip, target_url, user_agent, threat_type, threat_level,
    method, action, blocked, ddos_score, payload_length, ai_score,
    ai_confidence, text, label

If a `label` column is present, the script trains a supervised severity model.
Otherwise it trains a lightweight anomaly detector.
"""
import argparse
import sys

try:
    import pandas as pd
except Exception:
    print("pandas is required. Install with: pip install pandas")
    sys.exit(1)

try:
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import classification_report
    from sklearn.compose import ColumnTransformer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import MaxAbsScaler, OneHotEncoder
    import numpy as np
    import joblib
except Exception:
    print("scikit-learn and joblib are required. Install with: pip install scikit-learn joblib")
    sys.exit(1)


TEXT_FEATURE = "combined_text"
TEXT_SOURCE_COLUMNS = [
    "target_url",
    "user_agent",
    "text",
    "threat_type",
    "threat_level",
    "method",
]
NUMERIC_COLUMNS = [
    "ddos_score",
    "payload_length",
    "blocked",
    "ai_score",
    "ai_confidence",
]
CATEGORICAL_COLUMNS = [
    "threat_type",
    "threat_level",
    "method",
    "action",
]
LEGACY_LABEL_MAP = {
    "0": "INFO",
    "1": "MEDIUM",
    "2": "HIGH",
    "3": "CRITICAL",
    "4": "CRITICAL",
}
VALID_LABELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _normalize_text(series: pd.Series) -> pd.Series:
    return series.fillna("").astype(str).str.strip()


def _normalize_label(value) -> str:
    if pd.isna(value):
        return "INFO"

    raw = str(value).strip()
    if raw in LEGACY_LABEL_MAP:
        return LEGACY_LABEL_MAP[raw]

    upper = raw.upper()
    if upper in VALID_LABELS:
        return upper

    return "INFO"


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    frame = df.copy()

    for column in TEXT_SOURCE_COLUMNS + CATEGORICAL_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""

    for column in NUMERIC_COLUMNS:
        if column not in frame.columns:
            frame[column] = 0

    frame[TEXT_FEATURE] = (
        _normalize_text(frame["target_url"])
        + " "
        + _normalize_text(frame["user_agent"])
        + " "
        + _normalize_text(frame["text"])
        + " "
        + _normalize_text(frame["threat_type"])
        + " "
        + _normalize_text(frame["threat_level"])
        + " "
        + _normalize_text(frame["method"])
    ).str.strip()

    for column in NUMERIC_COLUMNS:
        frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0.0)

    frame["blocked"] = frame["blocked"].astype(float)

    for column in CATEGORICAL_COLUMNS:
        frame[column] = _normalize_text(frame[column]).replace("", "unknown")

    return frame


def build_supervised_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "text",
                TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=5000, sublinear_tf=True),
                TEXT_FEATURE,
            ),
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore"),
                CATEGORICAL_COLUMNS,
            ),
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
                        ("scaler", MaxAbsScaler()),
                    ]
                ),
                NUMERIC_COLUMNS,
            ),
        ]
    )

    classifier = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        solver="saga",
        random_state=42,
    )

    return Pipeline(steps=[("preprocessor", preprocessor), ("classifier", classifier)])


def train_supervised(df: pd.DataFrame, out_path: str):
    if "label" not in df.columns:
        print("No 'label' column found for supervised training.")
        return False

    frame = prepare_features(df)
    y = df["label"].map(_normalize_label).values

    class_counts = pd.Series(y).value_counts()
    use_holdout = len(frame) >= 10
    use_stratify = use_holdout and not class_counts.empty and int(class_counts.min()) >= 2

    if use_holdout:
        X_train, X_test, y_train, y_test = train_test_split(
            frame,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y if use_stratify else None,
        )
    else:
        X_train, X_test, y_train, y_test = frame, frame, y, y

    pipeline = build_supervised_pipeline()
    pipeline.fit(X_train, y_train)

    if use_holdout:
        y_pred = pipeline.predict(X_test)
        print(classification_report(y_test, y_pred, labels=VALID_LABELS, zero_division=0))
    else:
        print("Dataset too small for a stable holdout split; model trained on the full dataset.")

    joblib.dump(
        {
            "model": pipeline,
            "feature_version": "2.0",
            "training_columns": [TEXT_FEATURE, *CATEGORICAL_COLUMNS, *NUMERIC_COLUMNS],
            "label_mapping": VALID_LABELS,
            "model_kind": "severity_classifier",
        },
        out_path,
    )
    print(f"Saved supervised severity model to {out_path}")
    return True


def train_unsupervised(df: pd.DataFrame, out_path: str):
    frame = prepare_features(df)
    X = frame[NUMERIC_COLUMNS].fillna(0.0).astype(float).values
    iso = IsolationForest(contamination=0.02, random_state=42)
    iso.fit(X)
    joblib.dump(
        {
            "model": iso,
            "feature_version": "2.0",
            "training_columns": NUMERIC_COLUMNS,
            "model_kind": "anomaly_detector",
        },
        out_path,
    )
    print(f"Saved unsupervised model to {out_path}")
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="input CSV file with alerts")
    p.add_argument("--output", required=True, help="output model path (.joblib)")
    p.add_argument("--unsupervised", action="store_true", help="train unsupervised anomaly model")
    args = p.parse_args()

    df = pd.read_csv(args.input)

    if args.unsupervised or "label" not in df.columns:
        train_unsupervised(df, args.output)
    else:
        train_supervised(df, args.output)


if __name__ == "__main__":
    main()
