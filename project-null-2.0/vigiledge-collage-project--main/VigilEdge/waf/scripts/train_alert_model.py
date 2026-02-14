"""
Minimal training script for WAF alert models.

Usage examples:
  python train_alert_model.py --input alerts_labeled.csv --output alert_model.joblib
  python train_alert_model.py --input alerts_sample.csv --unsupervised --output anomaly_model.joblib

The script will try to use `sentence-transformers` for text embeddings if available;
otherwise it trains on numeric features only.

CSV expected columns (recommended):
  timestamp, source_ip, target_url, user_agent, ddos_score, payload_length, text, label

Label: optional. If provided, script trains a supervised classifier. Otherwise trains IsolationForest.
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
    import numpy as np
    import joblib
except Exception:
    print("scikit-learn and joblib are required. Install with: pip install scikit-learn joblib")
    sys.exit(1)

try:
    from sentence_transformers import SentenceTransformer
    HAVE_EMBED = True
except Exception:
    HAVE_EMBED = False


def build_features(df, embedder_name=None):
    nums = []
    for col in ("ddos_score", "payload_length"):
        if col in df.columns:
            nums.append(df[col].fillna(0).astype(float).values.reshape(-1, 1))
    if nums:
        X_num = np.hstack(nums)
    else:
        X_num = np.zeros((len(df), 0))

    X_text = None
    if HAVE_EMBED and embedder_name:
        texts = (
            df.get("target_url", "").fillna("") + " " +
            df.get("user_agent", "").fillna("") + " " +
            df.get("text", "").fillna("")
        ).tolist()
        embedder = SentenceTransformer(embedder_name)
        X_text = embedder.encode(texts, show_progress_bar=True)

    if X_text is not None and X_num.size:
        X = np.hstack([X_text, X_num])
    elif X_text is not None:
        X = X_text
    elif X_num.size:
        X = X_num
    else:
        X = np.zeros((len(df), 0))

    return X


def train_supervised(df, embedder_name, out_path):
    if "label" not in df.columns:
        print("No 'label' column found for supervised training.")
        return False

    X = build_features(df, embedder_name)
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump({"model": clf, "embedder_name": embedder_name}, out_path)
    print(f"Saved supervised model to {out_path}")
    return True


def train_unsupervised(df, embedder_name, out_path):
    X = build_features(df, embedder_name)
    iso = IsolationForest(contamination=0.01, random_state=42)
    iso.fit(X)
    joblib.dump({"model": iso, "embedder_name": embedder_name}, out_path)
    print(f"Saved unsupervised model to {out_path}")
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="input CSV file with alerts")
    p.add_argument("--output", required=True, help="output model path (.joblib)")
    p.add_argument("--unsupervised", action="store_true", help="train unsupervised anomaly model")
    p.add_argument("--embedder", default=("all-MiniLM-L6-v2" if HAVE_EMBED else None), help="sentence-transformers model name (optional)")
    args = p.parse_args()

    df = pd.read_csv(args.input)

    embedder_name = args.embedder if HAVE_EMBED and args.embedder else None

    if args.unsupervised or "label" not in df.columns:
        train_unsupervised(df, embedder_name, args.output)
    else:
        train_supervised(df, embedder_name, args.output)


if __name__ == "__main__":
    main()
