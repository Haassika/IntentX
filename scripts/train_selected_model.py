import csv
import json
from pathlib import Path

import joblib

from sklearn.feature_extraction.text import (
    TfidfVectorizer,
)
from sklearn.linear_model import (
    LogisticRegression,
)
from sklearn.metrics import (
    accuracy_score,
    classification_report,
)
from sklearn.pipeline import (
    FeatureUnion,
    Pipeline,
)


ROOT = Path(__file__).resolve().parents[1]

TRAIN_PATH = (
    ROOT
    / "data"
    / "processed"
    / "train.csv"
)

VALIDATION_PATH = (
    ROOT
    / "data"
    / "processed"
    / "validation.csv"
)

MODEL_DIR = ROOT / "models"

MODEL_PATH = (
    MODEL_DIR
    / "intent_classifier_v2.joblib"
)

METRICS_PATH = (
    MODEL_DIR
    / "intent_classifier_v2_metrics.json"
)


def read_dataset(path):
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(csv.DictReader(file))

    texts = [
        row["text"].strip()
        for row in rows
    ]

    labels = [
        row["intent"].strip()
        for row in rows
    ]

    return texts, labels


def build_model():
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    lowercase=True,
                    analyzer="word",
                    ngram_range=(1, 2),
                    sublinear_tf=True,
                ),
            ),
            (
                "char",
                TfidfVectorizer(
                    lowercase=True,
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    sublinear_tf=True,
                    min_df=1,
                ),
            ),
        ]
    )

    classifier = LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        random_state=42,
    )

    return Pipeline(
        [
            ("features", features),
            ("classifier", classifier),
        ]
    )


def main():
    train_texts, train_labels = (
        read_dataset(TRAIN_PATH)
    )

    validation_texts, validation_labels = (
        read_dataset(VALIDATION_PATH)
    )

    print(
        "IntentX Selected Model Training"
    )
    print(
        "==============================="
    )

    print(
        f"Training examples: "
        f"{len(train_texts)}"
    )

    print(
        f"Validation examples: "
        f"{len(validation_texts)}"
    )

    model = build_model()

    print(
        "\nTraining word + character "
        "TF-IDF model..."
    )

    model.fit(
        train_texts,
        train_labels,
    )

    predictions = model.predict(
        validation_texts
    )

    accuracy = accuracy_score(
        validation_labels,
        predictions,
    )

    report = classification_report(
        validation_labels,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    metrics = {
        "model_version": "v2",
        "model_type": (
            "word_char_tfidf_logistic_regression"
        ),
        "training_examples": len(
            train_texts
        ),
        "validation_examples": len(
            validation_texts
        ),
        "validation_accuracy": accuracy,
        "validation_macro_f1": (
            report["macro avg"]["f1-score"]
        ),
        "validation_weighted_f1": (
            report["weighted avg"]["f1-score"]
        ),
        "confidence_threshold": 0.50,
        "classification_report": report,
    }

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    with METRICS_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metrics,
            file,
            indent=2,
        )

    print(
        "\n=== VALIDATION PERFORMANCE ==="
    )

    print(
        f"Accuracy: "
        f"{accuracy:.4f}"
    )

    print(
        "Macro F1: "
        f"{report['macro avg']['f1-score']:.4f}"
    )

    print(
        "Weighted F1: "
        f"{report['weighted avg']['f1-score']:.4f}"
    )

    print(
        f"\nSaved model:"
        f"\n{MODEL_PATH}"
    )

    print(
        f"\nSaved metrics:"
        f"\n{METRICS_PATH}"
    )


if __name__ == "__main__":
    main()