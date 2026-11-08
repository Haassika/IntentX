import csv
import json
from pathlib import Path

import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.pipeline import Pipeline


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
    / "intent_classifier_v1.joblib"
)

METRICS_PATH = (
    MODEL_DIR
    / "intent_classifier_v1_metrics.json"
)


def read_dataset(path):
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        rows = list(
            csv.DictReader(file)
        )

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
    """
    Baseline IntentX classifier.

    TF-IDF:
        word unigrams + bigrams

    Logistic Regression:
        probabilistic multiclass classifier
        with balanced class weighting.
    """

    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=1,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )


def evaluate(
    model,
    texts,
    labels,
):
    predictions = model.predict(
        texts
    )

    accuracy = accuracy_score(
        labels,
        predictions,
    )

    report = classification_report(
        labels,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    label_order = sorted(
        set(labels)
    )

    matrix = confusion_matrix(
        labels,
        predictions,
        labels=label_order,
    )

    return (
        accuracy,
        report,
        label_order,
        matrix,
    )


def save_metrics(
    accuracy,
    report,
    label_order,
    matrix,
):
    metrics = {
        "validation_accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix_labels": (
            label_order
        ),
        "confusion_matrix": (
            matrix.tolist()
        ),
    }

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
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


def main():
    print(
        "IntentX Baseline Intent Classifier"
    )
    print(
        "================================"
    )

    train_texts, train_labels = (
        read_dataset(
            TRAIN_PATH
        )
    )

    validation_texts, validation_labels = (
        read_dataset(
            VALIDATION_PATH
        )
    )

    print(
        f"Training examples: "
        f"{len(train_texts)}"
    )

    print(
        f"Validation examples: "
        f"{len(validation_texts)}"
    )

    print(
        f"Training classes: "
        f"{len(set(train_labels))}"
    )

    model = build_model()

    print(
        "\nTraining model..."
    )

    model.fit(
        train_texts,
        train_labels,
    )

    (
        accuracy,
        report,
        label_order,
        matrix,
    ) = evaluate(
        model,
        validation_texts,
        validation_labels,
    )

    print(
        "\n=== VALIDATION RESULTS ==="
    )

    print(
        f"Accuracy: "
        f"{accuracy:.4f}"
    )

    print(
        "\nPer-class metrics:"
    )

    for label in label_order:
        values = report[label]

        print(
            f"{label:25} "
            f"P={values['precision']:.3f} "
            f"R={values['recall']:.3f} "
            f"F1={values['f1-score']:.3f} "
            f"N={int(values['support'])}"
        )

    print(
        "\nOverall:"
    )

    print(
        f"Macro F1: "
        f"{report['macro avg']['f1-score']:.4f}"
    )

    print(
        f"Weighted F1: "
        f"{report['weighted avg']['f1-score']:.4f}"
    )

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    save_metrics(
        accuracy,
        report,
        label_order,
        matrix,
    )

    print(
        f"\nModel saved to:"
        f"\n{MODEL_PATH}"
    )

    print(
        f"\nMetrics saved to:"
        f"\n{METRICS_PATH}"
    )


if __name__ == "__main__":
    main()