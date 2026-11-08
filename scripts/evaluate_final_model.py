"""Final held-out evaluation for the IntentX V2 intent classifier.

This script evaluates the already-trained V2 model against the untouched
test partition. It does not train, refit, or modify the classifier.

The test partition must not be used for model selection or tuning.
"""

import csv
import json
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


ROOT = Path(__file__).resolve().parents[1]

TEST_PATH = (
    ROOT
    / "data"
    / "processed"
    / "test.csv"
)

MODEL_PATH = (
    ROOT
    / "models"
    / "intent_classifier_v2.joblib"
)

OUTPUT_PATH = (
    ROOT
    / "models"
    / "intent_classifier_v2_test_metrics.json"
)

CONFIDENCE_THRESHOLDS = (
    0.00,
    0.40,
    0.50,
    0.60,
    0.70,
    0.80,
    0.90,
)


def read_test_dataset():
    with TEST_PATH.open(
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

    return rows, texts, labels


def build_prediction_records(
    rows,
    labels,
    predictions,
    probabilities,
    classes,
):
    records = []

    for (
        row,
        actual,
        predicted,
        probs,
    ) in zip(
        rows,
        labels,
        predictions,
        probabilities,
    ):
        order = np.argsort(probs)[::-1]

        first_index = int(order[0])
        second_index = int(order[1])

        confidence = float(
            probs[first_index]
        )

        second_probability = float(
            probs[second_index]
        )

        margin = (
            confidence
            - second_probability
        )

        records.append(
            {
                "text": row["text"],
                "actual": actual,
                "predicted": str(predicted),
                "correct": (
                    actual == predicted
                ),
                "confidence": confidence,
                "second_label": str(
                    classes[second_index]
                ),
                "second_probability": (
                    second_probability
                ),
                "margin": float(margin),
                "source": row.get(
                    "source",
                    "",
                ),
                "template_family": row.get(
                    "template_family",
                    "",
                ),
            }
        )

    return records


def selective_metrics(
    records,
    threshold,
):
    accepted = [
        record
        for record in records
        if record["confidence"] >= threshold
    ]

    total = len(records)
    accepted_count = len(accepted)

    if accepted_count:
        correct_count = sum(
            record["correct"]
            for record in accepted
        )

        selective_accuracy = (
            correct_count
            / accepted_count
        )
    else:
        correct_count = 0
        selective_accuracy = None

    coverage = (
        accepted_count / total
        if total
        else 0.0
    )

    return {
        "threshold": threshold,
        "accepted": accepted_count,
        "rejected": total - accepted_count,
        "coverage": coverage,
        "correct_accepted": correct_count,
        "selective_accuracy": (
            selective_accuracy
        ),
    }


def main():
    print(
        "IntentX Final Held-Out Test Evaluation"
    )
    print(
        "======================================"
    )

    rows, texts, labels = (
        read_test_dataset()
    )

    print(
        f"Test examples: {len(rows)}"
    )

    print(
        f"Test intents: "
        f"{len(set(labels))}"
    )

    print(
        f"Model: {MODEL_PATH.name}"
    )

    model = joblib.load(
        MODEL_PATH
    )

    predictions = model.predict(
        texts
    )

    probabilities = model.predict_proba(
        texts
    )

    classes = model.classes_

    accuracy = accuracy_score(
        labels,
        predictions,
    )

    report = classification_report(
        labels,
        predictions,
        labels=list(classes),
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        labels,
        predictions,
        labels=list(classes),
    )

    records = build_prediction_records(
        rows,
        labels,
        predictions,
        probabilities,
        classes,
    )

    confusion_pairs = Counter(
        (
            record["actual"],
            record["predicted"],
        )
        for record in records
        if not record["correct"]
    )

    correct_confidences = [
        record["confidence"]
        for record in records
        if record["correct"]
    ]

    wrong_confidences = [
        record["confidence"]
        for record in records
        if not record["correct"]
    ]

    selective_results = [
        selective_metrics(
            records,
            threshold,
        )
        for threshold
        in CONFIDENCE_THRESHOLDS
    ]

    print(
        "\n=== FINAL TEST PERFORMANCE ==="
    )

    print(
        f"Accuracy:    {accuracy:.4f}"
    )

    print(
        "Macro F1:    "
        f"{report['macro avg']['f1-score']:.4f}"
    )

    print(
        "Weighted F1: "
        f"{report['weighted avg']['f1-score']:.4f}"
    )

    print(
        "\n=== PER-INTENT PERFORMANCE ==="
    )

    for label in classes:
        values = report[label]

        print(
            f"{label:25} "
            f"P={values['precision']:.3f} "
            f"R={values['recall']:.3f} "
            f"F1={values['f1-score']:.3f} "
            f"N={int(values['support'])}"
        )

    print(
        "\n=== CONFIDENCE SUMMARY ==="
    )

    print(
        "Average confidence correct: "
        f"{np.mean(correct_confidences):.4f}"
    )

    if wrong_confidences:
        print(
            "Average confidence wrong:   "
            f"{np.mean(wrong_confidences):.4f}"
        )
    else:
        print(
            "Average confidence wrong:   "
            "N/A"
        )

    print(
        "\n=== SELECTIVE CLASSIFICATION ==="
    )

    for result in selective_results:
        selective_accuracy = (
            result["selective_accuracy"]
        )

        accuracy_text = (
            f"{selective_accuracy:.4f}"
            if selective_accuracy is not None
            else "N/A"
        )

        print(
            f"threshold={result['threshold']:.2f} "
            f"coverage={result['coverage']:.2%} "
            f"accepted={result['accepted']:3d} "
            f"accuracy={accuracy_text}"
        )

    print(
        "\n=== TOP CONFUSION PAIRS ==="
    )

    if confusion_pairs:
        for (
            actual,
            predicted,
        ), count in confusion_pairs.most_common(
            15
        ):
            print(
                f"{actual:25} -> "
                f"{predicted:25} "
                f"{count}"
            )
    else:
        print(
            "No misclassifications."
        )

    errors = [
        record
        for record in records
        if not record["correct"]
    ]

    errors.sort(
        key=lambda record: (
            -record["confidence"],
            record["actual"],
            record["text"],
        )
    )

    output = {
        "evaluation_type": (
            "final_held_out_test"
        ),
        "model_version": "v2",
        "model_path": str(
            MODEL_PATH.relative_to(ROOT)
        ),
        "test_path": str(
            TEST_PATH.relative_to(ROOT)
        ),
        "test_examples": len(rows),
        "test_intents": len(
            set(labels)
        ),
        "accuracy": float(accuracy),
        "macro_f1": float(
            report["macro avg"]["f1-score"]
        ),
        "weighted_f1": float(
            report["weighted avg"]["f1-score"]
        ),
        "classification_report": report,
        "confusion_matrix_labels": [
            str(label)
            for label in classes
        ],
        "confusion_matrix": (
            matrix.tolist()
        ),
        "average_confidence_correct": (
            float(
                np.mean(
                    correct_confidences
                )
            )
            if correct_confidences
            else None
        ),
        "average_confidence_wrong": (
            float(
                np.mean(
                    wrong_confidences
                )
            )
            if wrong_confidences
            else None
        ),
        "selective_classification": (
            selective_results
        ),
        "confusion_pairs": [
            {
                "actual": actual,
                "predicted": predicted,
                "count": count,
            }
            for (
                actual,
                predicted,
            ), count
            in confusion_pairs.most_common()
        ],
        "misclassification_count": len(
            errors
        ),
        "misclassifications": errors,
    }

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            output,
            file,
            indent=2,
        )

    print(
        f"\nSaved final test metrics:"
        f"\n{OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
