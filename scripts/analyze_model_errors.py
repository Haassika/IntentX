import csv
from collections import Counter, defaultdict
from pathlib import Path

import joblib


ROOT = Path(__file__).resolve().parents[1]

VALIDATION_PATH = (
    ROOT
    / "data"
    / "processed"
    / "validation.csv"
)

MODEL_PATH = (
    ROOT
    / "models"
    / "intent_classifier_v1.joblib"
)


def read_validation():
    with VALIDATION_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def main():
    rows = read_validation()

    model = joblib.load(
        MODEL_PATH
    )

    texts = [
        row["text"]
        for row in rows
    ]

    predictions = model.predict(
        texts
    )

    probabilities = model.predict_proba(
        texts
    )

    classes = list(
        model.classes_
    )

    errors = []
    confusion_pairs = Counter()

    for row, predicted, probs in zip(
        rows,
        predictions,
        probabilities,
    ):
        actual = row["intent"]

        predicted_index = (
            classes.index(predicted)
        )

        confidence = float(
            probs[predicted_index]
        )

        sorted_probs = sorted(
            zip(classes, probs),
            key=lambda item: item[1],
            reverse=True,
        )

        second_label = (
            sorted_probs[1][0]
        )

        second_probability = float(
            sorted_probs[1][1]
        )

        margin = (
            confidence
            - second_probability
        )

        if predicted != actual:

            confusion_pairs[
                (actual, predicted)
            ] += 1

            errors.append(
                {
                    "text": row["text"],
                    "actual": actual,
                    "predicted": predicted,
                    "confidence": confidence,
                    "second": second_label,
                    "second_probability": (
                        second_probability
                    ),
                    "margin": margin,
                    "source": row["source"],
                    "template_family": row[
                        "template_family"
                    ],
                }
            )

    print(
        "IntentX Validation Error Analysis"
    )

    print(
        "================================="
    )

    print(
        f"Validation examples: "
        f"{len(rows)}"
    )

    print(
        f"Correct predictions: "
        f"{len(rows) - len(errors)}"
    )

    print(
        f"Misclassifications: "
        f"{len(errors)}"
    )

    print(
        f"Error rate: "
        f"{len(errors) / len(rows):.2%}"
    )

    print(
        "\n=== CONFUSION PAIRS ==="
    )

    for (
        actual,
        predicted,
    ), count in confusion_pairs.most_common():

        print(
            f"{actual:25} -> "
            f"{predicted:25} "
            f"{count}"
        )

    print(
        "\n=== MISCLASSIFIED EXAMPLES ==="
    )

    errors.sort(
        key=lambda item: (
            -item["confidence"],
            item["actual"],
        )
    )

    for number, error in enumerate(
        errors,
        start=1,
    ):

        print(
            f"\n[{number}] "
            f"{error['text']!r}"
        )

        print(
            f"    actual:     "
            f"{error['actual']}"
        )

        print(
            f"    predicted:  "
            f"{error['predicted']}"
        )

        print(
            f"    confidence: "
            f"{error['confidence']:.4f}"
        )

        print(
            f"    second:     "
            f"{error['second']} "
            f"({error['second_probability']:.4f})"
        )

        print(
            f"    margin:     "
            f"{error['margin']:.4f}"
        )

        print(
            f"    source:     "
            f"{error['source']}"
        )

        print(
            f"    template:   "
            f"{error['template_family']}"
        )

    # --------------------------------------------------------
    # Confidence analysis
    # --------------------------------------------------------

    correct_confidences = []
    wrong_confidences = []

    for row, predicted, probs in zip(
        rows,
        predictions,
        probabilities,
    ):
        predicted_index = (
            classes.index(predicted)
        )

        confidence = float(
            probs[predicted_index]
        )

        if predicted == row["intent"]:
            correct_confidences.append(
                confidence
            )
        else:
            wrong_confidences.append(
                confidence
            )

    print(
        "\n=== CONFIDENCE SUMMARY ==="
    )

    if correct_confidences:
        print(
            "Average confidence when correct: "
            f"{sum(correct_confidences) / len(correct_confidences):.4f}"
        )

    if wrong_confidences:
        print(
            "Average confidence when wrong:   "
            f"{sum(wrong_confidences) / len(wrong_confidences):.4f}"
        )

    # --------------------------------------------------------
    # Confidence threshold simulation
    # --------------------------------------------------------

    print(
        "\n=== CONFIDENCE THRESHOLD SIMULATION ==="
    )

    thresholds = [
        0.40,
        0.50,
        0.60,
        0.70,
        0.80,
        0.90,
    ]

    for threshold in thresholds:

        accepted = 0
        accepted_correct = 0

        for row, predicted, probs in zip(
            rows,
            predictions,
            probabilities,
        ):

            predicted_index = (
                classes.index(predicted)
            )

            confidence = float(
                probs[predicted_index]
            )

            if confidence >= threshold:

                accepted += 1

                if predicted == row["intent"]:
                    accepted_correct += 1

        coverage = (
            accepted / len(rows)
        )

        if accepted:
            selective_accuracy = (
                accepted_correct / accepted
            )
        else:
            selective_accuracy = 0.0

        print(
            f"threshold={threshold:.2f}  "
            f"accepted={accepted:3}  "
            f"coverage={coverage:.2%}  "
            f"accuracy={selective_accuracy:.2%}"
        )


if __name__ == "__main__":
    main()