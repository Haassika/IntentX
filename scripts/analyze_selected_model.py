import csv
from pathlib import Path

import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
)
from sklearn.pipeline import FeatureUnion, Pipeline


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

    return rows, texts, labels


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
    (
        train_rows,
        train_texts,
        train_labels,
    ) = read_dataset(TRAIN_PATH)

    (
        validation_rows,
        validation_texts,
        validation_labels,
    ) = read_dataset(VALIDATION_PATH)

    model = build_model()

    print(
        "IntentX Selected Model Analysis"
    )
    print(
        "==============================="
    )

    print(
        f"Training examples: "
        f"{len(train_rows)}"
    )

    print(
        f"Validation examples: "
        f"{len(validation_rows)}"
    )

    print(
        "\nTraining word_char model..."
    )

    model.fit(
        train_texts,
        train_labels,
    )

    predictions = model.predict(
        validation_texts
    )

    probabilities = model.predict_proba(
        validation_texts
    )

    classes = model.classes_

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

    print(
        "\n=== BASE VALIDATION PERFORMANCE ==="
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

    records = []

    for (
        row,
        actual,
        predicted,
        probs,
    ) in zip(
        validation_rows,
        validation_labels,
        predictions,
        probabilities,
    ):

        order = np.argsort(
            probs
        )[::-1]

        first_index = order[0]
        second_index = order[1]

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
                "predicted": predicted,
                "correct": (
                    actual == predicted
                ),
                "confidence": confidence,
                "second_label": (
                    classes[second_index]
                ),
                "second_probability": (
                    second_probability
                ),
                "margin": margin,
            }
        )

    correct = [
        item
        for item in records
        if item["correct"]
    ]

    wrong = [
        item
        for item in records
        if not item["correct"]
    ]

    print(
        "\n=== CONFIDENCE SUMMARY ==="
    )

    print(
        "Correct predictions: "
        f"{len(correct)}"
    )

    print(
        "Wrong predictions:   "
        f"{len(wrong)}"
    )

    print(
        "Average confidence correct: "
        f"{np.mean([x['confidence'] for x in correct]):.4f}"
    )

    print(
        "Average confidence wrong:   "
        f"{np.mean([x['confidence'] for x in wrong]):.4f}"
    )

    print(
        "Average margin correct:     "
        f"{np.mean([x['margin'] for x in correct]):.4f}"
    )

    print(
        "Average margin wrong:       "
        f"{np.mean([x['margin'] for x in wrong]):.4f}"
    )

    print(
        "\n=== CONFIDENCE-ONLY REJECTION ==="
    )

    thresholds = [
        0.20,
        0.25,
        0.30,
        0.35,
        0.40,
        0.45,
        0.50,
        0.60,
    ]

    for threshold in thresholds:

        accepted = [
            item
            for item in records
            if item["confidence"]
            >= threshold
        ]

        accepted_correct = sum(
            item["correct"]
            for item in accepted
        )

        coverage = (
            len(accepted)
            / len(records)
        )

        selective_accuracy = (
            accepted_correct
            / len(accepted)
            if accepted
            else 0.0
        )

        errors_accepted = (
            len(accepted)
            - accepted_correct
        )

        print(
            f"confidence>={threshold:.2f} "
            f"accepted={len(accepted):3} "
            f"coverage={coverage:6.2%} "
            f"accuracy={selective_accuracy:6.2%} "
            f"errors={errors_accepted}"
        )

    print(
        "\n=== CONFIDENCE + MARGIN REJECTION ==="
    )

    combinations = [
        (0.20, 0.03),
        (0.20, 0.05),
        (0.25, 0.03),
        (0.25, 0.05),
        (0.30, 0.03),
        (0.30, 0.05),
        (0.35, 0.03),
        (0.35, 0.05),
        (0.40, 0.03),
        (0.40, 0.05),
    ]

    for (
        confidence_threshold,
        margin_threshold,
    ) in combinations:

        accepted = [
            item
            for item in records
            if (
                item["confidence"]
                >= confidence_threshold
                and item["margin"]
                >= margin_threshold
            )
        ]

        accepted_correct = sum(
            item["correct"]
            for item in accepted
        )

        coverage = (
            len(accepted)
            / len(records)
        )

        selective_accuracy = (
            accepted_correct
            / len(accepted)
            if accepted
            else 0.0
        )

        errors_accepted = (
            len(accepted)
            - accepted_correct
        )

        print(
            f"conf>={confidence_threshold:.2f} "
            f"margin>={margin_threshold:.2f} "
            f"accepted={len(accepted):3} "
            f"coverage={coverage:6.2%} "
            f"accuracy={selective_accuracy:6.2%} "
            f"errors={errors_accepted}"
        )

    print(
        "\n=== HIGH-CONFIDENCE ERRORS ==="
    )

    wrong_sorted = sorted(
        wrong,
        key=lambda item: (
            item["confidence"]
        ),
        reverse=True,
    )

    for number, item in enumerate(
        wrong_sorted,
        start=1,
    ):

        print(
            f"\n[{number}] "
            f"{item['text']!r}"
        )

        print(
            f"    actual:     "
            f"{item['actual']}"
        )

        print(
            f"    predicted:  "
            f"{item['predicted']}"
        )

        print(
            f"    confidence: "
            f"{item['confidence']:.4f}"
        )

        print(
            f"    second:     "
            f"{item['second_label']} "
            f"({item['second_probability']:.4f})"
        )

        print(
            f"    margin:     "
            f"{item['margin']:.4f}"
        )


if __name__ == "__main__":
    main()