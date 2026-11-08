import csv
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
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

    return texts, labels


def classifier():
    return LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        random_state=42,
    )


def build_models():
    return {

        # ----------------------------------------------------
        # Existing baseline
        # ----------------------------------------------------

        "word_1_2": Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        lowercase=True,
                        ngram_range=(1, 2),
                        sublinear_tf=True,
                    ),
                ),
                (
                    "classifier",
                    classifier(),
                ),
            ]
        ),

        # ----------------------------------------------------
        # Longer word phrases
        # ----------------------------------------------------

        "word_1_3": Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        lowercase=True,
                        ngram_range=(1, 3),
                        sublinear_tf=True,
                    ),
                ),
                (
                    "classifier",
                    classifier(),
                ),
            ]
        ),

        # ----------------------------------------------------
        # Character features
        #
        # Useful for lexical/morphological patterns and
        # previously unseen combinations.
        # ----------------------------------------------------

        "char_3_5": Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        ngram_range=(3, 5),
                        sublinear_tf=True,
                        min_df=1,
                    ),
                ),
                (
                    "classifier",
                    classifier(),
                ),
            ]
        ),

        # ----------------------------------------------------
        # Combined word + character representation
        # ----------------------------------------------------

        "word_char": Pipeline(
            [
                (
                    "features",
                    FeatureUnion(
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
                    ),
                ),
                (
                    "classifier",
                    classifier(),
                ),
            ]
        ),
    }


def evaluate_model(
    name,
    model,
    train_texts,
    train_labels,
    validation_texts,
    validation_labels,
):
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

    macro_f1 = f1_score(
        validation_labels,
        predictions,
        average="macro",
        zero_division=0,
    )

    weighted_f1 = f1_score(
        validation_labels,
        predictions,
        average="weighted",
        zero_division=0,
    )

    return {
        "name": name,
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
    }


def main():
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
        "IntentX Model Comparison"
    )
    print(
        "========================"
    )

    print(
        f"Training examples: "
        f"{len(train_texts)}"
    )

    print(
        f"Validation examples: "
        f"{len(validation_texts)}"
    )

    models = build_models()

    results = []

    for name, model in models.items():

        print(
            f"\nTraining: {name}"
        )

        result = evaluate_model(
            name,
            model,
            train_texts,
            train_labels,
            validation_texts,
            validation_labels,
        )

        results.append(
            result
        )

        print(
            f"Accuracy:    "
            f"{result['accuracy']:.4f}"
        )

        print(
            f"Macro F1:    "
            f"{result['macro_f1']:.4f}"
        )

        print(
            f"Weighted F1: "
            f"{result['weighted_f1']:.4f}"
        )

    results.sort(
        key=lambda item: (
            item["macro_f1"],
            item["accuracy"],
        ),
        reverse=True,
    )

    print(
        "\n=== RANKING BY MACRO F1 ==="
    )

    for index, result in enumerate(
        results,
        start=1,
    ):
        print(
            f"{index}. "
            f"{result['name']:12} "
            f"accuracy={result['accuracy']:.4f} "
            f"macro_f1={result['macro_f1']:.4f} "
            f"weighted_f1={result['weighted_f1']:.4f}"
        )


if __name__ == "__main__":
    main()