import csv
from collections import Counter
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "data" / "raw" / "intent_dataset.csv"

NEAR_DUPLICATE_THRESHOLD = 0.80
CROSS_INTENT_THRESHOLD = 0.65


def load_dataset():
    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def normalize_text(text):
    return " ".join(text.lower().split())


def print_class_distribution(rows):
    counts = Counter(row["intent"] for row in rows)

    print("\n=== CLASS DISTRIBUTION ===")

    for intent, count in sorted(counts.items()):
        print(f"{intent:25} {count}")

    return counts


def print_text_statistics(rows):
    lengths = [
        len(row["text"].split())
        for row in rows
    ]

    print("\n=== TEXT STATISTICS ===")

    if not lengths:
        print("No examples found.")
        return

    print(f"Examples: {len(lengths)}")
    print(f"Minimum words: {min(lengths)}")
    print(f"Maximum words: {max(lengths)}")
    print(
        f"Average words: "
        f"{sum(lengths) / len(lengths):.2f}"
    )


def find_exact_duplicates(rows):
    seen = {}
    duplicates = []

    for row in rows:
        normalized = normalize_text(row["text"])

        if normalized in seen:
            duplicates.append(
                (
                    seen[normalized],
                    row,
                )
            )
        else:
            seen[normalized] = row

    print("\n=== EXACT DUPLICATES ===")

    if not duplicates:
        print("None found.")
        return

    for first, second in duplicates:
        print(
            f"{first['example_id']} <-> "
            f"{second['example_id']}"
        )
        print(f"  {first['text']}")
        print(f"  {second['text']}")


def calculate_similarity(rows):
    texts = [row["text"] for row in rows]

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
    )

    matrix = vectorizer.fit_transform(texts)

    return cosine_similarity(matrix)


def find_near_duplicates(rows, similarities):
    matches = []

    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            score = similarities[i, j]

            if (
                score >= NEAR_DUPLICATE_THRESHOLD
                and rows[i]["intent"] == rows[j]["intent"]
            ):
                matches.append(
                    (
                        score,
                        rows[i],
                        rows[j],
                    )
                )

    matches.sort(
        key=lambda item: item[0],
        reverse=True,
    )

    print("\n=== SAME-INTENT NEAR DUPLICATES ===")
    print(
        f"Threshold: {NEAR_DUPLICATE_THRESHOLD:.2f}"
    )

    if not matches:
        print("None found.")
        return

    for score, first, second in matches:
        print(f"\nSimilarity: {score:.3f}")
        print(
            f"{first['example_id']} "
            f"[{first['intent']}]"
        )
        print(f"  {first['text']}")

        print(
            f"{second['example_id']} "
            f"[{second['intent']}]"
        )
        print(f"  {second['text']}")


def find_cross_intent_similarity(rows, similarities):
    matches = []

    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            score = similarities[i, j]

            if (
                score >= CROSS_INTENT_THRESHOLD
                and rows[i]["intent"] != rows[j]["intent"]
            ):
                matches.append(
                    (
                        score,
                        rows[i],
                        rows[j],
                    )
                )

    matches.sort(
        key=lambda item: item[0],
        reverse=True,
    )

    print("\n=== CROSS-INTENT SIMILARITY ===")
    print(
        f"Threshold: {CROSS_INTENT_THRESHOLD:.2f}"
    )

    if not matches:
        print("None found.")
        return

    for score, first, second in matches:
        print(f"\nSimilarity: {score:.3f}")

        print(
            f"{first['example_id']} "
            f"[{first['intent']}]"
        )
        print(f"  {first['text']}")

        print(
            f"{second['example_id']} "
            f"[{second['intent']}]"
        )
        print(f"  {second['text']}")


def main():
    rows = load_dataset()

    print("IntentX Dataset Analysis")
    print("========================")
    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows: {len(rows)}")

    if not rows:
        print("Dataset is empty.")
        return

    print_class_distribution(rows)
    print_text_statistics(rows)
    find_exact_duplicates(rows)

    similarities = calculate_similarity(rows)

    find_near_duplicates(
        rows,
        similarities,
    )

    find_cross_intent_similarity(
        rows,
        similarities,
    )


if __name__ == "__main__":
    main()