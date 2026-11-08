import csv
import hashlib
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    ROOT
    / "data"
    / "processed"
    / "intent_dataset_v1.csv"
)

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

TEST_PATH = (
    ROOT
    / "data"
    / "processed"
    / "test.csv"
)


SPLIT_RATIOS = {
    "train": 0.70,
    "validation": 0.15,
    "test": 0.15,
}


def read_dataset():
    with INPUT_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def normalize_text(text):
    return " ".join(
        text.lower().strip().split()
    )


def stable_hash(value):
    digest = hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()

    return int(
        digest[:16],
        16,
    )


def build_group_key(row, index):
    """
    Generated examples from the same intent/action/template
    family must remain together.

    Gold examples receive independent deterministic groups.
    """

    if row["source"] == "generated":
        return (
            "generated",
            row["intent"],
            row["action"],
            row["template_family"],
        )

    return (
        "gold",
        row["intent"],
        f"manual_{index}",
    )


def build_groups_by_intent(rows):
    groups_by_intent = defaultdict(
        lambda: defaultdict(list)
    )

    for index, row in enumerate(rows):
        intent = row["intent"]

        key = build_group_key(
            row,
            index,
        )

        groups_by_intent[
            intent
        ][key].append(row)

    return groups_by_intent


def choose_split(
    group_size,
    current_counts,
    target_counts,
):
    """
    Choose the split whose per-intent target is
    currently most under-filled.

    A small overshoot penalty discourages assigning
    large template groups to already-full splits.
    """

    best_split = None
    best_score = None

    for split in SPLIT_RATIOS:
        target = target_counts[split]
        current = current_counts[split]

        projected = current + group_size

        if target <= 0:
            score = float("-inf")

        else:
            deficit = (
                target - current
            ) / target

            overshoot = max(
                0,
                projected - target,
            ) / target

            score = (
                deficit
                - (1.5 * overshoot)
            )

        if (
            best_score is None
            or score > best_score
        ):
            best_score = score
            best_split = split

    return best_split


def assign_intent_groups(
    intent,
    groups,
):
    """
    Assign groups for one intent independently.

    This preserves approximate class stratification
    while maintaining template-family isolation.
    """

    total_rows = sum(
        len(rows)
        for rows in groups.values()
    )

    target_counts = {
        split: total_rows * ratio
        for split, ratio
        in SPLIT_RATIOS.items()
    }

    current_counts = {
        split: 0
        for split in SPLIT_RATIOS
    }

    assignments = {}

    ordered_groups = sorted(
        groups.items(),
        key=lambda item: (
            -len(item[1]),
            stable_hash(
                repr(item[0])
            ),
        ),
    )

    # --------------------------------------------------------
    # Coverage pass
    #
    # If at least three independent groups exist, place one
    # group into each split before normal balancing.
    # --------------------------------------------------------

    remaining = list(
        ordered_groups
    )

    if len(remaining) >= 3:

        initial_order = [
            "train",
            "validation",
            "test",
        ]

        for split in initial_order:
            key, rows = remaining.pop(0)

            assignments[key] = split

            current_counts[
                split
            ] += len(rows)

    # --------------------------------------------------------
    # Balance remaining groups within this intent.
    # --------------------------------------------------------

    for key, rows in remaining:

        split = choose_split(
            len(rows),
            current_counts,
            target_counts,
        )

        assignments[key] = split

        current_counts[
            split
        ] += len(rows)

    return assignments


def create_splits(rows):
    groups_by_intent = (
        build_groups_by_intent(rows)
    )

    all_assignments = {}

    for intent in sorted(
        groups_by_intent
    ):
        assignments = (
            assign_intent_groups(
                intent,
                groups_by_intent[intent],
            )
        )

        all_assignments.update(
            assignments
        )

    split_rows = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for index, row in enumerate(rows):

        key = build_group_key(
            row,
            index,
        )

        split = all_assignments[
            key
        ]

        split_rows[
            split
        ].append(row)

    return split_rows


def write_csv(path, rows):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "text",
        "intent",
        "action",
        "entities",
        "template_family",
        "source",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def check_text_leakage(split_rows):
    locations = defaultdict(set)

    for split, rows in split_rows.items():

        for row in rows:

            locations[
                normalize_text(
                    row["text"]
                )
            ].add(split)

    return {
        text: splits
        for text, splits
        in locations.items()
        if len(splits) > 1
    }


def check_generated_group_leakage(
    split_rows,
):
    locations = defaultdict(set)

    for split, rows in split_rows.items():

        for row in rows:

            if (
                row["source"]
                != "generated"
            ):
                continue

            key = (
                row["intent"],
                row["action"],
                row["template_family"],
            )

            locations[key].add(
                split
            )

    return {
        key: splits
        for key, splits
        in locations.items()
        if len(splits) > 1
    }


def get_intent_distribution(
    split_rows,
):
    distributions = {}

    for split, rows in (
        split_rows.items()
    ):
        distributions[split] = Counter(
            row["intent"]
            for row in rows
        )

    return distributions


def check_class_coverage(
    split_rows,
):
    """
    Determine which intent classes are absent
    from each split.
    """

    all_intents = {
        row["intent"]
        for rows in split_rows.values()
        for row in rows
    }

    missing = {}

    for split, rows in (
        split_rows.items()
    ):

        present = {
            row["intent"]
            for row in rows
        }

        missing[split] = sorted(
            all_intents - present
        )

    return missing


def print_distribution(
    split,
    rows,
):
    counts = Counter(
        row["intent"]
        for row in rows
    )

    print(
        f"\n=== {split.upper()} ==="
    )

    print(
        f"Rows: {len(rows)}"
    )

    for intent, count in sorted(
        counts.items()
    ):
        print(
            f"{intent:25} {count}"
        )


def main():
    rows = read_dataset()

    print(
        "IntentX Stratified "
        "Group-Aware Dataset Split"
    )

    print(
        "=========================================="
    )

    print(
        f"Input examples: {len(rows)}"
    )

    split_rows = create_splits(
        rows
    )

    text_leakage = (
        check_text_leakage(
            split_rows
        )
    )

    group_leakage = (
        check_generated_group_leakage(
            split_rows
        )
    )

    coverage = (
        check_class_coverage(
            split_rows
        )
    )

    print(
        f"Text leakage conflicts: "
        f"{len(text_leakage)}"
    )

    print(
        "Generated group leakage conflicts: "
        f"{len(group_leakage)}"
    )

    if text_leakage:
        raise SystemExit(
            "Split failed: text leakage detected."
        )

    if group_leakage:
        raise SystemExit(
            "Split failed: generated template "
            "family leakage detected."
        )

    for split in (
        "train",
        "validation",
        "test",
    ):
        missing = coverage[
            split
        ]

        print(
            f"{split.title()} missing classes: "
            f"{len(missing)}"
        )

        if missing:
            print(
                "  "
                + ", ".join(missing)
            )

    write_csv(
        TRAIN_PATH,
        split_rows["train"],
    )

    write_csv(
        VALIDATION_PATH,
        split_rows["validation"],
    )

    write_csv(
        TEST_PATH,
        split_rows["test"],
    )

    for split in (
        "train",
        "validation",
        "test",
    ):
        print_distribution(
            split,
            split_rows[split],
        )

    total = len(rows)

    print(
        "\n=== FINAL SPLIT SIZES ==="
    )

    for split, data in (
        split_rows.items()
    ):

        count = len(data)

        percentage = (
            count / total * 100
        )

        print(
            f"{split:12} "
            f"{count:4} "
            f"({percentage:.2f}%)"
        )

    print(
        "\nSplit completed successfully."
    )


if __name__ == "__main__":
    main()