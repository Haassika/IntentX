import csv
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

GOLD_PATH = (
    ROOT / "data" / "raw" / "intent_dataset.csv"
)

CANDIDATE_PATH = (
    ROOT
    / "data"
    / "candidates"
    / "generated_candidates.csv"
)

OUTPUT_PATH = (
    ROOT
    / "data"
    / "processed"
    / "intent_dataset_v1.csv"
)


def normalize_text(text):
    """Normalize text for duplicate comparison."""
    return " ".join(
        text.strip().lower().split()
    )


def read_csv(path):
    """Read a CSV file and return all rows."""
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(
            csv.DictReader(file)
        )


def normalize_entities(value):
    """
    Convert entity representation into compact,
    deterministic JSON.
    """

    if value is None:
        return "{}"

    value = value.strip()

    if not value:
        return "{}"

    try:
        parsed = json.loads(value)

    except json.JSONDecodeError:
        return value

    return json.dumps(
        parsed,
        sort_keys=True,
        separators=(",", ":"),
    )


def prepare_gold(rows):
    """
    Convert manually curated gold examples into
    the common dataset schema.

    Gold examples do not originate from generated
    template families, so they receive a special
    manual-family marker.
    """

    prepared = []

    for row in rows:
        prepared.append(
            {
                "text": row["text"].strip(),
                "intent": row["intent"].strip(),
                "action": row.get(
                    "action",
                    "",
                ).strip(),
                "entities": normalize_entities(
                    row.get(
                        "entities",
                        "{}",
                    )
                ),
                "template_family": "gold_manual",
                "source": "gold",
            }
        )

    return prepared


def prepare_candidates(rows):
    """
    Convert generated candidates into the common
    dataset schema while preserving template-family
    information.
    """

    prepared = []

    for row in rows:
        prepared.append(
            {
                "text": row["text"].strip(),
                "intent": row["intent"].strip(),
                "action": row.get(
                    "action",
                    "",
                ).strip(),
                "entities": normalize_entities(
                    row.get(
                        "entities",
                        "{}",
                    )
                ),
                "template_family": row.get(
                    "template_family",
                    "",
                ).strip(),
                "source": "generated",
            }
        )

    return prepared


def remove_candidate_gold_overlap(
    gold_rows,
    candidate_rows,
):
    """
    Remove generated examples whose normalized text
    already exists in the manually curated gold dataset.
    """

    gold_texts = {
        normalize_text(row["text"])
        for row in gold_rows
    }

    filtered = []
    removed = []

    for row in candidate_rows:
        normalized = normalize_text(
            row["text"]
        )

        if normalized in gold_texts:
            removed.append(row)
        else:
            filtered.append(row)

    return filtered, removed


def remove_internal_duplicates(rows):
    """
    Remove exact text duplicates inside the generated
    candidate dataset.
    """

    seen = set()
    unique = []
    duplicates = []

    for row in rows:
        normalized = normalize_text(
            row["text"]
        )

        if normalized in seen:
            duplicates.append(row)
            continue

        seen.add(normalized)
        unique.append(row)

    return unique, duplicates


def detect_cross_intent_conflicts(rows):
    """
    Detect identical normalized text mapped to
    multiple intent labels.
    """

    text_to_intents = {}

    for row in rows:
        normalized = normalize_text(
            row["text"]
        )

        text_to_intents.setdefault(
            normalized,
            set(),
        ).add(
            row["intent"]
        )

    conflicts = {
        text: intents
        for text, intents
        in text_to_intents.items()
        if len(intents) > 1
    }

    return conflicts


def validate_template_families(rows):
    """
    Ensure every generated example retains its
    template-family metadata.
    """

    missing = []

    for row in rows:
        if (
            row["source"] == "generated"
            and not row["template_family"]
        ):
            missing.append(row)

    return missing


def write_dataset(rows):
    """Write assembled Dataset V1."""

    OUTPUT_PATH.parent.mkdir(
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

    with OUTPUT_PATH.open(
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


def main():
    gold_raw = read_csv(
        GOLD_PATH
    )

    candidates_raw = read_csv(
        CANDIDATE_PATH
    )

    gold = prepare_gold(
        gold_raw
    )

    candidates = prepare_candidates(
        candidates_raw
    )

    candidates, overlap_removed = (
        remove_candidate_gold_overlap(
            gold,
            candidates,
        )
    )

    candidates, internal_duplicates = (
        remove_internal_duplicates(
            candidates
        )
    )

    combined = (
        gold + candidates
    )

    conflicts = detect_cross_intent_conflicts(
        combined
    )

    missing_template_families = (
        validate_template_families(
            combined
        )
    )

    print("IntentX Dataset Assembly")
    print("========================")

    print(
        f"Gold examples: "
        f"{len(gold)}"
    )

    print(
        f"Generated candidates read: "
        f"{len(candidates_raw)}"
    )

    print(
        f"Gold/generated overlaps removed: "
        f"{len(overlap_removed)}"
    )

    print(
        f"Generated internal duplicates removed: "
        f"{len(internal_duplicates)}"
    )

    print(
        f"Cross-intent conflicts: "
        f"{len(conflicts)}"
    )

    print(
        "Missing generated template families: "
        f"{len(missing_template_families)}"
    )

    if conflicts:
        print(
            "\n=== CROSS-INTENT CONFLICTS ==="
        )

        for text, intents in sorted(
            conflicts.items()
        ):
            print(
                f"{text!r} -> "
                f"{sorted(intents)}"
            )

        raise SystemExit(
            "\nDataset assembly stopped because "
            "cross-intent conflicts were found."
        )

    if missing_template_families:
        print(
            "\n=== MISSING TEMPLATE FAMILIES ==="
        )

        for row in (
            missing_template_families[:20]
        ):
            print(
                f"{row['intent']}: "
                f"{row['text']!r}"
            )

        raise SystemExit(
            "\nDataset assembly stopped because "
            "generated examples are missing "
            "template-family metadata."
        )

    write_dataset(
        combined
    )

    counts = Counter(
        row["intent"]
        for row in combined
    )

    source_counts = Counter(
        row["source"]
        for row in combined
    )

    print(
        f"Final examples: "
        f"{len(combined)}"
    )

    print("\n=== SOURCE DISTRIBUTION ===")

    for source, count in sorted(
        source_counts.items()
    ):
        print(
            f"{source:15} {count}"
        )

    print("\n=== CLASS DISTRIBUTION ===")

    for intent, count in sorted(
        counts.items()
    ):
        print(
            f"{intent:25} {count}"
        )

    print(
        f"\nClasses represented: "
        f"{len(counts)}"
    )

    print(
        f"\nOutput: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()