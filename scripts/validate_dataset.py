import csv
import json
import sys
from collections import Counter
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = ROOT / "data" / "raw" / "intent_dataset.csv"
CATALOG_PATH = ROOT / "configs" / "intent_catalog.yaml"

REQUIRED_COLUMNS = {
    "example_id",
    "text",
    "intent",
    "action",
    "entities",
    "source",
    "split",
}

ALLOWED_SOURCES = {
    "curated",
    "synthetic_reviewed",
}

ALLOWED_SPLITS = {
    "",
    "train",
    "validation",
    "test",
}


def load_catalog():
    with CATALOG_PATH.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_dataset():
    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        columns = set(reader.fieldnames or [])

    return rows, columns


def validate():
    errors = []

    catalog = load_catalog()
    intents = catalog["intents"]

    rows, columns = load_dataset()

    missing_columns = REQUIRED_COLUMNS - columns

    if missing_columns:
        errors.append(
            f"Missing columns: {sorted(missing_columns)}"
        )

    seen_ids = set()
    seen_text = {}

    class_counts = Counter()

    for line_number, row in enumerate(rows, start=2):
        example_id = row.get("example_id", "").strip()
        text = row.get("text", "").strip()
        intent = row.get("intent", "").strip()
        action = row.get("action", "").strip()
        entities_raw = row.get("entities", "").strip()
        source = row.get("source", "").strip()
        split = row.get("split", "").strip()

        if not example_id:
            errors.append(
                f"Line {line_number}: missing example_id"
            )

        elif example_id in seen_ids:
            errors.append(
                f"Line {line_number}: duplicate ID {example_id}"
            )

        seen_ids.add(example_id)

        if not text:
            errors.append(
                f"Line {line_number}: text is empty"
            )

        normalized_text = " ".join(text.lower().split())

        if normalized_text in seen_text:
            errors.append(
                f"Line {line_number}: duplicate text; "
                f"first seen at line {seen_text[normalized_text]}"
            )
        else:
            seen_text[normalized_text] = line_number

        if intent not in intents:
            errors.append(
                f"Line {line_number}: unknown intent '{intent}'"
            )
            continue

        class_counts[intent] += 1

        valid_actions = intents[intent].get("actions", [])

        if action and action not in valid_actions:
            errors.append(
                f"Line {line_number}: action '{action}' "
                f"is invalid for intent '{intent}'"
            )

        try:
            entities = json.loads(entities_raw)
        except json.JSONDecodeError:
            errors.append(
                f"Line {line_number}: entities is not valid JSON"
            )
            entities = {}

        if not isinstance(entities, dict):
            errors.append(
                f"Line {line_number}: entities must be a JSON object"
            )
            entities = {}

        required_entities = intents[intent].get(
            "required_entities",
            [],
        )

        for required_entity in required_entities:
            if required_entity not in entities:
                errors.append(
                    f"Line {line_number}: required entity "
                    f"'{required_entity}' missing"
                )

        if source not in ALLOWED_SOURCES:
            errors.append(
                f"Line {line_number}: invalid source '{source}'"
            )

        if split not in ALLOWED_SPLITS:
            errors.append(
                f"Line {line_number}: invalid split '{split}'"
            )

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows: {len(rows)}")
    print(f"Classes represented: {len(class_counts)}")

    if class_counts:
        print("\nClass counts:")

        for intent, count in sorted(class_counts.items()):
            print(f"  {intent:25} {count}")

    if errors:
        print("\nVALIDATION FAILED\n")

        for error in errors:
            print(f"- {error}")

        return 1

    print("\nDataset validation successful.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())