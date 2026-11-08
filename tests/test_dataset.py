import csv
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CATALOG_PATH = ROOT / "configs" / "intent_catalog.yaml"

DATASET_PATH = (
    ROOT
    / "data"
    / "processed"
    / "intent_dataset_v1.csv"
)

SPLIT_PATHS = {
    "train": ROOT / "data" / "processed" / "train.csv",
    "validation": ROOT / "data" / "processed" / "validation.csv",
    "test": ROOT / "data" / "processed" / "test.csv",
}


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def normalize_text(text):
    return " ".join(
        text.lower().strip().split()
    )


def test_processed_dataset_exists():
    assert DATASET_PATH.exists()


def test_all_split_files_exist():
    for path in SPLIT_PATHS.values():
        assert path.exists()


def test_dataset_has_expected_schema():
    rows = read_csv(DATASET_PATH)

    assert rows

    expected = {
        "text",
        "intent",
        "action",
        "entities",
        "template_family",
        "source",
    }

    assert set(rows[0].keys()) == expected


def test_dataset_has_21_intents():
    rows = read_csv(DATASET_PATH)

    intents = {
        row["intent"]
        for row in rows
    }

    assert len(intents) == 21


def test_no_empty_text_or_intent():
    rows = read_csv(DATASET_PATH)

    for row in rows:
        assert row["text"].strip()
        assert row["intent"].strip()


def test_generated_rows_have_template_family():
    rows = read_csv(DATASET_PATH)

    for row in rows:
        if row["source"] == "generated":
            assert row[
                "template_family"
            ].strip()


def test_no_duplicate_normalized_text():
    rows = read_csv(DATASET_PATH)

    normalized = [
        normalize_text(row["text"])
        for row in rows
    ]

    assert len(normalized) == len(
        set(normalized)
    )


def test_split_rows_reconstruct_dataset():
    dataset_rows = read_csv(
        DATASET_PATH
    )

    split_rows = []

    for path in SPLIT_PATHS.values():
        split_rows.extend(
            read_csv(path)
        )

    assert len(split_rows) == len(
        dataset_rows
    )

    dataset_texts = {
        normalize_text(row["text"])
        for row in dataset_rows
    }

    split_texts = {
        normalize_text(row["text"])
        for row in split_rows
    }

    assert split_texts == dataset_texts


def test_no_text_leakage_between_splits():
    locations = defaultdict(set)

    for split, path in (
        SPLIT_PATHS.items()
    ):
        for row in read_csv(path):
            locations[
                normalize_text(
                    row["text"]
                )
            ].add(split)

    leaked = {
        text: splits
        for text, splits
        in locations.items()
        if len(splits) > 1
    }

    assert leaked == {}


def test_no_generated_template_group_leakage():
    locations = defaultdict(set)

    for split, path in (
        SPLIT_PATHS.items()
    ):
        for row in read_csv(path):

            if row["source"] != "generated":
                continue

            key = (
                row["intent"],
                row["action"],
                row["template_family"],
            )

            locations[key].add(split)

    leaked = {
        key: splits
        for key, splits
        in locations.items()
        if len(splits) > 1
    }

    assert leaked == {}


def test_every_split_contains_all_intents():
    dataset_rows = read_csv(
        DATASET_PATH
    )

    expected_intents = {
        row["intent"]
        for row in dataset_rows
    }

    assert len(expected_intents) == 21

    for path in SPLIT_PATHS.values():
        rows = read_csv(path)

        actual_intents = {
            row["intent"]
            for row in rows
        }

        assert actual_intents == (
            expected_intents
        )