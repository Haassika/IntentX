import csv
import json
import sys
from pathlib import Path

import yaml
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


ROOT = Path(__file__).resolve().parents[1]

CANDIDATE_PATH = (
    ROOT
    / "data"
    / "candidates"
    / "generated_candidates.csv"
)

GOLD_PATH = (
    ROOT
    / "data"
    / "raw"
    / "intent_dataset.csv"
)

CATALOG_PATH = (
    ROOT
    / "configs"
    / "intent_catalog.yaml"
)

REQUIRED_COLUMNS = {
    "text",
    "intent",
    "action",
    "entities",
}

SIMILARITY_THRESHOLD = 0.60


def normalize_text(text):
    """Normalize text for exact duplicate comparison."""
    return " ".join(text.lower().split())


def load_catalog():
    """Load the IntentX intent catalog."""
    with CATALOG_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def load_csv(path):
    """Load a CSV file and return rows and column names."""
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        columns = set(reader.fieldnames or [])

    return rows, columns


def analyze_similarity(candidates, gold_rows):
    """
    Compare candidate examples against gold examples using
    TF-IDF vectors and cosine similarity.

    For each candidate, retain its most similar gold example
    when the similarity score meets the configured threshold.
    """
    candidate_texts = [
        row["text"].strip()
        for row in candidates
        if row.get("text", "").strip()
    ]

    gold_texts = [
        row["text"].strip()
        for row in gold_rows
        if row.get("text", "").strip()
    ]

    if not candidate_texts or not gold_texts:
        return []

    all_texts = gold_texts + candidate_texts

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
    )

    matrix = vectorizer.fit_transform(all_texts)

    gold_matrix = matrix[:len(gold_texts)]
    candidate_matrix = matrix[len(gold_texts):]

    similarities = cosine_similarity(
        candidate_matrix,
        gold_matrix,
    )

    matches = []

    for candidate_index, scores in enumerate(
        similarities
    ):
        best_gold_index = scores.argmax()
        best_score = float(scores[best_gold_index])

        if best_score >= SIMILARITY_THRESHOLD:
            matches.append(
                (
                    best_score,
                    candidate_texts[candidate_index],
                    gold_texts[best_gold_index],
                )
            )

    matches.sort(
        key=lambda item: item[0],
        reverse=True,
    )

    return matches


def validate():
    """Validate generated IntentX candidate examples."""
    errors = []
    warnings = []

    catalog = load_catalog()
    intents = catalog["intents"]

    candidates, columns = load_csv(
        CANDIDATE_PATH
    )

    gold_rows, _ = load_csv(
        GOLD_PATH
    )

    # ---------------------------------------------------------
    # Validate candidate CSV structure
    # ---------------------------------------------------------

    missing_columns = REQUIRED_COLUMNS - columns

    if missing_columns:
        errors.append(
            f"Missing columns: "
            f"{sorted(missing_columns)}"
        )

    # ---------------------------------------------------------
    # Prepare duplicate detection
    # ---------------------------------------------------------

    gold_texts = {
        normalize_text(row["text"])
        for row in gold_rows
        if row.get("text", "").strip()
    }

    seen_candidate_texts = set()

    # ---------------------------------------------------------
    # Validate individual candidate rows
    # ---------------------------------------------------------

    for line_number, row in enumerate(
        candidates,
        start=2,
    ):
        text = row.get("text", "").strip()
        intent = row.get("intent", "").strip()
        action = row.get("action", "").strip()

        entities_raw = (
            row.get("entities", "").strip()
        )

        # -----------------------------------------------------
        # Text validation
        # -----------------------------------------------------

        if not text:
            errors.append(
                f"Line {line_number}: "
                "text is empty"
            )
            continue

        normalized = normalize_text(text)

        # Candidate-to-candidate exact duplicate
        if normalized in seen_candidate_texts:
            errors.append(
                f"Line {line_number}: "
                "duplicate candidate text"
            )

        seen_candidate_texts.add(normalized)

        # Candidate-to-gold exact duplicate
        if normalized in gold_texts:
            warnings.append(
                f"Line {line_number}: "
                f"already exists in gold dataset: "
                f"'{text}'"
            )

        # -----------------------------------------------------
        # Intent validation
        # -----------------------------------------------------

        if intent not in intents:
            errors.append(
                f"Line {line_number}: "
                f"unknown intent '{intent}'"
            )
            continue

        # -----------------------------------------------------
        # Action validation
        # -----------------------------------------------------

        valid_actions = intents[intent].get(
            "actions",
            [],
        )

        if action not in valid_actions:
            errors.append(
                f"Line {line_number}: "
                f"invalid action '{action}' "
                f"for intent '{intent}'"
            )

        # -----------------------------------------------------
        # Entity JSON validation
        # -----------------------------------------------------

        try:
            entities = json.loads(
                entities_raw
            )

        except json.JSONDecodeError:
            errors.append(
                f"Line {line_number}: "
                "entities is not valid JSON"
            )
            continue

        if not isinstance(entities, dict):
            errors.append(
                f"Line {line_number}: "
                "entities must be a JSON object"
            )
            continue

        # -----------------------------------------------------
        # Entity schema validation
        # -----------------------------------------------------

        allowed_entities = set(
            intents[intent].get(
                "entities",
                [],
            )
        )

        required_entities = set(
            intents[intent].get(
                "required_entities",
                [],
            )
        )

        supplied_entities = set(
            entities.keys()
        )

        unknown_entities = (
            supplied_entities
            - allowed_entities
        )

        if unknown_entities:
            errors.append(
                f"Line {line_number}: "
                "unsupported entities "
                f"{sorted(unknown_entities)}"
            )

        missing_entities = (
            required_entities
            - supplied_entities
        )

        if missing_entities:
            errors.append(
                f"Line {line_number}: "
                "missing required entities "
                f"{sorted(missing_entities)}"
            )

    # ---------------------------------------------------------
    # Similarity analysis
    # ---------------------------------------------------------

    similarity_matches = analyze_similarity(
        candidates,
        gold_rows,
    )

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------

    print("IntentX Candidate Validation")
    print("============================")

    print(
        f"Candidates: {len(candidates)}"
    )

    print(
        f"Gold examples: {len(gold_rows)}"
    )

    print(
        f"Errors: {len(errors)}"
    )

    print(
        f"Warnings: {len(warnings)}"
    )

    print(
        "Near-similar candidate/gold pairs: "
        f"{len(similarity_matches)}"
    )

    print(
        "Similarity threshold: "
        f"{SIMILARITY_THRESHOLD:.2f}"
    )

    # ---------------------------------------------------------
    # Warnings
    # ---------------------------------------------------------

    if warnings:
        print("\n=== WARNINGS ===")

        for warning in warnings:
            print(f"- {warning}")

    # ---------------------------------------------------------
    # Near-similarity report
    # ---------------------------------------------------------

    if similarity_matches:
        print(
            "\n=== NEAR-SIMILAR "
            "GOLD/CANDIDATE PAIRS ==="
        )

        for score, candidate, gold in similarity_matches:
            print(
                f"\nSimilarity: {score:.3f}"
            )

            print(
                f"Candidate: {candidate}"
            )

            print(
                f"Gold:      {gold}"
            )

    # ---------------------------------------------------------
    # Errors
    # ---------------------------------------------------------

    if errors:
        print("\n=== ERRORS ===")

        for error in errors:
            print(f"- {error}")

        print(
            "\nCandidate validation FAILED."
        )

        return 1

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    print(
        "\nCandidate validation successful."
    )

    return 0


if __name__ == "__main__":
    sys.exit(validate())