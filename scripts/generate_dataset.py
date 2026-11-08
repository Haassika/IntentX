import csv
import json
import random
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

GENERATION_CONFIG_PATH = (
    ROOT
    / "configs"
    / "dataset_generation.yaml"
)

OUTPUT_PATH = (
    ROOT
    / "data"
    / "candidates"
    / "generated_candidates.csv"
)

DEFAULT_TARGET_PER_INTENT = 100
RANDOM_SEED = 42


def load_generation_config():
    """Load dataset-generation configuration."""

    with GENERATION_CONFIG_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def get_variants(intent_config):
    """
    Normalize old single-definition and newer
    multi-variant intent configurations.
    """

    variants = intent_config.get("variants")

    if variants is not None:
        if not isinstance(variants, list):
            raise ValueError(
                "'variants' must be a list"
            )

        return variants

    return [intent_config]


def generate_variant(
    intent_name,
    variant,
    entity_pools,
):
    """
    Generate raw candidates for a variant supporting:
    - zero entities
    - one entity
    - multiple entities
    """

    action = variant.get("action", "")
    templates = variant.get("templates", [])

    if not action and intent_name != "out_of_scope":
        raise ValueError(
        f"Intent '{intent_name}' contains "
        "a variant without an action"
    )

    if not templates:
        raise ValueError(
            f"Intent '{intent_name}', action "
            f"'{action}' contains no templates"
        )

    expansion_entity = variant.get(
        "expansion_entity"
    )

    entity_name = variant.get(
        "entity_name"
    )

    expansion_entities = variant.get(
        "expansion_entities"
    )

    entity_names = variant.get(
        "entity_names"
    )

    examples = []

    # ---------------------------------------------------------
    # MULTIPLE ENTITIES
    # ---------------------------------------------------------

    if expansion_entities:
        if not isinstance(
            expansion_entities,
            dict,
        ):
            raise ValueError(
                f"Intent '{intent_name}': "
                "'expansion_entities' must be a mapping"
            )

        if not isinstance(
            entity_names,
            dict,
        ):
            raise ValueError(
                f"Intent '{intent_name}': "
                "'entity_names' must be a mapping"
            )

        variable_names = list(
            expansion_entities.keys()
        )

        value_pools = []

        for variable_name in variable_names:
            pool_name = expansion_entities[
                variable_name
            ]

            if pool_name not in entity_pools:
                raise ValueError(
                    f"Intent '{intent_name}' references "
                    f"unknown entity pool '{pool_name}'"
                )

            if variable_name not in entity_names:
                raise ValueError(
                    f"Intent '{intent_name}' has no "
                    f"entity name for '{variable_name}'"
                )

            value_pools.append(
                entity_pools[pool_name]
            )

        for values in product(*value_pools):
            template_values = dict(
                zip(
                    variable_names,
                    values,
                )
            )

            # Avoid nonsensical copy/move operations where
            # source and destination are identical.
            if (
                "source" in template_values
                and "destination" in template_values
                and template_values["source"]
                == template_values["destination"]
            ):
                continue

            entities = {
                entity_names[variable_name]: str(
                    template_values[variable_name]
                )
                for variable_name in variable_names
            }

            for template in templates:
                text = template.format(
                    **template_values
                )

                examples.append(
                    {
                        "text": text,
                        "intent": intent_name,
                        "action": action,
                        "entities": entities.copy(),
                        "template_family": template,
                    }
                )

        return examples

    # ---------------------------------------------------------
    # ONE ENTITY
    # ---------------------------------------------------------

    if expansion_entity:
        if expansion_entity not in entity_pools:
            raise ValueError(
                f"Intent '{intent_name}' references "
                f"unknown entity pool "
                f"'{expansion_entity}'"
            )

        if not entity_name:
            raise ValueError(
                f"Intent '{intent_name}' has an "
                "expansion_entity but no entity_name"
            )

        values = entity_pools[
            expansion_entity
        ]

        for value in values:
            for template in templates:
                examples.append(
                    {
                        "text": template.format(
                            value=value
                        ),
                        "intent": intent_name,
                        "action": action,
                        "entities": {
                            entity_name: str(value)
                        },
                        "template_family": template,
                    }
                )

        return examples

    # ---------------------------------------------------------
    # ZERO ENTITIES
    # ---------------------------------------------------------

    for template in templates:
        examples.append(
            {
                "text": template,
                "intent": intent_name,
                "action": action,
                "entities": {},
                "template_family": template,
            }
        )

    return examples


def generate_all_raw_examples(config):
    """Generate all possible configured candidates."""

    entity_pools = config.get(
        "entities",
        {}
    )

    intent_configs = config.get(
        "intents",
        {}
    )

    examples = []

    for intent_name, intent_config in (
        intent_configs.items()
    ):
        for variant in get_variants(
            intent_config
        ):
            examples.extend(
                generate_variant(
                    intent_name=intent_name,
                    variant=variant,
                    entity_pools=entity_pools,
                )
            )

    return examples


def remove_exact_duplicates(examples):
    """
    Remove exact duplicate generated rows while preserving
    deterministic order.
    """

    seen = set()
    unique = []

    for example in examples:
        key = (
            " ".join(
                example["text"]
                .lower()
                .split()
            ),
            example["intent"],
            example["action"],
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(example)

    return unique


def balanced_select(
    examples,
    target_per_intent,
    seed,
):
    """
    Deterministically cap each intent while trying to preserve
    action and template-family diversity.

    Selection proceeds round-robin across action/template
    groups instead of simply taking the first N rows.
    """

    rng = random.Random(seed)

    by_intent = defaultdict(list)

    for example in examples:
        by_intent[
            example["intent"]
        ].append(example)

    selected = []

    for intent_name in sorted(
        by_intent.keys()
    ):
        intent_examples = by_intent[
            intent_name
        ]

        # If an intent has fewer examples than the target,
        # keep all available examples.
        if len(intent_examples) <= target_per_intent:
            selected.extend(intent_examples)
            continue

        groups = defaultdict(list)

        for example in intent_examples:
            group_key = (
                example["action"],
                example["template_family"],
            )

            groups[group_key].append(
                example
            )

        # Shuffle within each group using our fixed seed.
        for group_examples in groups.values():
            rng.shuffle(group_examples)

        group_keys = sorted(
            groups.keys()
        )

        chosen = []
        position = 0

        # Round-robin selection preserves representation
        # across different actions and template families.
        while len(chosen) < target_per_intent:
            added_this_round = False

            for group_key in group_keys:
                group_examples = groups[
                    group_key
                ]

                if position < len(group_examples):
                    chosen.append(
                        group_examples[position]
                    )

                    added_this_round = True

                    if (
                        len(chosen)
                        >= target_per_intent
                    ):
                        break

            if not added_this_round:
                break

            position += 1

        selected.extend(chosen)

    return selected


def write_examples(examples):
    """Write selected candidates to CSV."""

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

        for example in examples:
            writer.writerow(
                {
                    "text": example["text"],
                    "intent": example["intent"],
                    "action": example["action"],
                    "entities": json.dumps(
                        example["entities"],
                        separators=(",", ":"),
                    ),
                    "template_family": (
                        example["template_family"]
                    ),
                }
            )


def print_summary(
    config,
    raw_examples,
    unique_examples,
    selected_examples,
    target_per_intent,
):
    """Print generation and balancing statistics."""

    intent_counts = Counter(
        example["intent"]
        for example in selected_examples
    )

    action_counts = Counter(
        (
            example["intent"],
            example["action"],
        )
        for example in selected_examples
    )

    print("IntentX Balanced Candidate Generator")
    print("====================================")

    print(
        f"Configuration: "
        f"{GENERATION_CONFIG_PATH}"
    )

    print(
        f"Configured intents: "
        f"{len(config.get('intents', {}))}"
    )

    print(
        f"Target per intent: "
        f"{target_per_intent}"
    )

    print(
        f"Random seed: {RANDOM_SEED}"
    )

    print(
        f"Raw candidates: "
        f"{len(raw_examples)}"
    )

    print(
        f"Unique candidates: "
        f"{len(unique_examples)}"
    )

    print(
        f"Selected candidates: "
        f"{len(selected_examples)}"
    )

    print("\n=== SELECTED BY INTENT ===")

    for intent, count in sorted(
        intent_counts.items()
    ):
        print(
            f"{intent:25} {count}"
        )

    print("\n=== SELECTED BY ACTION ===")

    for (intent, action), count in sorted(
        action_counts.items()
    ):
        print(
            f"{intent:25} "
            f"{action:20} "
            f"{count}"
        )

    print(
        f"\nOutput: {OUTPUT_PATH}"
    )


def main():
    config = load_generation_config()

    generation_config = config.get(
        "generation",
        {}
    )

    target_per_intent = int(
        generation_config.get(
            "target_examples_per_intent",
            DEFAULT_TARGET_PER_INTENT,
        )
    )

    if target_per_intent <= 0:
        raise ValueError(
            "target_examples_per_intent "
            "must be greater than zero"
        )

    raw_examples = generate_all_raw_examples(
        config
    )

    unique_examples = remove_exact_duplicates(
        raw_examples
    )

    selected_examples = balanced_select(
        examples=unique_examples,
        target_per_intent=target_per_intent,
        seed=RANDOM_SEED,
    )

    write_examples(
        selected_examples
    )

    print_summary(
        config=config,
        raw_examples=raw_examples,
        unique_examples=unique_examples,
        selected_examples=selected_examples,
        target_per_intent=target_per_intent,
    )


if __name__ == "__main__":
    main()