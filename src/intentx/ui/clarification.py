"""Deterministic presentation suggestions, never plans or execution authority."""
import re

# Curated standalone examples. Never interpolate user input or invented targets.
TOPICS = (
    ("memory", r"\b(memory|ram)\b", ("Show memory usage", "Check free memory")),
    ("processes", r"\b(process|processes|pid|tasks?|kill|terminate)\b", ("Show running processes", "List processes")),
    ("network", r"\b(network|internet|connections?|sockets?|ports?|interfaces?)\b", ("Show network connections", "Show listening ports", "Show network interfaces")),
    ("system", r"\b(system|kernel|operating|architecture|hostname|computer|machine)\b", ("What operating system is this?", "Tell me the kernel version")),
    ("files", r"\b(files?|folders?|director(?:y|ies)|logs?|read|delete|remove|copy|move|rename|permissions?)\b", ("List files in /app/logs", "Can you read /app/README.md?")),
    ("create", r"\b(create|make)\b.*\b(files?|folders?|director(?:y|ies))\b", ("Create a file at /app/logs/demo-notes.txt", "Create a folder at /app/logs/demo-reports")),
)


def clarification_help(text, *, missing_entities=()):
    """Use keyword relevance only; confidence and authorization gates stay unchanged."""
    normalized = str(text)[:4000].lower()
    topics = [entry for entry in TOPICS if re.search(entry[1], normalized)]
    if any(t[0] == "create" for t in topics):
        topics = [t for t in topics if t[0] != "files"]
    matched = bool(topics)
    if not topics:
        topics = [TOPICS[1], TOPICS[2], TOPICS[3]]
    examples = []
    for topic, _, phrases in topics:
        for phrase in phrases[:2]:
            examples.append({"topic": topic, "text": phrase,
                             "state_changing": topic == "create"})
    return {
        "message": (
            "I could not turn this into one clear supported request. Choose a related example or name one action and its exact target."
            if matched else
            "I could not identify a clear supported request. Choose a task below or describe one system action in plain language."
        ),
        "missing_entities": list(missing_entities or ()),
        "suggestions": examples[:6],
        "notice": "Examples are alternatives, not a confirmed interpretation. Choose one, review the full request, then Analyze Request. File examples use demo paths; replace them with your intended target. Role, risk and execution checks still apply.",
    }
