import pytest

from intentx.execution.output import (
    BoundedOutput,
    limit_output,
)


# ============================================================
# BoundedOutput model tests
# ============================================================


def test_bounded_output_valid_instance():
    result = BoundedOutput(
        text="hello",
        truncated=False,
        original_bytes=5,
        retained_bytes=5,
    )

    assert result.text == "hello"
    assert result.truncated is False
    assert result.original_bytes == 5
    assert result.retained_bytes == 5


def test_bounded_output_is_immutable():
    result = BoundedOutput(
        text="hello",
        truncated=False,
        original_bytes=5,
        retained_bytes=5,
    )

    with pytest.raises(Exception):
        result.text = "changed"


def test_bounded_output_rejects_non_string_text():
    with pytest.raises(TypeError):
        BoundedOutput(
            text=b"hello",
            truncated=False,
            original_bytes=5,
            retained_bytes=5,
        )


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        "false",
        None,
    ],
)
def test_bounded_output_requires_boolean_truncated(
    value,
):
    with pytest.raises(TypeError):
        BoundedOutput(
            text="hello",
            truncated=value,
            original_bytes=5,
            retained_bytes=5,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "original_bytes",
        "retained_bytes",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        "5",
        1.5,
        None,
    ],
)
def test_bounded_output_requires_integer_byte_counts(
    field_name,
    value,
):
    values = {
        "text": "hello",
        "truncated": False,
        "original_bytes": 5,
        "retained_bytes": 5,
    }

    values[field_name] = value

    with pytest.raises(TypeError):
        BoundedOutput(**values)


@pytest.mark.parametrize(
    "field_name",
    [
        "original_bytes",
        "retained_bytes",
    ],
)
def test_bounded_output_rejects_negative_byte_counts(
    field_name,
):
    values = {
        "text": "",
        "truncated": False,
        "original_bytes": 0,
        "retained_bytes": 0,
    }

    values[field_name] = -1

    with pytest.raises(ValueError):
        BoundedOutput(**values)


def test_retained_bytes_cannot_exceed_original_bytes():
    with pytest.raises(ValueError):
        BoundedOutput(
            text="hello",
            truncated=True,
            original_bytes=4,
            retained_bytes=5,
        )


def test_non_truncated_output_must_retain_all_bytes():
    with pytest.raises(ValueError):
        BoundedOutput(
            text="hello",
            truncated=False,
            original_bytes=10,
            retained_bytes=5,
        )


# ============================================================
# limit_output normal behavior
# ============================================================


def test_limit_output_preserves_small_string():
    result = limit_output(
        "hello",
        max_bytes=10,
    )

    assert result == BoundedOutput(
        text="hello",
        truncated=False,
        original_bytes=5,
        retained_bytes=5,
    )


def test_limit_output_preserves_exact_limit():
    result = limit_output(
        "hello",
        max_bytes=5,
    )

    assert result.text == "hello"
    assert result.truncated is False
    assert result.original_bytes == 5
    assert result.retained_bytes == 5


def test_limit_output_truncates_large_string():
    result = limit_output(
        "abcdefghij",
        max_bytes=5,
    )

    assert result.text == "abcde"
    assert result.truncated is True
    assert result.original_bytes == 10
    assert result.retained_bytes == 5


def test_limit_output_accepts_bytes():
    result = limit_output(
        b"1234567890",
        max_bytes=4,
    )

    assert result.text == "1234"
    assert result.truncated is True
    assert result.original_bytes == 10
    assert result.retained_bytes == 4


def test_limit_output_accepts_none():
    result = limit_output(
        None,
        max_bytes=10,
    )

    assert result.text == ""
    assert result.truncated is False
    assert result.original_bytes == 0
    assert result.retained_bytes == 0


def test_empty_string_is_not_truncated():
    result = limit_output(
        "",
        max_bytes=10,
    )

    assert result.text == ""
    assert result.truncated is False
    assert result.original_bytes == 0
    assert result.retained_bytes == 0


# ============================================================
# UTF-8 byte-boundary behavior
# ============================================================


def test_limit_is_measured_in_bytes_not_characters():
    value = "😀"

    assert len(value) == 1
    assert len(value.encode("utf-8")) == 4

    result = limit_output(
        value,
        max_bytes=3,
    )

    assert result.truncated is True
    assert result.original_bytes == 4
    assert result.text == ""
    assert result.retained_bytes == 0


def test_utf8_boundary_drops_incomplete_character():
    result = limit_output(
        "A😀B",
        max_bytes=3,
    )

    assert result.truncated is True
    assert result.original_bytes == 6

    # A is complete, while only part of the emoji fits.
    # The incomplete UTF-8 sequence is discarded.
    assert result.text == "A"
    assert result.retained_bytes == 1


def test_utf8_character_is_retained_when_complete():
    result = limit_output(
        "A😀B",
        max_bytes=5,
    )

    assert result.truncated is True
    assert result.text == "A😀"
    assert result.original_bytes == 6
    assert result.retained_bytes == 5


def test_multibyte_output_without_truncation():
    value = "हैलो"

    encoded_length = len(
        value.encode("utf-8")
    )

    result = limit_output(
        value,
        max_bytes=100,
    )

    assert result.text == value
    assert result.truncated is False
    assert result.original_bytes == encoded_length
    assert result.retained_bytes == encoded_length


# ============================================================
# Invalid input tests
# ============================================================


@pytest.mark.parametrize(
    "max_bytes",
    [
        True,
        False,
        "10",
        10.5,
        None,
    ],
)
def test_limit_output_requires_integer_max_bytes(
    max_bytes,
):
    with pytest.raises(TypeError):
        limit_output(
            "hello",
            max_bytes=max_bytes,
        )


@pytest.mark.parametrize(
    "max_bytes",
    [
        0,
        -1,
        -100,
    ],
)
def test_limit_output_requires_positive_max_bytes(
    max_bytes,
):
    with pytest.raises(ValueError):
        limit_output(
            "hello",
            max_bytes=max_bytes,
        )


@pytest.mark.parametrize(
    "value",
    [
        123,
        1.5,
        True,
        ["hello"],
        {"text": "hello"},
    ],
)
def test_limit_output_rejects_unsupported_value_types(
    value,
):
    with pytest.raises(TypeError):
        limit_output(
            value,
            max_bytes=10,
        )


# ============================================================
# Security-oriented boundary tests
# ============================================================


def test_large_output_is_bounded():
    value = "A" * 1_000_000

    result = limit_output(
        value,
        max_bytes=65536,
    )

    assert result.truncated is True
    assert result.original_bytes == 1_000_000
    assert result.retained_bytes == 65536

    assert len(
        result.text.encode("utf-8")
    ) <= 65536


def test_large_binary_output_is_bounded():
    value = b"A" * 1_000_000

    result = limit_output(
        value,
        max_bytes=65536,
    )

    assert result.truncated is True
    assert result.original_bytes == 1_000_000
    assert result.retained_bytes == 65536


def test_output_never_exceeds_requested_byte_limit():
    values = [
        "simple ASCII output",
        "😀" * 100,
        "A😀B" * 100,
        b"x" * 1000,
    ]

    max_bytes = 37

    for value in values:
        result = limit_output(
            value,
            max_bytes=max_bytes,
        )

        assert (
            len(
                result.text.encode("utf-8")
            )
            <= max_bytes
        )

        assert (
            result.retained_bytes
            <= max_bytes
        )