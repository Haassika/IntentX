from dataclasses import dataclass


@dataclass(frozen=True)
class BoundedOutput:
    """
    Immutable representation of captured process output
    after applying a byte limit.
    """

    text: str
    truncated: bool
    original_bytes: int
    retained_bytes: int

    def __post_init__(self):
        if not isinstance(self.text, str):
            raise TypeError(
                "text must be a string."
            )

        if not isinstance(
            self.truncated,
            bool,
        ):
            raise TypeError(
                "truncated must be boolean."
            )

        for field_name, value in (
            (
                "original_bytes",
                self.original_bytes,
            ),
            (
                "retained_bytes",
                self.retained_bytes,
            ),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
            ):
                raise TypeError(
                    f"{field_name} must be "
                    "an integer."
                )

            if value < 0:
                raise ValueError(
                    f"{field_name} cannot "
                    "be negative."
                )

        if (
            self.retained_bytes
            > self.original_bytes
        ):
            raise ValueError(
                "retained_bytes cannot exceed "
                "original_bytes."
            )

        if (
            not self.truncated
            and self.retained_bytes
            != self.original_bytes
        ):
            raise ValueError(
                "Non-truncated output must retain "
                "all original bytes."
            )


def limit_output(
    value,
    max_bytes: int,
) -> BoundedOutput:
    """
    Bound captured process output by UTF-8 byte size.

    The function accepts str, bytes, or None.

    Truncation is performed on bytes rather than Python
    character count because execution limits are defined
    in bytes.

    Invalid trailing UTF-8 sequences caused by truncation
    are safely discarded during decoding.
    """

    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
    ):
        raise TypeError(
            "max_bytes must be an integer."
        )

    if max_bytes <= 0:
        raise ValueError(
            "max_bytes must be greater than zero."
        )

    if value is None:
        raw = b""

    elif isinstance(value, bytes):
        raw = value

    elif isinstance(value, str):
        raw = value.encode(
            "utf-8",
            errors="replace",
        )

    else:
        raise TypeError(
            "value must be str, bytes, or None."
        )

    original_bytes = len(raw)

    if original_bytes <= max_bytes:
        retained = raw
        truncated = False
    else:
        retained = raw[:max_bytes]
        truncated = True

    text = retained.decode(
        "utf-8",
        errors="ignore",
    )

    # Decoding with errors='ignore' may remove an incomplete
    # UTF-8 sequence at the byte boundary. retained_bytes
    # therefore describes the bytes represented by the final
    # returned text rather than merely len(retained).
    represented_bytes = len(
        text.encode("utf-8")
    )

    return BoundedOutput(
        text=text,
        truncated=truncated,
        original_bytes=original_bytes,
        retained_bytes=represented_bytes,
    )