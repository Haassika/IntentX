from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Tuple


class ExecutableResolutionError(RuntimeError):
    """
    Raised when an executable cannot be safely resolved from
    the configured trusted executable directories.
    """


class TrustedExecutableResolver:
    """
    Resolve executable names only from explicitly trusted
    directories.

    The resolver deliberately does not:

    - search the caller's PATH
    - invoke a shell
    - execute the resolved file
    - accept arbitrary executable paths

    Intent-level executable allowlisting remains the
    responsibility of validation. This component only resolves
    an already validated executable name to a trusted absolute
    filesystem path.

    Modern Linux distributions may use a merged-/usr layout,
    where paths such as /bin and /usr/bin resolve to the same
    physical directory. Such filesystem aliases are safely
    deduplicated after resolution.
    """

    def __init__(
        self,
        trusted_directories: Iterable[str],
    ):
        if isinstance(
            trusted_directories,
            (
                str,
                bytes,
                bytearray,
            ),
        ):
            raise TypeError(
                "trusted_directories must be "
                "an iterable of directory strings, "
                "not a string or bytes object."
            )

        try:
            directories = tuple(
                trusted_directories
            )
        except TypeError as exc:
            raise TypeError(
                "trusted_directories must be "
                "an iterable of strings."
            ) from exc

        if not directories:
            raise ValueError(
                "At least one trusted executable "
                "directory is required."
            )

        validated_directories = []

        for directory in directories:
            if not isinstance(
                directory,
                str,
            ):
                raise TypeError(
                    "Trusted executable directories "
                    "must be strings."
                )

            if not directory.strip():
                raise ValueError(
                    "Trusted executable directories "
                    "cannot be empty."
                )

            if "\x00" in directory:
                raise ValueError(
                    "Trusted executable directories "
                    "cannot contain NUL bytes."
                )

            path = Path(directory)

            if not path.is_absolute():
                raise ValueError(
                    "Trusted executable directories "
                    "must be absolute paths."
                )

            validated_directories.append(
                directory
            )

        if (
            len(validated_directories)
            != len(set(validated_directories))
        ):
            raise ValueError(
                "Trusted executable directories "
                "must not contain exact duplicates."
            )

        normalized = []
        seen_normalized = set()

        for directory in (
            validated_directories
        ):
            normalized_path = str(
                Path(directory).resolve(
                    strict=False
                )
            )

            if (
                normalized_path
                in seen_normalized
            ):
                # A legitimate filesystem alias can occur on
                # merged-/usr Linux systems, for example:
                #
                # /bin      -> /usr/bin
                # /sbin     -> /usr/sbin
                #
                # Searching the canonical directory once is
                # sufficient and avoids treating that layout
                # as an invalid configuration.
                continue

            seen_normalized.add(
                normalized_path
            )

            normalized.append(
                normalized_path
            )

        if not normalized:
            raise ValueError(
                "No usable trusted executable "
                "directories remain after "
                "normalization."
            )

        self._trusted_directories: Tuple[
            str,
            ...
        ] = tuple(normalized)

    @property
    def trusted_directories(
        self,
    ) -> Tuple[str, ...]:
        return self._trusted_directories

    def resolve(
        self,
        executable: str,
    ) -> str:
        """
        Resolve a simple executable name to a trusted absolute
        path.

        Resolution fails closed when the executable:

        - is not a non-empty string
        - contains path separators
        - contains a NUL byte
        - is '.' or '..'
        - cannot be found
        - is not a regular file
        - is not executable
        - resolves outside the trusted directory because of a
          symbolic link
        """

        if not isinstance(
            executable,
            str,
        ):
            raise TypeError(
                "executable must be a string."
            )

        if not executable:
            raise ValueError(
                "executable cannot be empty."
            )

        if executable != executable.strip():
            raise ValueError(
                "executable cannot contain leading "
                "or trailing whitespace."
            )

        if "\x00" in executable:
            raise ValueError(
                "executable cannot contain "
                "NUL bytes."
            )

        if executable in {
            ".",
            "..",
        }:
            raise ExecutableResolutionError(
                "Executable must be a simple "
                "file name."
            )

        if (
            "/" in executable
            or "\\" in executable
        ):
            raise ExecutableResolutionError(
                "Executable paths are not accepted. "
                "Only simple executable names may "
                "be resolved."
            )

        for trusted_directory in (
            self._trusted_directories
        ):
            trusted_root = Path(
                trusted_directory
            )

            candidate = (
                trusted_root
                / executable
            )

            try:
                resolved_candidate = (
                    candidate.resolve(
                        strict=True
                    )
                )
            except (
                FileNotFoundError,
                OSError,
            ):
                continue

            if not self._is_within(
                resolved_candidate,
                trusted_root,
            ):
                continue

            try:
                if (
                    not resolved_candidate.is_file()
                ):
                    continue

                if not os.access(
                    resolved_candidate,
                    os.X_OK,
                ):
                    continue
            except OSError:
                continue

            return str(
                resolved_candidate
            )

        raise ExecutableResolutionError(
            "Executable could not be resolved "
            "from a trusted directory: "
            f"{executable}"
        )

    @staticmethod
    def _is_within(
        candidate: Path,
        trusted_root: Path,
    ) -> bool:
        """
        Return True only when candidate is located inside the
        trusted root after path resolution.
        """

        try:
            candidate.relative_to(
                trusted_root
            )
        except ValueError:
            return False

        return True