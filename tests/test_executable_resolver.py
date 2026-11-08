from pathlib import Path

import pytest

from intentx.execution.resolver import (
    ExecutableResolutionError,
    TrustedExecutableResolver,
)


# ============================================================
# Helpers / fixtures
# ============================================================


def create_executable(
    path: Path,
) -> Path:
    """
    Create a small executable test file.

    The file is never executed by these tests. It exists only
    so that the resolver can inspect filesystem properties.
    """

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        "#!/bin/sh\n"
        "exit 0\n",
        encoding="utf-8",
    )

    path.chmod(0o755)

    return path


@pytest.fixture
def trusted_directory(
    tmp_path,
):
    directory = (
        tmp_path
        / "trusted"
    )

    directory.mkdir()

    return directory


@pytest.fixture
def resolver(
    trusted_directory,
):
    return TrustedExecutableResolver(
        [
            str(
                trusted_directory
            )
        ]
    )


# ============================================================
# Constructor validation
# ============================================================


def test_resolver_accepts_single_trusted_directory(
    trusted_directory,
):
    resolver = TrustedExecutableResolver(
        [
            str(
                trusted_directory
            )
        ]
    )

    assert resolver.trusted_directories == (
        str(
            trusted_directory.resolve(
                strict=False
            )
        ),
    )


def test_trusted_directories_are_tuple(
    resolver,
):
    assert isinstance(
        resolver.trusted_directories,
        tuple,
    )


def test_trusted_directories_are_immutable(
    resolver,
):
    original = (
        resolver.trusted_directories
    )

    with pytest.raises(
        AttributeError
    ):
        original.append(
            "/tmp"
        )


def test_input_directories_are_defensively_copied(
    trusted_directory,
):
    directories = [
        str(
            trusted_directory
        )
    ]

    resolver = TrustedExecutableResolver(
        directories
    )

    directories.append(
        "/tmp"
    )

    assert (
        len(
            resolver.trusted_directories
        )
        == 1
    )


@pytest.mark.parametrize(
    "value",
    [
        [],
        (),
    ],
)
def test_empty_trusted_directories_are_rejected(
    value,
):
    with pytest.raises(
        ValueError,
        match="At least one",
    ):
        TrustedExecutableResolver(
            value
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
    ],
)
def test_non_iterable_trusted_directories_are_rejected(
    value,
):
    with pytest.raises(
        TypeError
    ):
        TrustedExecutableResolver(
            value
        )


@pytest.mark.parametrize(
    "value",
    [
        "/usr/bin",
        b"/usr/bin",
        bytearray(b"/usr/bin"),
    ],
)
def test_string_like_trusted_directory_container_is_rejected(
    value,
):
    with pytest.raises(
        TypeError
    ):
        TrustedExecutableResolver(
            value
        )


@pytest.mark.parametrize(
    "directory",
    [
        123,
        True,
        None,
        b"/usr/bin",
    ],
)
def test_each_trusted_directory_must_be_string(
    directory,
):
    with pytest.raises(
        TypeError
    ):
        TrustedExecutableResolver(
            [
                directory
            ]
        )


@pytest.mark.parametrize(
    "directory",
    [
        "",
        " ",
        "\t",
        "\n",
    ],
)
def test_empty_trusted_directory_is_rejected(
    directory,
):
    with pytest.raises(
        ValueError
    ):
        TrustedExecutableResolver(
            [
                directory
            ]
        )


def test_trusted_directory_rejects_nul_byte():
    with pytest.raises(
        ValueError,
        match="NUL",
    ):
        TrustedExecutableResolver(
            [
                "/usr/bi\x00n"
            ]
        )


@pytest.mark.parametrize(
    "directory",
    [
        "usr/bin",
        "./bin",
        "../bin",
        "bin",
    ],
)
def test_trusted_directory_must_be_absolute(
    directory,
):
    with pytest.raises(
        ValueError,
        match="absolute",
    ):
        TrustedExecutableResolver(
            [
                directory
            ]
        )


def test_exact_duplicate_directories_are_rejected(
    trusted_directory,
):
    directory = str(
        trusted_directory
    )

    with pytest.raises(
        ValueError,
        match="exact duplicates",
    ):
        TrustedExecutableResolver(
            [
                directory,
                directory,
            ]
        )


def test_equivalent_normalized_directories_are_deduplicated(
    trusted_directory,
):
    first = str(
        trusted_directory
    )

    second = str(
        trusted_directory
        / ".."
        / trusted_directory.name
    )

    resolver = TrustedExecutableResolver(
        [
            first,
            second,
        ]
    )

    expected = str(
        trusted_directory.resolve(
            strict=False
        )
    )

    assert resolver.trusted_directories == (
        expected,
    )


def test_normalized_alias_preserves_first_search_position(
    tmp_path,
):
    first = (
        tmp_path
        / "first"
    )

    second = (
        tmp_path
        / "second"
    )

    first.mkdir()
    second.mkdir()

    alias = (
        tmp_path
        / "first"
        / ".."
        / "first"
    )

    resolver = TrustedExecutableResolver(
        [
            str(first),
            str(alias),
            str(second),
        ]
    )

    assert resolver.trusted_directories == (
        str(
            first.resolve(
                strict=False
            )
        ),
        str(
            second.resolve(
                strict=False
            )
        ),
    )


def test_multiple_distinct_trusted_directories_are_preserved(
    tmp_path,
):
    first = (
        tmp_path
        / "first"
    )

    second = (
        tmp_path
        / "second"
    )

    first.mkdir()
    second.mkdir()

    resolver = TrustedExecutableResolver(
        [
            str(first),
            str(second),
        ]
    )

    assert resolver.trusted_directories == (
        str(
            first.resolve(
                strict=False
            )
        ),
        str(
            second.resolve(
                strict=False
            )
        ),
    )


# ============================================================
# Executable-name validation
# ============================================================


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        [],
        {},
        b"safe-tool",
    ],
)
def test_executable_must_be_string(
    resolver,
    value,
):
    with pytest.raises(
        TypeError,
        match="string",
    ):
        resolver.resolve(
            value
        )


def test_empty_executable_is_rejected(
    resolver,
):
    with pytest.raises(
        ValueError,
        match="empty",
    ):
        resolver.resolve(
            ""
        )


@pytest.mark.parametrize(
    "executable_name",
    [
        " ",
        "\t",
        "\n",
        "   ",
    ],
)
def test_whitespace_only_executable_is_rejected(
    resolver,
    executable_name,
):
    with pytest.raises(
        ValueError,
        match="leading or trailing whitespace",
    ):
        resolver.resolve(
            executable_name
        )


@pytest.mark.parametrize(
    "executable_name",
    [
        " safe-tool",
        "safe-tool ",
        "  safe-tool  ",
        "\tsafe-tool",
        "safe-tool\n",
    ],
)
def test_surrounding_whitespace_is_rejected(
    resolver,
    trusted_directory,
    executable_name,
):
    create_executable(
        trusted_directory
        / "safe-tool"
    )

    with pytest.raises(
        ValueError,
        match="leading or trailing whitespace",
    ):
        resolver.resolve(
            executable_name
        )


def test_executable_rejects_nul_byte(
    resolver,
):
    with pytest.raises(
        ValueError,
        match="NUL",
    ):
        resolver.resolve(
            "safe\x00tool"
        )


@pytest.mark.parametrize(
    "value",
    [
        ".",
        "..",
    ],
)
def test_dot_names_are_rejected(
    resolver,
    value,
):
    with pytest.raises(
        ExecutableResolutionError,
        match="simple file name",
    ):
        resolver.resolve(
            value
        )


@pytest.mark.parametrize(
    "value",
    [
        "/bin/ls",
        "./safe-tool",
        "../safe-tool",
        "subdir/safe-tool",
        "subdir\\safe-tool",
        "\\safe-tool",
    ],
)
def test_executable_paths_are_rejected(
    resolver,
    value,
):
    with pytest.raises(
        ExecutableResolutionError,
        match="paths are not accepted",
    ):
        resolver.resolve(
            value
        )


# ============================================================
# Successful resolution
# ============================================================


def test_resolves_executable_from_trusted_directory(
    resolver,
    trusted_directory,
):
    executable = create_executable(
        trusted_directory
        / "safe-tool"
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert resolved == str(
        executable.resolve(
            strict=True
        )
    )


def test_resolved_path_is_absolute(
    resolver,
    trusted_directory,
):
    create_executable(
        trusted_directory
        / "safe-tool"
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert Path(
        resolved
    ).is_absolute()


def test_resolution_returns_string(
    resolver,
    trusted_directory,
):
    create_executable(
        trusted_directory
        / "safe-tool"
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert isinstance(
        resolved,
        str,
    )


def test_resolution_uses_configured_directory_order(
    tmp_path,
):
    first = (
        tmp_path
        / "first"
    )

    second = (
        tmp_path
        / "second"
    )

    first.mkdir()
    second.mkdir()

    first_executable = (
        create_executable(
            first
            / "safe-tool"
        )
    )

    create_executable(
        second
        / "safe-tool"
    )

    resolver = TrustedExecutableResolver(
        [
            str(first),
            str(second),
        ]
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert resolved == str(
        first_executable.resolve(
            strict=True
        )
    )


def test_resolution_falls_through_to_later_trusted_directory(
    tmp_path,
):
    first = (
        tmp_path
        / "first"
    )

    second = (
        tmp_path
        / "second"
    )

    first.mkdir()
    second.mkdir()

    executable = create_executable(
        second
        / "safe-tool"
    )

    resolver = TrustedExecutableResolver(
        [
            str(first),
            str(second),
        ]
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert resolved == str(
        executable.resolve(
            strict=True
        )
    )


# ============================================================
# Missing / invalid files
# ============================================================


def test_missing_executable_is_rejected(
    resolver,
):
    with pytest.raises(
        ExecutableResolutionError,
        match="could not be resolved",
    ):
        resolver.resolve(
            "does-not-exist"
        )


def test_directory_with_executable_name_is_rejected(
    resolver,
    trusted_directory,
):
    directory = (
        trusted_directory
        / "safe-tool"
    )

    directory.mkdir()

    with pytest.raises(
        ExecutableResolutionError
    ):
        resolver.resolve(
            "safe-tool"
        )


def test_non_executable_regular_file_is_rejected(
    resolver,
    trusted_directory,
):
    file_path = (
        trusted_directory
        / "safe-tool"
    )

    file_path.write_text(
        "not executable",
        encoding="utf-8",
    )

    file_path.chmod(
        0o644
    )

    with pytest.raises(
        ExecutableResolutionError
    ):
        resolver.resolve(
            "safe-tool"
        )


def test_executable_regular_file_is_accepted(
    resolver,
    trusted_directory,
):
    executable = (
        trusted_directory
        / "safe-tool"
    )

    executable.write_text(
        "test",
        encoding="utf-8",
    )

    executable.chmod(
        0o755
    )

    assert resolver.resolve(
        "safe-tool"
    ) == str(
        executable.resolve(
            strict=True
        )
    )


# ============================================================
# Symlink containment
# ============================================================


def test_symlink_to_file_inside_trusted_directory_is_allowed(
    resolver,
    trusted_directory,
):
    target = create_executable(
        trusted_directory
        / "real-tool"
    )

    link = (
        trusted_directory
        / "safe-tool"
    )

    link.symlink_to(
        target
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert resolved == str(
        target.resolve(
            strict=True
        )
    )


def test_symlink_escaping_trusted_directory_is_rejected(
    tmp_path,
):
    trusted = (
        tmp_path
        / "trusted"
    )

    outside = (
        tmp_path
        / "outside"
    )

    trusted.mkdir()
    outside.mkdir()

    outside_executable = (
        create_executable(
            outside
            / "outside-tool"
        )
    )

    link = (
        trusted
        / "safe-tool"
    )

    link.symlink_to(
        outside_executable
    )

    resolver = TrustedExecutableResolver(
        [
            str(trusted)
        ]
    )

    with pytest.raises(
        ExecutableResolutionError
    ):
        resolver.resolve(
            "safe-tool"
        )


def test_broken_symlink_is_rejected(
    resolver,
    trusted_directory,
):
    link = (
        trusted_directory
        / "safe-tool"
    )

    link.symlink_to(
        trusted_directory
        / "missing-target"
    )

    with pytest.raises(
        ExecutableResolutionError
    ):
        resolver.resolve(
            "safe-tool"
        )


# ============================================================
# No PATH-based resolution
# ============================================================


def test_resolver_does_not_search_parent_path(
    monkeypatch,
    tmp_path,
):
    trusted = (
        tmp_path
        / "trusted"
    )

    untrusted = (
        tmp_path
        / "untrusted"
    )

    trusted.mkdir()
    untrusted.mkdir()

    create_executable(
        untrusted
        / "safe-tool"
    )

    monkeypatch.setenv(
        "PATH",
        str(untrusted),
    )

    resolver = TrustedExecutableResolver(
        [
            str(trusted)
        ]
    )

    with pytest.raises(
        ExecutableResolutionError
    ):
        resolver.resolve(
            "safe-tool"
        )


def test_trusted_directory_wins_regardless_of_parent_path(
    monkeypatch,
    tmp_path,
):
    trusted = (
        tmp_path
        / "trusted"
    )

    untrusted = (
        tmp_path
        / "untrusted"
    )

    trusted.mkdir()
    untrusted.mkdir()

    trusted_executable = (
        create_executable(
            trusted
            / "safe-tool"
        )
    )

    create_executable(
        untrusted
        / "safe-tool"
    )

    monkeypatch.setenv(
        "PATH",
        str(untrusted),
    )

    resolver = TrustedExecutableResolver(
        [
            str(trusted)
        ]
    )

    resolved = resolver.resolve(
        "safe-tool"
    )

    assert resolved == str(
        trusted_executable.resolve(
            strict=True
        )
    )


# ============================================================
# Containment helper
# ============================================================


def test_is_within_accepts_child_path(
    tmp_path,
):
    root = (
        tmp_path
        / "root"
    )

    child = (
        root
        / "child"
        / "tool"
    )

    assert (
        TrustedExecutableResolver._is_within(
            child,
            root,
        )
        is True
    )


def test_is_within_accepts_root_itself(
    tmp_path,
):
    root = (
        tmp_path
        / "root"
    )

    assert (
        TrustedExecutableResolver._is_within(
            root,
            root,
        )
        is True
    )


def test_is_within_rejects_sibling_path(
    tmp_path,
):
    root = (
        tmp_path
        / "root"
    )

    sibling = (
        tmp_path
        / "other"
        / "tool"
    )

    assert (
        TrustedExecutableResolver._is_within(
            sibling,
            root,
        )
        is False
    )


def test_is_within_rejects_similar_prefix(
    tmp_path,
):
    root = (
        tmp_path
        / "trusted"
    )

    candidate = (
        tmp_path
        / "trusted-evil"
        / "tool"
    )

    assert (
        TrustedExecutableResolver._is_within(
            candidate,
            root,
        )
        is False
    )


# ============================================================
# Important security invariants
# ============================================================


def test_resolver_never_accepts_absolute_executable_even_if_trusted(
    trusted_directory,
):
    executable = create_executable(
        trusted_directory
        / "safe-tool"
    )

    resolver = TrustedExecutableResolver(
        [
            str(
                trusted_directory
            )
        ]
    )

    with pytest.raises(
        ExecutableResolutionError
    ):
        resolver.resolve(
            str(executable)
        )


def test_resolver_returns_canonical_target_path(
    trusted_directory,
):
    target = create_executable(
        trusted_directory
        / "real-tool"
    )

    alias = (
        trusted_directory
        / "alias-tool"
    )

    alias.symlink_to(
        target
    )

    resolved = resolver = (
        TrustedExecutableResolver(
            [
                str(
                    trusted_directory
                )
            ]
        )
    )

    result = resolved.resolve(
        "alias-tool"
    )

    assert result == str(
        target.resolve(
            strict=True
        )
    )


def test_resolution_does_not_execute_file(
    resolver,
    trusted_directory,
    tmp_path,
):
    marker = (
        tmp_path
        / "executed.txt"
    )

    executable = (
        trusted_directory
        / "safe-tool"
    )

    executable.write_text(
        "#!/bin/sh\n"
        f"touch '{marker}'\n",
        encoding="utf-8",
    )

    executable.chmod(
        0o755
    )

    resolver.resolve(
        "safe-tool"
    )

    assert not marker.exists()