import pytest

from intentx.entities.extractor import (
    EntityExtractor,
)


@pytest.fixture
def extractor():
    return EntityExtractor()


# =========================================================
# PID extraction
# =========================================================


def test_extract_pid(extractor):
    result = extractor.extract(
        "terminate process 1234",
        ["PID"],
    )

    assert result == {
        "PID": "1234"
    }


def test_extract_explicit_pid(extractor):
    result = extractor.extract(
        "inspect PID 4321",
        ["PID"],
    )

    assert result == {
        "PID": "4321"
    }


# =========================================================
# Port extraction
# =========================================================


def test_extract_port(extractor):
    result = extractor.extract(
        "show connections on port 443",
        ["PORT"],
    )

    assert result == {
        "PORT": "443"
    }


def test_invalid_port_not_extracted(
    extractor,
):
    result = extractor.extract(
        "check port 70000",
        ["PORT"],
    )

    assert result == {}


# =========================================================
# Permission extraction
# =========================================================


def test_extract_permission_and_path(
    extractor,
):
    result = extractor.extract(
        "chmod 644 /tmp/report.txt",
        [
            "PERMISSION",
            "PATH",
        ],
    )

    assert result == {
        "PERMISSION": "644",
        "PATH": "/tmp/report.txt",
    }


def test_extract_permission_from_context(
    extractor,
):
    result = extractor.extract(
        "change permissions to 755 "
        "on /tmp/report.txt",
        [
            "PERMISSION",
            "PATH",
        ],
    )

    assert result == {
        "PERMISSION": "755",
        "PATH": "/tmp/report.txt",
    }


def test_numeric_path_not_inferred_as_permission(
    extractor,
):
    """
    Numeric path components must never be
    interpreted as Unix permission modes.
    """

    result = extractor.extract(
        "change permissions on /tmp/1234",
        [
            "PERMISSION",
            "PATH",
        ],
    )

    assert "PERMISSION" not in result

    assert result == {
        "PATH": "/tmp/1234",
    }


def test_numeric_file_path_not_inferred_as_permission(
    extractor,
):
    """
    Permission extraction must require explicit
    permission context rather than matching any
    octal-looking number in the request.
    """

    result = extractor.extract(
        "read /tmp/755",
        [
            "PERMISSION",
            "PATH",
        ],
    )

    assert "PERMISSION" not in result

    assert result == {
        "PATH": "/tmp/755",
    }


# =========================================================
# Device and path extraction
# =========================================================


def test_extract_device(extractor):
    result = extractor.extract(
        "format /dev/sdb",
        ["DEVICE"],
    )

    assert result == {
        "DEVICE": "/dev/sdb"
    }


def test_device_not_treated_as_path(
    extractor,
):
    result = extractor.extract(
        "format /dev/sdb",
        ["PATH"],
    )

    assert result == {}


def test_extract_single_path(extractor):
    result = extractor.extract(
        "delete /tmp/report.txt",
        ["PATH"],
    )

    assert result == {
        "PATH": "/tmp/report.txt"
    }


def test_extract_source_and_destination(
    extractor,
):
    result = extractor.extract(
        "copy /tmp/a.txt to /opt/a.txt",
        [
            "SOURCE_PATH",
            "DESTINATION_PATH",
        ],
    )

    assert result == {
        "SOURCE_PATH": "/tmp/a.txt",
        "DESTINATION_PATH": "/opt/a.txt",
    }


def test_missing_destination_not_invented(
    extractor,
):
    result = extractor.extract(
        "copy /tmp/a.txt",
        [
            "SOURCE_PATH",
            "DESTINATION_PATH",
        ],
    )

    assert result == {
        "SOURCE_PATH": "/tmp/a.txt"
    }


# =========================================================
# Extraction contract
# =========================================================


def test_only_expected_entities_returned(
    extractor,
):
    result = extractor.extract(
        "chmod 644 /tmp/report.txt",
        ["PATH"],
    )

    assert result == {
        "PATH": "/tmp/report.txt"
    }


def test_empty_input_rejected(
    extractor,
):
    with pytest.raises(ValueError):
        extractor.extract(
            "",
            ["PATH"],
        )


def test_non_string_input_rejected(
    extractor,
):
    with pytest.raises(TypeError):
        extractor.extract(
            123,
            ["PATH"],
        )


def test_expected_entities_must_be_list(
    extractor,
):
    with pytest.raises(TypeError):
        extractor.extract(
            "delete /tmp/file.txt",
            "PATH",
        )


def test_unknown_expected_entity_fails_closed(
    extractor,
):
    """
    Unsupported extraction contracts must fail
    closed instead of being silently ignored.
    """

    with pytest.raises(
        ValueError,
        match="Unsupported expected entity type",
    ):
        extractor.extract(
            "something",
            ["MADE_UP_ENTITY"],
        )


def test_empty_expected_entity_rejected(
    extractor,
):
    with pytest.raises(
        ValueError,
        match="Expected entity type cannot be empty",
    ):
        extractor.extract(
            "delete /tmp/file.txt",
            [""],
        )


def test_non_string_expected_entity_rejected(
    extractor,
):
    with pytest.raises(
        TypeError,
        match=(
            "Every expected entity type "
            "must be a string"
        ),
    ):
        extractor.extract(
            "delete /tmp/file.txt",
            [123],
        )


# =========================================================
# Service extraction
# =========================================================


def test_extract_service_restart(
    extractor,
):
    result = extractor.extract(
        "restart nginx",
        ["SERVICE"],
    )

    assert result == {
        "SERVICE": "nginx"
    }


def test_extract_service_status(
    extractor,
):
    result = extractor.extract(
        "check nginx status",
        ["SERVICE"],
    )

    assert result == {
        "SERVICE": "nginx"
    }


def test_extract_service_running(
    extractor,
):
    result = extractor.extract(
        "is ssh running",
        ["SERVICE"],
    )

    assert result == {
        "SERVICE": "ssh"
    }


def test_extract_service_shutdown(
    extractor,
):
    result = extractor.extract(
        "shut down the apache service",
        ["SERVICE"],
    )

    assert result == {
        "SERVICE": "apache"
    }


# =========================================================
# Package extraction
# =========================================================


def test_extract_package(
    extractor,
):
    result = extractor.extract(
        "install nginx",
        ["PACKAGE"],
    )

    assert result == {
        "PACKAGE": "nginx"
    }


def test_extract_package_remove(
    extractor,
):
    result = extractor.extract(
        "remove package curl",
        ["PACKAGE"],
    )

    assert result == {
        "PACKAGE": "curl"
    }


# =========================================================
# Username extraction
# =========================================================


def test_extract_username(
    extractor,
):
    result = extractor.extract(
        "change owner to deploy "
        "for /opt/application",
        [
            "USERNAME",
            "PATH",
        ],
    )

    assert result == {
        "USERNAME": "deploy",
        "PATH": "/opt/application",
    }


def test_extract_username_from_chown(
    extractor,
):
    result = extractor.extract(
        "chown appuser /tmp/report.txt",
        [
            "USERNAME",
            "PATH",
        ],
    )

    assert result == {
        "USERNAME": "appuser",
        "PATH": "/tmp/report.txt",
    }


# =========================================================
# Pattern extraction
# =========================================================


def test_extract_quoted_pattern(
    extractor,
):
    result = extractor.extract(
        'search for "ERROR" in '
        '/var/log/app.log',
        [
            "PATTERN",
            "PATH",
        ],
    )

    assert result == {
        "PATTERN": "ERROR",
        "PATH": "/var/log/app.log",
    }


def test_extract_unquoted_pattern(
    extractor,
):
    result = extractor.extract(
        "search for timeout in "
        "/var/log/app.log",
        [
            "PATTERN",
            "PATH",
        ],
    )

    assert result == {
        "PATTERN": "timeout",
        "PATH": "/var/log/app.log",
    }


# =========================================================
# Context isolation
# =========================================================


def test_same_word_different_entity_context(
    extractor,
):
    service = extractor.extract(
        "restart nginx",
        ["SERVICE"],
    )

    package = extractor.extract(
        "install nginx",
        ["PACKAGE"],
    )

    assert service == {
        "SERVICE": "nginx"
    }

    assert package == {
        "PACKAGE": "nginx"
    }