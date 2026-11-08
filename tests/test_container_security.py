"""Security regression tests for the IntentX Docker environment.

These tests inspect the container build configuration only. They do not
start containers or execute operating-system commands.

Their purpose is to prevent accidental weakening of the Phase 12
container security baseline.
"""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = PROJECT_ROOT / "Dockerfile"
DOCKERIGNORE = PROJECT_ROOT / ".dockerignore"


def _dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _dockerignore_lines() -> set[str]:
    return {
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def test_dockerfile_exists() -> None:
    assert DOCKERFILE.is_file()


def test_dockerignore_exists() -> None:
    assert DOCKERIGNORE.is_file()


def test_container_uses_python_311_base() -> None:
    text = _dockerfile_text()

    assert "FROM python:3.11-slim" in text


def test_container_creates_dedicated_intentx_user() -> None:
    text = _dockerfile_text()

    assert "groupadd --system intentx" in text
    assert "useradd" in text
    assert "--system" in text
    assert "--gid intentx" in text


def test_container_runtime_user_is_not_root() -> None:
    text = _dockerfile_text()

    user_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("USER ")
    ]

    assert user_lines
    assert user_lines[-1] == "USER intentx"
    assert "USER root" not in user_lines


def test_runtime_directories_are_owned_by_intentx() -> None:
    text = _dockerfile_text()

    assert "/app/runtime" in text
    assert "/app/logs" in text
    assert "chown -R intentx:intentx" in text


def test_image_contains_required_runtime_configuration() -> None:
    text = _dockerfile_text()

    assert "COPY configs ./configs" in text


def test_image_contains_only_selected_runtime_model() -> None:
    text = _dockerfile_text()

    assert "models/intent_classifier_v2.joblib" in text


def test_container_does_not_copy_tests_into_runtime_image() -> None:
    ignored = _dockerignore_lines()

    assert "tests" in ignored


def test_container_does_not_copy_local_virtual_environment() -> None:
    ignored = _dockerignore_lines()

    assert ".venv" in ignored


def test_container_does_not_copy_git_repository_metadata() -> None:
    ignored = _dockerignore_lines()

    assert ".git" in ignored


def test_container_does_not_copy_local_runtime_state() -> None:
    ignored = _dockerignore_lines()

    assert "runtime" in ignored
    assert "logs" in ignored
    assert "*.db" in ignored
    assert "*.sqlite" in ignored
    assert "*.sqlite3" in ignored
    assert "*.log" in ignored


def test_container_excludes_training_and_research_data() -> None:
    ignored = _dockerignore_lines()

    assert "data" in ignored
    assert "notebooks" in ignored


def test_container_excludes_all_models_except_selected_v2_model() -> None:
    ignored = _dockerignore_lines()

    assert "models/*" in ignored
    assert "!models/intent_classifier_v2.joblib" in ignored


def test_container_entrypoint_runs_application_directly() -> None:
    text = _dockerfile_text()

    expected = (
        'CMD ["uvicorn", "intentx.api.app:app", '
        '"--host", "0.0.0.0", "--port", "8000"]'
    )

    assert expected in text


def test_container_command_does_not_use_shell_wrapper() -> None:
    text = _dockerfile_text()

    command_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("CMD ", "ENTRYPOINT "))
    ]

    assert command_lines

    for line in command_lines:
        lowered = line.lower()
        assert "sh -c" not in lowered
        assert "bash -c" not in lowered


def test_dockerfile_does_not_install_sudo() -> None:
    text = _dockerfile_text().lower()

    install_section = text.split("# create an unprivileged runtime user.", 1)[0]

    assert " sudo " not in f" {install_section} "
    assert "\nsudo" not in install_section


def test_dockerfile_does_not_enable_privileged_execution() -> None:
    text = _dockerfile_text().lower()

    assert "--privileged" not in text
    assert "docker.sock" not in text


def test_container_exposes_only_application_port() -> None:
    text = _dockerfile_text()

    expose_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("EXPOSE ")
    ]

    assert expose_lines == ["EXPOSE 8000"]
