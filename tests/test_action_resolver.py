import pytest

from intentx.planning.action_resolver import (
    ActionResolution,
    ActionResolver,
)


@pytest.fixture
def resolver():
    return ActionResolver()


# =========================================================
# Basic action resolution
# =========================================================


def test_restart_service(resolver):
    result = resolver.resolve(
        "restart nginx",
        "service_management",
    )

    assert result.resolved is True
    assert result.action == "restart"


def test_stop_service(resolver):
    result = resolver.resolve(
        "stop nginx",
        "service_management",
    )

    assert result.resolved is True
    assert result.action == "stop"


def test_package_install(resolver):
    result = resolver.resolve(
        "install nginx",
        "package_management",
    )

    assert result.resolved is True
    assert result.action == "install"


def test_package_remove(resolver):
    result = resolver.resolve(
        "remove curl",
        "package_management",
    )

    assert result.resolved is True
    assert result.action == "remove"


def test_file_create_directory(resolver):
    result = resolver.resolve(
        "create directory /tmp/demo",
        "file_create",
    )

    assert result.resolved is True

    assert (
        result.action
        == "create_directory"
    )


def test_file_create_file(resolver):
    result = resolver.resolve(
        "create file /tmp/demo.txt",
        "file_create",
    )

    assert result.resolved is True
    assert result.action == "create_file"


def test_permission_chmod(resolver):
    result = resolver.resolve(
        "chmod 644 /tmp/test.txt",
        "permission_change",
    )

    assert result.resolved is True
    assert result.action == "chmod"


def test_permission_chown(resolver):
    result = resolver.resolve(
        "chown alice /tmp/test.txt",
        "permission_change",
    )

    assert result.resolved is True
    assert result.action == "chown"


# =========================================================
# Process termination
# =========================================================


def test_force_terminate(resolver):
    """
    Specific force-termination language must
    resolve to force_terminate rather than the
    more general terminate action.
    """

    result = resolver.resolve(
        "force kill process 1234",
        "process_termination",
    )

    assert result.resolved is True

    assert (
        result.action
        == "force_terminate"
    )


def test_normal_terminate_not_forced(
    resolver,
):
    """
    Ordinary kill language must remain a normal
    terminate action.
    """

    result = resolver.resolve(
        "kill process 1234",
        "process_termination",
    )

    assert result.resolved is True

    assert (
        result.action
        == "terminate"
    )


def test_sigkill_is_force_terminate(
    resolver,
):
    result = resolver.resolve(
        "send sigkill to process 1234",
        "process_termination",
    )

    assert result.resolved is True

    assert (
        result.action
        == "force_terminate"
    )


def test_kill_minus_nine_is_force_terminate(
    resolver,
):
    result = resolver.resolve(
        "kill -9 process 1234",
        "process_termination",
    )

    assert result.resolved is True

    assert (
        result.action
        == "force_terminate"
    )


# =========================================================
# Fallback and invalid-input behavior
# =========================================================


def test_single_action_fallback(resolver):
    """
    memory_inspection has exactly one catalog
    action, so deterministic fallback is safe.
    """

    result = resolver.resolve(
        "how much ram is being used",
        "memory_inspection",
    )

    assert result.resolved is True

    assert (
        result.action
        == "memory_usage"
    )


def test_ambiguous_multi_action_fails_closed(
    resolver,
):
    """
    service_management contains multiple
    possible actions.

    If none can be identified, the resolver
    must not guess.
    """

    result = resolver.resolve(
        "manage nginx",
        "service_management",
    )

    assert result.resolved is False
    assert result.action == ""


def test_out_of_scope_has_no_action(
    resolver,
):
    result = resolver.resolve(
        "tell me a joke",
        "out_of_scope",
    )

    assert result.resolved is False
    assert result.action == ""


def test_unknown_intent_rejected(
    resolver,
):
    with pytest.raises(ValueError):
        resolver.resolve(
            "restart nginx",
            "made_up_intent",
        )


def test_empty_text_rejected(
    resolver,
):
    with pytest.raises(ValueError):
        resolver.resolve(
            "",
            "service_management",
        )


def test_non_string_text_rejected(
    resolver,
):
    with pytest.raises(TypeError):
        resolver.resolve(
            1234,
            "service_management",
        )


def test_empty_intent_rejected(
    resolver,
):
    with pytest.raises(ValueError):
        resolver.resolve(
            "restart nginx",
            "",
        )


def test_non_string_intent_rejected(
    resolver,
):
    with pytest.raises(TypeError):
        resolver.resolve(
            "restart nginx",
            1234,
        )


def test_resolution_result_type(
    resolver,
):
    result = resolver.resolve(
        "restart nginx",
        "service_management",
    )

    assert isinstance(
        result,
        ActionResolution,
    )


# =========================================================
# Multi-action ambiguity and subsumption
# =========================================================


def test_conflicting_start_and_stop_fails_closed(
    resolver,
):
    result = resolver.resolve(
        "start and stop nginx",
        "service_management",
    )

    assert result.resolved is False
    assert result.action == ""

    assert (
        result.reason
        == "Multiple permitted actions "
        "matched the request."
    )


def test_conflicting_restart_and_stop_fails_closed(
    resolver,
):
    result = resolver.resolve(
        "restart and stop nginx",
        "service_management",
    )

    assert result.resolved is False
    assert result.action == ""


def test_single_start_still_resolves(
    resolver,
):
    result = resolver.resolve(
        "start nginx",
        "service_management",
    )

    assert result.resolved is True
    assert result.action == "start"


def test_single_restart_still_resolves(
    resolver,
):
    result = resolver.resolve(
        "restart nginx",
        "service_management",
    )

    assert result.resolved is True
    assert result.action == "restart"


def test_force_kill_subsumes_normal_terminate(
    resolver,
):
    result = resolver.resolve(
        "force kill process 1234",
        "process_termination",
    )

    assert result.resolved is True

    assert (
        result.action
        == "force_terminate"
    )


def test_normal_kill_still_resolves_terminate(
    resolver,
):
    result = resolver.resolve(
        "kill process 1234",
        "process_termination",
    )

    assert result.resolved is True
    assert result.action == "terminate"


# =========================================================
# Process inspection semantic resolution
# =========================================================


def test_process_search_resolves_to_list(
    resolver,
):
    result = resolver.resolve(
        "find nginx processes",
        "process_inspection",
    )

    assert result.resolved is True
    assert result.action == "list"


def test_process_with_pid_resolves_to_inspect(
    resolver,
):
    result = resolver.resolve(
        "show process 4321",
        "process_inspection",
    )

    assert result.resolved is True
    assert result.action == "inspect"


def test_explicit_process_list_resolves_to_list(
    resolver,
):
    result = resolver.resolve(
        "list processes",
        "process_inspection",
    )

    assert result.resolved is True
    assert result.action == "list"


def test_process_inspect_without_pid_fails_closed(
    resolver,
):
    result = resolver.resolve(
        "inspect process",
        "process_inspection",
    )

    assert result.resolved is False
    assert result.action == ""

    assert (
        result.reason
        == "Process inspection requires a "
        "specific PID."
    )


# =========================================================
# File-read semantic subsumption
# =========================================================


def test_file_read_resolves_to_read(
    resolver,
):
    result = resolver.resolve(
        "read /tmp/report.txt",
        "file_read",
    )

    assert result.resolved is True
    assert result.action == "read"


def test_show_head_resolves_to_head(
    resolver,
):
    """
    'show' matches the generic read pattern while
    'head' matches the specific head pattern.

    Explicit semantic subsumption must retain head.
    """

    result = resolver.resolve(
        "show head /tmp/report.txt",
        "file_read",
    )

    assert result.resolved is True
    assert result.action == "head"


def test_head_alone_resolves_to_head(
    resolver,
):
    result = resolver.resolve(
        "head /tmp/report.txt",
        "file_read",
    )

    assert result.resolved is True
    assert result.action == "head"


def test_show_tail_resolves_to_tail(
    resolver,
):
    """
    'show' matches the generic read pattern while
    'tail' matches the specific tail pattern.

    Explicit semantic subsumption must retain tail.
    """

    result = resolver.resolve(
        "show tail /tmp/report.txt",
        "file_read",
    )

    assert result.resolved is True
    assert result.action == "tail"


def test_tail_alone_resolves_to_tail(
    resolver,
):
    result = resolver.resolve(
        "tail /tmp/report.txt",
        "file_read",
    )

    assert result.resolved is True
    assert result.action == "tail"


def test_conflicting_head_and_tail_fails_closed(
    resolver,
):
    """
    head and tail are different specific actions.

    Both may subsume generic read, but neither
    subsumes the other. The resolver must therefore
    preserve the ambiguity and fail closed.
    """

    result = resolver.resolve(
        "show head and tail /tmp/report.txt",
        "file_read",
    )

    assert result.resolved is False
    assert result.action == ""

    assert (
        result.reason
        == "Multiple permitted actions "
        "matched the request."
    )