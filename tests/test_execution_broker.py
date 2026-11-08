from pathlib import Path

import pytest

from intentx.execution.broker import ExecutionBroker
from intentx.execution.models import ExecutionResult
from intentx.planning.models import OperationPlan


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "security_policy.yaml"
CATALOG_PATH = ROOT / "configs" / "intent_catalog.yaml"


# ============================================================
# Test operation-plan factories
# ============================================================


def memory_plan():
    """
    Valid low-risk read-only operation.
    """

    return OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="free",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )


def tampered_memory_plan():
    """
    Looks like a memory-inspection operation at the intent
    and action level, but substitutes an executable that is
    not valid for the deterministic memory_usage contract.

    The execution broker must cause the operation validator
    to reject this before any execution boundary is reached.
    """

    return OperationPlan(
        intent="memory_inspection",
        action="memory_usage",
        executable="uname",
        arguments=("-h",),
        entities={},
        state_changing=False,
        privilege_required=False,
        critical_operation=False,
    )


def restart_service_plan():
    """
    Valid service restart operation.

    This operation is state-changing and should therefore
    be subject to RBAC and risk policy.
    """

    return OperationPlan(
        intent="service_management",
        action="restart",
        executable="systemctl",
        arguments=("restart", "nginx"),
        entities={
            "SERVICE": "nginx",
        },
        state_changing=True,
        privilege_required="conditional",
        critical_operation=False,
    )


def format_disk_plan():
    """
    Structurally valid critical disk-format operation.

    IntentX V1 policy contains a hard safety boundary that
    must deny this operation even for ADMINISTRATOR.
    """

    return OperationPlan(
        intent="disk_management",
        action="format",
        executable="mkfs",
        arguments=("/dev/sdb",),
        entities={
            "DEVICE": "/dev/sdb",
        },
        state_changing=True,
        privilege_required=True,
        critical_operation=True,
    )


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def broker():
    """
    Construct the authorization-only execution broker using
    the real IntentX policy and intent catalog.

    The current broker does not launch operating-system
    processes.
    """

    return ExecutionBroker(
        policy_path=POLICY_PATH,
        catalog_path=CATALOG_PATH,
    )


# ============================================================
# Basic execution-boundary contract tests
# ============================================================


def test_execution_result_type_available():
    """
    Basic Phase 9 model/broker contract check.
    """

    assert ExecutionResult is not None


def test_memory_plan_is_structured_argv():
    plan = memory_plan()

    assert plan.argv == [
        "free",
        "-h",
    ]


def test_tampered_plan_differs_from_valid_operation():
    valid = memory_plan()
    tampered = tampered_memory_plan()

    assert valid.intent == tampered.intent
    assert valid.action == tampered.action

    assert (
        valid.executable
        != tampered.executable
    )


def test_viewer_memory_operation_is_expected_low_risk_case():
    plan = memory_plan()

    assert plan.state_changing is False
    assert plan.privilege_required is False
    assert plan.critical_operation is False


def test_service_restart_is_state_changing():
    plan = restart_service_plan()

    assert plan.state_changing is True
    assert plan.action == "restart"


def test_disk_format_is_critical():
    plan = format_disk_plan()

    assert plan.state_changing is True
    assert plan.privilege_required is True
    assert plan.critical_operation is True


def test_no_shell_command_string_is_constructed():
    plan = restart_service_plan()

    assert isinstance(
        plan.executable,
        str,
    )

    assert isinstance(
        plan.arguments,
        tuple,
    )

    assert plan.argv == [
        "systemctl",
        "restart",
        "nginx",
    ]


@pytest.mark.parametrize(
    "decision",
    [
        "DENY",
        "REQUIRE_APPROVAL",
        "CLARIFICATION_REQUIRED",
    ],
)
def test_non_allow_decisions_are_not_execution_authority(
    decision,
):
    """
    Only ALLOW can become execution authority.

    DENY, REQUIRE_APPROVAL, and CLARIFICATION_REQUIRED must
    never be interpreted as permission to cross the process
    execution boundary.
    """

    assert decision != "ALLOW"


# ============================================================
# Broker authorization-chain tests
# ============================================================


def test_broker_authorizes_valid_low_risk_memory_operation(
    broker,
):
    """
    A valid low-risk read-only operation for VIEWER in DEV
    should pass validation, risk assessment, and policy.

    The result is an ExecutionRequest only.

    No operating-system process is launched by authorize().
    """

    request, blocked = broker.authorize(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
        execution_id="exec-memory-001",
    )

    assert blocked is None
    assert request is not None

    assert (
        request.execution_id
        == "exec-memory-001"
    )

    assert request.role == "VIEWER"
    assert request.environment == "DEV"

    assert (
        request.intent
        == "memory_inspection"
    )

    assert (
        request.action
        == "memory_usage"
    )

    assert request.executable == "free"

    assert request.arguments == (
        "-h",
    )

    assert request.argv == [
        "free",
        "-h",
    ]


def test_broker_blocks_tampered_executable(
    broker,
):
    """
    A manually constructed OperationPlan must not bypass
    deterministic operation validation.
    """

    request, blocked = broker.authorize(
        plan=tampered_memory_plan(),
        role="VIEWER",
        environment="DEV",
        execution_id="exec-tampered-001",
    )

    assert request is None
    assert blocked is not None

    assert blocked.status == "BLOCKED"

    assert (
        blocked.process_started
        is False
    )

    assert (
        blocked.reason_code
        == "OPERATION_VALIDATION_FAILED"
    )

    assert (
        blocked.metadata[
            "validation_decision"
        ]
        != "VALIDATED_OPERATION"
    )


def test_viewer_cannot_restart_service(
    broker,
):
    """
    VIEWER does not have access to the administration
    category, so a service restart must be denied.
    """

    request, blocked = broker.authorize(
        plan=restart_service_plan(),
        role="VIEWER",
        environment="DEV",
        execution_id=(
            "exec-restart-viewer"
        ),
    )

    assert request is None
    assert blocked is not None

    assert blocked.status == "BLOCKED"

    assert (
        blocked.process_started
        is False
    )

    assert (
        blocked.reason_code
        == "POLICY_NOT_ALLOW"
    )

    assert (
        blocked.metadata[
            "policy_decision"
        ]
        == "DENY"
    )

    assert (
        "ROLE_CATEGORY_NOT_ALLOWED"
        in blocked.metadata[
            "policy_reason_codes"
        ]
    )


def test_operator_restart_requires_approval_and_is_blocked(
    broker,
):
    """
    OPERATOR may request administration operations, but the
    risk policy requires approval for this restart.

    REQUIRE_APPROVAL is deliberately not execution authority.
    """

    request, blocked = broker.authorize(
        plan=restart_service_plan(),
        role="OPERATOR",
        environment="DEV",
        execution_id=(
            "exec-restart-operator"
        ),
    )

    assert request is None
    assert blocked is not None

    assert blocked.status == "BLOCKED"

    assert (
        blocked.process_started
        is False
    )

    assert (
        blocked.reason_code
        == "POLICY_NOT_ALLOW"
    )

    assert (
        blocked.metadata[
            "policy_decision"
        ]
        == "REQUIRE_APPROVAL"
    )


def test_require_approval_is_not_execution_authority(
    broker,
):
    """
    Explicit regression test for an important security rule:

    REQUIRE_APPROVAL does not mean executable.

    A future approval workflow must create its own trusted
    authorization artifact rather than converting this
    decision to ALLOW with a simple Boolean.
    """

    request, blocked = broker.authorize(
        plan=restart_service_plan(),
        role="SENIOR_OPERATOR",
        environment="DEV",
        execution_id="exec-approval-001",
    )

    assert request is None
    assert blocked is not None

    assert (
        blocked.metadata[
            "policy_decision"
        ]
        == "REQUIRE_APPROVAL"
    )

    assert (
        blocked.process_started
        is False
    )


def test_administrator_cannot_cross_disk_format_hard_boundary(
    broker,
):
    """
    Hard safety boundaries override role and risk policy.

    Even ADMINISTRATOR must not receive an ExecutionRequest
    for disk formatting in IntentX V1.
    """

    request, blocked = broker.authorize(
        plan=format_disk_plan(),
        role="ADMINISTRATOR",
        environment="DEV",
        execution_id="exec-format-001",
    )

    assert request is None
    assert blocked is not None

    assert blocked.status == "BLOCKED"

    assert (
        blocked.process_started
        is False
    )

    assert (
        blocked.reason_code
        == "POLICY_NOT_ALLOW"
    )

    assert (
        blocked.metadata[
            "policy_decision"
        ]
        == "DENY"
    )

    assert (
        "HARD_SAFETY_BOUNDARY"
        in blocked.metadata[
            "policy_reason_codes"
        ]
    )


def test_broker_normalizes_role_and_environment_through_policy(
    broker,
):
    """
    Role and environment normalization should come from the
    deterministic policy layer rather than being trusted from
    raw caller input.
    """

    request, blocked = broker.authorize(
        plan=memory_plan(),
        role=" viewer ",
        environment=" dev ",
        execution_id=(
            "exec-normalized-001"
        ),
    )

    assert blocked is None
    assert request is not None

    assert request.role == "VIEWER"
    assert request.environment == "DEV"


def test_broker_generates_execution_id_when_not_supplied(
    broker,
):
    request, blocked = broker.authorize(
        plan=memory_plan(),
        role="VIEWER",
        environment="DEV",
    )

    assert blocked is None
    assert request is not None

    assert (
        request.execution_id.startswith(
            "exec-"
        )
    )

    assert (
        len(request.execution_id)
        > len("exec-")
    )


def test_broker_rejects_empty_execution_id(
    broker,
):
    with pytest.raises(ValueError):
        broker.authorize(
            plan=memory_plan(),
            role="VIEWER",
            environment="DEV",
            execution_id="   ",
        )


def test_broker_rejects_non_string_execution_id(
    broker,
):
    with pytest.raises(TypeError):
        broker.authorize(
            plan=memory_plan(),
            role="VIEWER",
            environment="DEV",
            execution_id=123,
        )


def test_broker_rejects_non_operation_plan(
    broker,
):
    """
    Raw command strings must never be accepted as operation
    plans by the execution broker.
    """

    with pytest.raises(TypeError):
        broker.authorize(
            plan="free -h",
            role="VIEWER",
            environment="DEV",
        )