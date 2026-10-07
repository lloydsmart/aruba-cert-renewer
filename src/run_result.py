"""Version 1 structured result for one Aruba CLI invocation."""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4


class Outcome(StrEnum):
    SUCCESS_CHANGED = "success_changed"
    SUCCESS_NO_CHANGE = "success_no_change"
    SUCCESS_PREPARED = "success_prepared"
    ATTENTION_DUE = "attention_due"
    FAILURE_PRE_ATTEMPT = "failure_pre_attempt"
    FAILURE_PARTIAL = "failure_partial"
    FAILURE_AMBIGUOUS = "failure_ambiguous"


class Stage(StrEnum):
    STARTUP = "startup"
    CONFIGURATION = "configuration"
    LOCK = "lock"
    INSPECTION = "inspection"
    DECISION = "decision"
    PREFLIGHT = "preflight"
    CSR_GENERATION = "csr_generation"
    CSR_RETRIEVAL = "csr_retrieval"
    SIGNING = "signing"
    ISSUED_VALIDATION = "issued_validation"
    INSTALLATION = "installation"
    ACTIVATION = "activation"
    LIVE_VERIFICATION = "live_verification"
    FINALIZATION = "finalization"
    COMPLETED = "completed"


class Milestone(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    NOT_APPLICABLE = "not_applicable"


class Change(StrEnum):
    NONE = "none"
    CONFIRMED = "confirmed"
    POSSIBLE = "possible"


class Reason(StrEnum):
    CONFIG_INVALID = "config_invalid"
    LOCK_BUSY = "lock_busy"
    LOCK_FAILED = "lock_failed"
    PENDING_STATE = "pending_state"
    INSPECTION_FAILED = "inspection_failed"
    CSR_FAILED = "csr_failed"
    SIGNING_FAILED = "signing_failed"
    VALIDATION_FAILED = "validation_failed"
    INSTALLATION_FAILED = "installation_failed"
    VERIFICATION_FAILED = "verification_failed"
    RECOVERY_REQUIRED = "recovery_required"
    UNEXPECTED_FAILURE = "unexpected_failure"


MILESTONE_NAMES = ("csr", "issuance", "installation", "activation", "live_tls")
_SEVERITY = {
    Outcome.SUCCESS_NO_CHANGE: 0,
    Outcome.SUCCESS_PREPARED: 1,
    Outcome.SUCCESS_CHANGED: 2,
    Outcome.ATTENTION_DUE: 3,
    Outcome.FAILURE_PRE_ATTEMPT: 4,
    Outcome.FAILURE_PARTIAL: 5,
    Outcome.FAILURE_AMBIGUOUS: 6,
}


def utc_now():
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class SwitchResult:
    target: str
    outcome: Outcome = Outcome.FAILURE_PRE_ATTEMPT
    stage: Stage = Stage.STARTUP
    renewal_due: bool | None = None
    change: Change = Change.NONE
    manual_recovery_required: bool = False
    reason_code: Reason | None = None
    message: str = "Operation has not completed."
    certificate: dict[str, str | None] | None = None
    pending_csr_observed: bool = field(default=False, repr=False)
    milestones: dict[str, Milestone] = field(
        default_factory=lambda: {
            name: Milestone.NOT_ATTEMPTED for name in MILESTONE_NAMES
        }
    )

    def as_dict(self):
        return {
            "target": self.target,
            "outcome": self.outcome.value,
            "stage": self.stage.value,
            "renewal_due": self.renewal_due,
            "change": self.change.value,
            "manual_recovery_required": self.manual_recovery_required,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "message": self.message,
            "certificate": self.certificate,
            "milestones": {key: value.value for key, value in self.milestones.items()},
        }


@dataclass
class RunResult:
    operation: str
    attempt_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    outcome: Outcome = Outcome.FAILURE_PRE_ATTEMPT
    stage: Stage = Stage.STARTUP
    manual_recovery_required: bool = False
    reason_code: Reason | None = None
    message: str = "Operation has not completed."
    results: list[SwitchResult] = field(default_factory=list)

    def finish(self):
        if self.results:
            chosen = max(self.results, key=lambda item: _SEVERITY[item.outcome])
            self.outcome = chosen.outcome
            self.stage = (
                chosen.stage
                if _SEVERITY[chosen.outcome] >= _SEVERITY[Outcome.ATTENTION_DUE]
                else Stage.COMPLETED
            )
            self.reason_code = chosen.reason_code
            self.message = chosen.message
            self.manual_recovery_required |= any(
                item.manual_recovery_required for item in self.results
            )
        self.finished_at = utc_now()

    def as_dict(self):
        return {
            "schema_version": 1,
            "product": "aruba",
            "operation": self.operation,
            "attempt_id": self.attempt_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome.value,
            "stage": self.stage.value,
            "manual_recovery_required": self.manual_recovery_required,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "message": self.message,
            "results": [item.as_dict() for item in self.results],
        }

    def to_json(self):
        return json.dumps(self.as_dict(), ensure_ascii=True, allow_nan=False)
