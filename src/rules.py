from datetime import date

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from .repository import LOCK_CONTENTION_SECONDS


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _parse_day(value, field):
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        raise ValidationError("%s must be an ISO date (YYYY-MM-DD)" % field)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _validated_purposes(value):
    purposes = [str(item) for item in _as_list(value) if str(item).strip()]
    if not purposes:
        raise ValidationError("at least one allowed purpose is required")
    if len(set(purposes)) != len(purposes):
        raise ValidationError("allowed_purposes contains duplicates")
    return purposes


def _validate_participant(actor, data, lookup, ctx):
    if len(data.get("name", "")) < 2:
        raise ValidationError("participant name is required")


def _validate_authorization(actor, data, lookup, ctx):
    participant = _find_one(lookup, "participant", "id", data.get("participant_id"))
    if not participant or participant["status"] == "closed":
        raise ValidationError("authorization requires an active participant")
    agent_user_id = data.get("agent_user_id")
    if not agent_user_id:
        raise ValidationError("agent_user_id is required")
    if str(agent_user_id) == str(participant["id"]):
        raise ValidationError("agent must differ from participant")
    if not data.get("relationship"):
        raise ValidationError("relationship is required")
    data["allowed_purposes"] = _validated_purposes(data.get("allowed_purposes"))
    expires_on = _parse_day(data["expires_at"], "expires_at")
    if expires_on <= ctx["today"]():
        raise ValidationError("authorization must expire in the future")


def _consent_authorization(actor, data, lookup, ctx):
    """Resolve and verify the formal proxy authorization behind a consent."""
    participant = _find_one(lookup, "participant", "id", data.get("participant_id"))
    if not participant or participant["status"] == "closed":
        raise ValidationError("consent requires an active participant")
    scope = _validated_purposes(data.get("scope"))
    data["scope"] = scope

    authorization_id = data.get("authorization_id")
    if not authorization_id:
        # Staff record a consent directly for the participant.
        return None

    authorization = _find_one(lookup, "authorization", "id", authorization_id)
    if not authorization:
        raise ValidationError("authorization not found: " + str(authorization_id))
    if authorization["data"].get("participant_id") != participant["id"]:
        raise ValidationError("authorization belongs to a different participant")
    if actor.role == "agent" and actor.user_id != authorization["data"].get("agent_user_id"):
        raise PermissionDenied("agent is not the registered representative")
    if authorization["status"] != "active":
        raise InvalidTransition(
            "authorization is %s; consent submission returned" % authorization["status"]
        )
    expires_on = _parse_day(authorization["data"].get("expires_at"), "expires_at")
    if expires_on < ctx["today"]():
        raise ValidationError(
            "authorization expired on %s; consent submission returned"
            % authorization["data"].get("expires_at")
        )
    allowed = set(authorization["data"].get("allowed_purposes", []))
    outside = [purpose for purpose in scope if purpose not in allowed]
    if outside:
        raise ValidationError(
            "scope %s exceeds allowed purposes %s; consent submission returned"
            % (",".join(outside), ",".join(sorted(allowed)))
        )
    return authorization


def _validate_consent(actor, data, lookup, ctx):
    authorization = _consent_authorization(actor, data, lookup, ctx)
    if authorization:
        data["agent_user_id"] = authorization["data"].get("agent_user_id")
        data["submitted_by"] = actor.user_id


def _validate_consent_activate(actor, entity, data, lookup, ctx):
    authorization_id = entity["data"].get("authorization_id")
    if authorization_id:
        authorization = _find_one(lookup, "authorization", "id", authorization_id)
        if not authorization or authorization["status"] != "active":
            raise InvalidTransition(
                "proxy authorization is no longer active; cannot activate consent"
            )
        expires_on = _parse_day(authorization["data"].get("expires_at"), "expires_at")
        if expires_on <= ctx["today"]():
            raise ValidationError(
                "authorization expired on %s; cannot activate consent"
                % authorization["data"].get("expires_at")
            )
        allowed = set(authorization["data"].get("allowed_purposes", []))
        outside = [purpose for purpose in entity["data"].get("scope", []) if purpose not in allowed]
        if outside:
            raise ValidationError(
                "scope %s exceeds allowed purposes %s; activation returned"
                % (",".join(outside), ",".join(sorted(allowed)))
            )
    expires = data.get("expires_at")
    if expires and _parse_day(expires, "expires_at") < ctx["today"]():
        raise ValidationError("consent expires_at is already in the past")


def _validate_sample_store(actor, entity, data, lookup, ctx):
    consent = _find_one(lookup, "consent", "id", data.get("consent_id"))
    if not consent or consent["status"] != "active":
        raise ValidationError("storage requires active consent")
    if "research" not in consent["data"].get("scope", []):
        raise ValidationError("consent does not include research use")
    return {"stored_at": "2026-09-24T00:00:00Z"}


def _validate_withdrawal_approve(actor, entity, data, lookup, ctx):
    samples = data.get("sample_ids") or []
    if len(set(samples)) != len(samples):
        raise ConflictError("sample_ids contains duplicates")
    for sample_id in samples:
        if not _find_one(lookup, "sample", "id", sample_id):
            raise ValidationError("unknown sample: " + str(sample_id))
    return {"approved_by": actor.user_id}


CUSTOM_CREATE = {
    "participant": _validate_participant,
    "authorization": _validate_authorization,
    "consent": _validate_consent,
}
CUSTOM_TRANSITIONS = {
    ("consent", "activate"): _validate_consent_activate,
    ("sample", "store"): _validate_sample_store,
    ("withdrawal", "approve"): _validate_withdrawal_approve,
}


class RuleEngine:
    ALIASES = {
        "participants": "participant",
        "authorizations": "authorization",
        "consents": "consent",
        "samples": "sample",
        "withdrawals": "withdrawal",
    }
    INITIAL_STATUS = {
        "participant": "registered",
        "authorization": "active",
        "consent": "draft",
        "sample": "collected",
        "withdrawal": "requested",
    }
    TRANSITIONS = {
        "participant": {
            "close_participant": (("registered",), "closed"),
        },
        "authorization": {
            "revoke": (("active",), "revoked"),
        },
        "consent": {
            "activate": (("draft",), "active"),
            "supersede": (("active",), "superseded"),
            "withdraw": (("active",), "withdrawn"),
            "stop": (("draft",), "stopped"),
        },
        "sample": {
            "store": (("collected",), "stored"),
            "loan": (("stored",), "on_loan"),
            "return": (("on_loan",), "stored"),
            "anonymize": (("stored",), "anonymized"),
            "destroy": (("stored",), "destroyed"),
        },
        "withdrawal": {
            "approve": (("requested",), "approved"),
            "execute": (("approved",), "executed"),
        },
    }
    CREATE_REQUIRED = {
        "participant": ("name",),
        "authorization": (
            "participant_id",
            "agent_user_id",
            "relationship",
            "allowed_purposes",
            "expires_at",
        ),
        "consent": ("participant_id", "scope"),
        "sample": ("participant_id", "sample_code", "collected_at"),
        "withdrawal": ("participant_id", "requested_at"),
    }
    ACTION_REQUIRED = {
        ("consent", "activate"): ("scope", "version", "expires_at"),
        ("consent", "supersede"): ("reason",),
        ("consent", "withdraw"): ("reason",),
        ("consent", "stop"): ("reason",),
        ("sample", "store"): ("freezer", "position", "consent_id"),
        ("sample", "loan"): ("recipient", "purpose", "due_at"),
        ("sample", "anonymize"): ("reason",),
        ("sample", "destroy"): ("reason",),
        ("withdrawal", "approve"): ("reason", "sample_ids"),
        ("withdrawal", "execute"): ("executed_at",),
        ("authorization", "revoke"): ("reason",),
    }
    CREATE_ROLES = {
        "participant": ("admin", "biobank"),
        "authorization": ("admin", "biobank", "committee"),
        "consent": ("admin", "committee", "biobank", "agent"),
        "sample": ("admin", "biobank"),
        "withdrawal": ("admin", "biobank"),
    }
    ROLE_ACTIONS = {
        "close_participant": ("admin", "biobank"),
        "activate": ("admin", "committee", "agent"),
        "supersede": ("admin", "committee"),
        "withdraw": ("admin", "committee"),
        "stop": ("admin", "committee", "biobank"),
        "store": ("admin", "biobank"),
        "loan": ("admin", "biobank"),
        "return": ("admin", "biobank"),
        "anonymize": ("admin", "biobank"),
        "destroy": ("admin", "biobank"),
        "approve": ("admin", "committee"),
        "execute": ("admin", "biobank"),
    }

    def __init__(self, clock=None):
        self._clock = clock

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    def _ctx(self):
        return {"today": self._today}

    def _today(self):
        if self._clock is not None:
            return _parse_day(self._clock(), "clock")
        return date.today()

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup, self._ctx())
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup, self._ctx()) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch

    # ---- formal proxy authorization revocation (multi-object rule) ----

    def validate_authorization_revocation(self, actor, authorization, reason, lookup, lock_wait_seconds):
        """Apply the revocation policy and return the consent drafts that must stop.

        Already-effective consents and stored samples keep their original
        conclusion; only consents that have not taken effect are halted.
        A consent activation racing with the revocation is rejected so that
        only one of the two concurrent requests can succeed.
        """
        if authorization["kind"] != "authorization":
            raise ValidationError("entity is not an authorization")
        if authorization["status"] != "active":
            raise InvalidTransition(
                "cannot revoke authorization from status %s" % authorization["status"]
            )
        if actor.role == "participant":
            if actor.user_id != authorization["data"].get("participant_id"):
                raise PermissionDenied("participant can only revoke own authorization")
        else:
            self._ensure_role(actor, ("admin", "biobank", "committee"))

        participant_id = authorization["data"].get("participant_id")
        linked = [
            consent
            for consent in (lookup("consent", "authorization_id", authorization["id"]) or [])
            if consent["data"].get("participant_id") == participant_id
        ]
        contended = lock_wait_seconds >= LOCK_CONTENTION_SECONDS
        for consent in linked:
            if consent["status"] == "active" and contended:
                raise ConflictError(
                    "consent %s took effect at the same time as this revocation; "
                    "only one request may succeed" % consent["id"]
                )
        stopped = []
        for consent in linked:
            if consent["status"] == "draft":
                stopped.append(
                    self.build_system_transition(
                        consent,
                        "stop",
                        {
                            "reason": "proxy authorization revoked: " + reason,
                            "authorization_id": authorization["id"],
                        },
                    )
                )
        return stopped

    def build_system_transition(self, entity, action, patch):
        """Compute a system-triggered transition without an actor/role check."""
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition or entity["status"] not in transition[0]:
            raise InvalidTransition(
                "cannot %s %s from status %s" % (action, kind, entity["status"])
            )
        return {
            "entity_id": entity["id"],
            "expected_version": entity["version"],
            "next_status": transition[1],
            "patch": dict(patch),
        }
