from datetime import datetime, timedelta, timezone

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


def _validate_participant(actor, data, lookup):
    if len(data.get("name", "")) < 2:
        raise ValidationError("participant name is required")


def _validate_authorization(actor, data, lookup):
    participant = _find_one(lookup, "participant", "id", data.get("participant_id"))
    if not participant or participant["status"] == "closed":
        raise ValidationError("authorization requires an active participant")
    if not isinstance(data.get("agent_name"), str) or len(data["agent_name"].strip()) < 2:
        raise ValidationError("agent_name is required")
    if not data.get("relationship"):
        raise ValidationError("agent relationship is required")
    purposes = data.get("purposes")
    if not isinstance(purposes, list) or not purposes:
        raise ValidationError("purposes must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in purposes):
        raise ValidationError("purposes must contain non-empty strings")
    expires_ordinal = _parse_date_ordinal(data.get("expires_at"), "expires_at")
    if expires_ordinal < _today_ordinal():
        raise ValidationError(
            "authorization expires_at is in the past: " + str(data.get("expires_at"))
        )


def _validate_consent(actor, data, lookup):
    participant = _find_one(lookup, "participant", "id", data.get("participant_id"))
    if not participant or participant["status"] == "closed":
        raise ValidationError("consent requires an active participant")
    if not data.get("scope"):
        raise ValidationError("consent scope is required")
    if data.get("authorization_id"):
        _check_proxy_authorization(data, lookup)


def _validate_consent_activate(actor, entity, data, lookup):
    if not entity["data"].get("authorization_id"):
        return {}
    prospective = dict(entity["data"])
    prospective.update(data)
    _check_proxy_authorization(prospective, lookup)
    return {"activated_by": actor.user_id}


def _validate_sample_store(actor, entity, data, lookup):
    consent = _find_one(lookup, "consent", "id", data.get("consent_id"))
    if not consent or consent["status"] != "active":
        raise ValidationError("storage requires active consent")
    if "research" not in consent["data"].get("scope", []):
        raise ValidationError("consent does not include research use")
    return {"stored_at": "2026-09-24T00:00:00Z"}


def _validate_withdrawal_approve(actor, entity, data, lookup):
    samples = data.get("sample_ids") or []
    if len(set(samples)) != len(samples):
        raise ConflictError("sample_ids contains duplicates")
    for sample_id in samples:
        if not _find_one(lookup, "sample", "id", sample_id):
            raise ValidationError("unknown sample: " + str(sample_id))
    return {"approved_by": actor.user_id}


def _check_proxy_authorization(consent_data, lookup):
    """Reject agent-submitted consent whose proxy authorization is missing,
    revoked, expired, for another participant, or narrower than the scope.
    Each rejection carries an explicit reason for the 退回说明 response."""
    auth_id = consent_data.get("authorization_id")
    authorization = _find_one(lookup, "authorization", "id", auth_id)
    if not authorization:
        raise ValidationError("proxy authorization not found: " + str(auth_id))
    if authorization["status"] != "active":
        raise ValidationError(
            "proxy authorization %s is %s; consent submission rejected"
            % (auth_id, authorization["status"])
        )
    auth_data = authorization["data"]
    expires_at = auth_data.get("expires_at")
    if _parse_date_ordinal(expires_at, "expires_at") < _today_ordinal():
        raise ValidationError(
            "proxy authorization %s expired on %s; consent submission rejected"
            % (auth_id, expires_at)
        )
    if auth_data.get("participant_id") != consent_data.get("participant_id"):
        raise ValidationError(
            "proxy authorization %s belongs to participant %s, not %s"
            % (auth_id, auth_data.get("participant_id"), consent_data.get("participant_id"))
        )
    scope = set(consent_data.get("scope") or [])
    purposes = set(auth_data.get("purposes") or [])
    outside = sorted(scope - purposes)
    if outside:
        raise ValidationError(
            "consent scope %s exceeds authorized purposes %s"
            % (outside, sorted(purposes))
        )


CUSTOM_CREATE = {'participant': _validate_participant, 'consent': _validate_consent, 'authorization': _validate_authorization}
CUSTOM_TRANSITIONS = {('consent', 'activate'): _validate_consent_activate, ('sample', 'store'): _validate_sample_store, ('withdrawal', 'approve'): _validate_withdrawal_approve}


class RuleEngine:
    ALIASES = {'participants': 'participant', 'consents': 'consent', 'samples': 'sample', 'withdrawals': 'withdrawal', 'authorizations': 'authorization'}
    INITIAL_STATUS = {'participant': 'registered', 'consent': 'draft', 'sample': 'collected', 'withdrawal': 'requested', 'authorization': 'active'}
    TRANSITIONS = {'participant': {'close_participant': (('registered',), 'closed')}, 'consent': {'activate': (('draft',), 'active'), 'supersede': (('active',), 'superseded'), 'withdraw': (('active',), 'withdrawn'), 'stop': (('draft',), 'stopped')}, 'sample': {'store': (('collected',), 'stored'), 'loan': (('stored',), 'on_loan'), 'return': (('on_loan',), 'stored'), 'anonymize': (('stored',), 'anonymized'), 'destroy': (('stored',), 'destroyed')}, 'withdrawal': {'approve': (('requested',), 'approved'), 'execute': (('approved',), 'executed')}, 'authorization': {'revoke': (('active',), 'revoked')}}
    # When an authorization is revoked, consents that have not taken effect are
    # stopped in the same transaction. Effective consents and stored samples
    # are intentionally not listed here and keep their existing conclusion.
    CASCADES = {('authorization', 'revoke'): ({'kind': 'consent', 'link_field': 'authorization_id', 'from_status': ('draft',), 'to_status': 'stopped', 'action': 'stop'},)}
    CREATE_REQUIRED = {'participant': ('name',), 'consent': ('participant_id', 'scope'), 'sample': ('participant_id', 'sample_code', 'collected_at'), 'withdrawal': ('participant_id', 'requested_at'), 'authorization': ('participant_id', 'agent_name', 'relationship', 'purposes', 'expires_at')}
    ACTION_REQUIRED = {('consent', 'activate'): ('scope', 'version', 'expires_at'), ('consent', 'supersede'): ('reason',), ('consent', 'withdraw'): ('reason',), ('sample', 'store'): ('freezer', 'position', 'consent_id'), ('sample', 'loan'): ('recipient', 'purpose', 'due_at'), ('sample', 'anonymize'): ('reason',), ('sample', 'destroy'): ('reason',), ('withdrawal', 'approve'): ('reason', 'sample_ids'), ('withdrawal', 'execute'): ('executed_at',), ('authorization', 'revoke'): ('reason',)}
    CREATE_ROLES = {'participant': ('admin', 'biobank'), 'consent': ('admin', 'committee'), 'sample': ('admin', 'biobank'), 'withdrawal': ('admin', 'biobank'), 'authorization': ('admin', 'committee')}
    ROLE_ACTIONS = {'close_participant': ('admin', 'biobank'), 'activate': ('admin', 'committee'), 'supersede': ('admin', 'committee'), 'withdraw': ('admin', 'committee'), 'stop': ('admin', 'committee'), 'store': ('admin', 'biobank'), 'loan': ('admin', 'biobank'), 'return': ('admin', 'biobank'), 'anonymize': ('admin', 'biobank'), 'destroy': ('admin', 'biobank'), 'approve': ('admin', 'committee'), 'execute': ('admin', 'biobank'), 'revoke': ('admin', 'committee')}

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    def cascade_for(self, kind, action):
        return self.CASCADES.get((self.normalize_kind(kind), action), ())

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
            custom(actor, data, lookup)
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
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _today_ordinal():
    return datetime.now(timezone.utc).date().toordinal()


def _parse_date_ordinal(value, field):
    try:
        return _date_ordinal(value)
    except (ValueError, TypeError):
        raise ValidationError(field + " must be an ISO date (YYYY-MM-DD)")


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
