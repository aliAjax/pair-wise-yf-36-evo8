from datetime import datetime, timezone
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError, ValidationError
from .repository import LOCK_CONTENTION_SECONDS
from .rules import RuleEngine


def _utcnow_micro():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _tx_lookup(self, tx):
        def lookup(kind, field, value):
            return tx.find_entities(self.rules.normalize_kind(kind), field, value)

        return lookup

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        with self.repository.transaction() as tx:
            if idempotency_key:
                existing = tx.get_idempotency(actor.user_id, idempotency_key)
                if existing:
                    entity = tx.get_entity(existing)
                    if entity:
                        return entity
            self.rules.validate_create(actor, kind, payload, self._tx_lookup(tx))
            entity_id = str(payload.pop("id", "") or uuid4())
            if tx.get_entity(entity_id):
                raise ConflictError("entity already exists: " + entity_id)
            status = self.rules.initial_status(kind)
            entity = tx.create_entity(entity_id, kind, status, payload, actor.user_id)
            self.audit.record(
                tx, entity_id, actor, "create", None, status, {"kind": kind}
            )
            if idempotency_key:
                tx.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        with self.repository.transaction() as tx:
            entity = tx.get_entity(entity_id)
            if not entity:
                raise NotFoundError("entity not found: " + entity_id)
            kind = self.rules.normalize_kind(entity["kind"])
            if kind == "authorization" and action == "revoke":
                return self._revoke_authorization(
                    tx, actor, entity, dict(data or {}), expected_version
                )
            # A concurrent revocation may have stopped this draft while the
            # activation waited for the write lock. A contended lock means the
            # two requests truly ran simultaneously: that is a conflict, and
            # exactly one of them succeeds. A later attempt on an already
            # stopped consent falls through to the normal invalid-transition
            # rule.
            if (
                kind == "consent"
                and action == "activate"
                and entity["status"] == "stopped"
                and tx.lock_wait_seconds >= LOCK_CONTENTION_SECONDS
            ):
                raise ConflictError(
                    "consent was stopped by a concurrent authorization revocation; "
                    "only one request may succeed"
                )
            expected = (
                int(expected_version) if expected_version is not None else entity["version"]
            )
            next_status, patch = self.rules.validate_transition(
                actor, entity, action, dict(data or {}), self._tx_lookup(tx)
            )
            if kind == "consent" and action == "activate":
                patch["activated_at"] = _utcnow_micro()
            merged = dict(entity["data"])
            merged.update(patch)
            updated = tx.update_entity(entity_id, expected, next_status, merged)
            self.audit.record(
                tx,
                entity_id,
                actor,
                action,
                entity["status"],
                updated["status"],
                {"patch": patch},
            )
        return updated

    def _revoke_authorization(self, tx, actor, authorization, data, expected_version):
        """Revoke a proxy authorization in one atomic unit.

        - Not-yet-effective (draft) consents are stopped inside the same commit.
        - Already effective consents and stored samples keep their conclusion.
        - A consent activation racing with the revocation conflicts, so only
          one of the two simultaneous requests can succeed.
        """
        reason = str(data.get("reason") or "").strip()
        if not reason:
            raise ValidationError("missing required field: reason")
        stopped = self.rules.validate_authorization_revocation(
            actor,
            authorization,
            reason,
            self._tx_lookup(tx),
            tx.lock_wait_seconds,
        )
        expected = (
            int(expected_version)
            if expected_version is not None
            else authorization["version"]
        )
        revoked_at = _utcnow_micro()
        auth_patch = {"revoked_at": revoked_at, "revocation_reason": reason}
        auth_data = dict(authorization["data"])
        auth_data.update(auth_patch)
        updated_authorization = tx.update_entity(
            authorization["id"], expected, "revoked", auth_data
        )
        self.audit.record(
            tx,
            authorization["id"],
            actor,
            "revoke",
            authorization["status"],
            "revoked",
            {"reason": reason, "stopped_consent_ids": [item["entity_id"] for item in stopped]},
        )
        for change in stopped:
            consent = tx.get_entity(change["entity_id"])
            merged = dict(consent["data"])
            merged.update(change["patch"])
            stopped_consent = tx.update_entity(
                change["entity_id"],
                change["expected_version"],
                change["next_status"],
                merged,
            )
            self.audit.record(
                tx,
                stopped_consent["id"],
                actor,
                "stop",
                consent["status"],
                stopped_consent["status"],
                {"patch": change["patch"], "caused_by": "authorization.revoke"},
            )
        return updated_authorization

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
