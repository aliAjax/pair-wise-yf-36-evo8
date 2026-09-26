from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError
from .rules import RuleEngine


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        creates = [{"id": entity_id, "kind": kind, "status": status,
                    "data": payload, "actor_id": actor.user_id}]
        audits = [self.audit.entry(entity_id, actor, "create", None, status,
                                  {"kind": kind})]
        idempotency = (
            [{"actor_id": actor.user_id, "key": idempotency_key,
              "entity_id": entity_id}]
            if idempotency_key else []
        )
        self.repository.apply_unit_of_work(
            creates=creates, audits=audits, idempotency=idempotency
        )
        return self.repository.get_entity(entity_id)

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)

        updates = [{"id": entity_id, "expected_version": expected,
                    "status": next_status, "data": merged}]
        audits = [self.audit.entry(
            entity_id, actor, action, entity["status"], next_status,
            {"patch": patch},
        )]
        guards = self._guards_for(entity, action)
        cascade = self._cascade_for(actor, entity, action)
        updates.extend(cascade["updates"])
        audits.extend(cascade["audits"])

        # Authorization state, consent states and audit entries commit as one
        # unit. Any guard/version failure rolls everything back.
        self.repository.apply_unit_of_work(
            updates=updates, guards=guards, audits=audits
        )
        return self.repository.get_entity(entity_id)

    def _guards_for(self, entity, action):
        # An agent-activated consent only takes effect if the proxy
        # authorization is still active at the exact commit instant. The
        # version guard makes revocation and activation mutually exclusive.
        if (
            entity["kind"] == "consent"
            and action == "activate"
            and entity["data"].get("authorization_id")
        ):
            authorization = self.repository.get_entity(
                entity["data"]["authorization_id"]
            )
            if authorization:
                return [{
                    "id": authorization["id"],
                    "expected_version": authorization["version"],
                    "required_status": "active",
                }]
        return []

    def _cascade_for(self, actor, entity, action):
        updates = []
        audits = []
        for spec in self.rules.cascade_for(entity["kind"], action):
            targets = self.repository.find_entities(
                spec["kind"], spec["link_field"], entity["id"]
            )
            for target in targets:
                if target["status"] not in spec["from_status"]:
                    continue
                updates.append({
                    "id": target["id"],
                    "expected_version": target["version"],
                    "status": spec["to_status"],
                    "data": target["data"],
                })
                audits.append(self.audit.entry(
                    target["id"], actor, spec["action"],
                    target["status"], spec["to_status"],
                    {"cause": "%s %s" % (entity["kind"], action),
                     "source": entity["id"]},
                ))
        return {"updates": updates, "audits": audits}

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
