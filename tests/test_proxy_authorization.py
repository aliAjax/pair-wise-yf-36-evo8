import tempfile
import threading
import unittest
from datetime import date
from pathlib import Path

from src.domain import (
    Actor,
    ConflictError,
    DomainError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


def clock_on(day):
    return day.isoformat() + "T09:00:00.000000+00:00"


class ProxyAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.rules = RuleEngine(clock=lambda: clock_on(date(2026, 9, 26)))
        self.service = DomainService(self.repo, self.rules)
        self.admin = Actor("admin", "admin")
        self.participant = Actor("P-1", "participant")
        self.agent = Actor("A-1", "agent")
        self.other_agent = Actor("A-2", "agent")

        self.participant_entity = self.service.create(
            self.admin, "participant", {"id": "P-1", "name": "Participant One"}
        )
        self.authorization = self.service.create(
            self.admin,
            "authorization",
            {
                "participant_id": self.participant_entity["id"],
                "agent_user_id": "A-1",
                "relationship": "adult child",
                "allowed_purposes": ["research", "clinical_trial"],
                "expires_at": "2026-12-31",
            },
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _submit_consent(self, actor, scope, authorization_id=None):
        payload = {
            "participant_id": self.participant_entity["id"],
            "scope": scope,
        }
        if authorization_id:
            payload["authorization_id"] = authorization_id
        return self.service.create(actor, "consent", payload)

    def _activate(self, consent, actor=None, expires_at="2099-01-01"):
        return self.service.transition(
            actor or self.admin,
            consent["id"],
            "activate",
            {
                "scope": consent["data"]["scope"],
                "version": "v1",
                "expires_at": expires_at,
            },
        )

    def test_authorization_registration_fields(self):
        self.assertEqual(self.authorization["kind"], "authorization")
        self.assertEqual(self.authorization["status"], "active")
        self.assertEqual(
            self.authorization["data"]["allowed_purposes"],
            ["research", "clinical_trial"],
        )
        audit = self.service.audit_log(self.authorization["id"])
        self.assertEqual(audit[0]["action"], "create")

    def test_authorization_must_not_expire_in_the_past(self):
        with self.assertRaises(ValidationError):
            self.service.create(
                self.admin,
                "authorization",
                {
                    "participant_id": self.participant_entity["id"],
                    "agent_user_id": "A-9",
                    "relationship": "spouse",
                    "allowed_purposes": ["research"],
                    "expires_at": "2020-01-01",
                },
            )

    def test_agent_submits_consent_within_scope_and_date(self):
        consent = self._submit_consent(
            self.agent, ["research"], self.authorization["id"]
        )
        self.assertEqual(consent["status"], "draft")
        self.assertEqual(consent["data"]["agent_user_id"], "A-1")
        self.assertEqual(consent["data"]["submitted_by"], "A-1")
        active = self._activate(consent, self.agent)
        self.assertEqual(active["status"], "active")
        self.assertIn("activated_at", active["data"])

    def test_consent_scope_outside_authorization_is_returned(self):
        with self.assertRaises(ValidationError) as caught:
            self._submit_consent(
                self.agent, ["marketing"], self.authorization["id"]
            )
        self.assertIn("returned", str(caught.exception))

    def test_expired_authorization_rejects_consent(self):
        expired_rules = RuleEngine(clock=lambda: clock_on(date(2027, 1, 1)))
        service = DomainService(self.repo, expired_rules)
        with self.assertRaises(ValidationError) as caught:
            service.create(
                self.agent,
                "consent",
                {
                    "participant_id": self.participant_entity["id"],
                    "authorization_id": self.authorization["id"],
                    "scope": ["research"],
                },
            )
        self.assertIn("expired", str(caught.exception))

    def test_unknown_agent_cannot_use_authorization(self):
        with self.assertRaises(PermissionDenied):
            self._submit_consent(
                self.other_agent, ["research"], self.authorization["id"]
            )

    def test_revocation_stops_draft_consent_but_keeps_active_consent_and_sample(self):
        # Already-effective consent and a sample stored against it.
        active_consent = self._submit_consent(
            self.agent, ["research"], self.authorization["id"]
        )
        active_consent = self._activate(active_consent, self.agent)
        sample = self.service.create(
            self.admin,
            "sample",
            {
                "participant_id": self.participant_entity["id"],
                "sample_code": "B-100",
                "collected_at": "2026-09-20",
            },
        )
        sample = self.service.transition(
            self.admin,
            sample["id"],
            "store",
            {"freezer": "F1", "position": "A1", "consent_id": active_consent["id"]},
        )
        self.assertEqual(sample["status"], "stored")

        # A later consent not yet in effect.
        draft_consent = self._submit_consent(
            self.agent, ["clinical_trial"], self.authorization["id"]
        )

        revoked = self.service.transition(
            self.participant,
            self.authorization["id"],
            "revoke",
            {"reason": "participant changed mind"},
        )
        self.assertEqual(revoked["status"], "revoked")

        stopped = self.service.get(draft_consent["id"])
        self.assertEqual(stopped["status"], "stopped")
        # Stopped consents cannot be activated afterwards.
        with self.assertRaises(InvalidTransition):
            self._activate(stopped, self.agent)

        # Effective consent and stored sample keep their original conclusion.
        self.assertEqual(self.service.get(active_consent["id"])["status"], "active")
        self.assertEqual(self.service.get(sample["id"])["status"], "stored")

        # Audit records for authorization and stopped consent share one timeline.
        auth_audit = self.service.audit_log(self.authorization["id"])
        self.assertEqual(auth_audit[-1]["action"], "revoke")
        self.assertEqual(
            auth_audit[-1]["detail"]["stopped_consent_ids"], [draft_consent["id"]]
        )
        consent_audit = self.service.audit_log(draft_consent["id"])
        self.assertEqual(consent_audit[-1]["action"], "stop")

    def test_participant_cannot_revoke_someone_elses_authorization(self):
        stranger = Actor("P-2", "participant")
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                stranger,
                self.authorization["id"],
                "revoke",
                {"reason": "no right"},
            )

    def test_revoked_authorization_rejects_new_consent(self):
        self.service.transition(
            self.participant,
            self.authorization["id"],
            "revoke",
            {"reason": "done"},
        )
        with self.assertRaises(InvalidTransition):
            self._submit_consent(
                self.agent, ["research"], self.authorization["id"]
            )

    def test_concurrent_revoke_and_activate_only_one_succeeds(self):
        consent = self._submit_consent(
            self.agent, ["research"], self.authorization["id"]
        )
        consent = self.repo.get_entity(consent["id"])

        errors = []
        barrier = threading.Barrier(2)

        def activate():
            barrier.wait()
            try:
                self._activate(consent, self.agent)
            except DomainError as exc:
                errors.append(("activate", type(exc).__name__, str(exc)))

        def revoke():
            barrier.wait()
            try:
                self.service.transition(
                    self.participant,
                    self.authorization["id"],
                    "revoke",
                    {"reason": "concurrent"},
                )
            except DomainError as exc:
                errors.append(("revoke", type(exc).__name__, str(exc)))

        thread_a = threading.Thread(target=activate)
        thread_b = threading.Thread(target=revoke)
        thread_a.start()
        thread_b.start()
        thread_a.join(timeout=10)
        thread_b.join(timeout=10)

        # Exactly one side fails with a conflict, one succeeds.
        self.assertEqual(len(errors), 1)
        loser = errors[0]
        self.assertEqual(loser[1], "ConflictError")

        authorization = self.service.get(self.authorization["id"])
        consent_after = self.service.get(consent["id"])
        if loser[0] == "activate":
            self.assertEqual(authorization["status"], "revoked")
            self.assertEqual(consent_after["status"], "stopped")
        else:
            self.assertEqual(authorization["status"], "active")
            self.assertEqual(consent_after["status"], "active")

    def test_stale_authorization_version_rolls_back_everything(self):
        consent = self._submit_consent(
            self.agent, ["clinical_trial"], self.authorization["id"]
        )
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.participant,
                self.authorization["id"],
                "revoke",
                {"reason": "stale"},
                expected_version=self.authorization["version"] + 5,
            )
        # No stop, no revoke audit on rollback.
        self.assertEqual(self.service.get(consent["id"])["status"], "draft")
        self.assertEqual(self.service.get(self.authorization["id"])["status"], "active")
        actions = [row["action"] for row in self.service.audit_log(self.authorization["id"])]
        self.assertNotIn("revoke", actions)


if __name__ == "__main__":
    unittest.main()
