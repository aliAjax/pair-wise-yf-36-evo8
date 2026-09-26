import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from src.domain import Actor, ConflictError, InvalidTransition, PermissionDenied, ValidationError
from src.http_api import create_server
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


def admin(user="admin-1"):
    return Actor(user, "admin")


class ProxyAuthorizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())

    def tearDown(self):
        self.tmp.cleanup()

    def _participant(self, name="Proxy Participant"):
        return self.service.create(admin(), "participant", {"name": name})

    def _authorization(self, participant_id, **overrides):
        data = {
            "participant_id": participant_id,
            "agent_name": "Zhang Spouse",
            "relationship": "spouse",
            "purposes": ["research"],
            "expires_at": "2099-12-31",
        }
        data.update(overrides)
        return self.service.create(admin(), "authorization", data)

    def _draft_consent(self, participant_id, authorization_id=None, scope=("research",)):
        data = {"participant_id": participant_id, "scope": list(scope)}
        if authorization_id:
            data["authorization_id"] = authorization_id
        return self.service.create(admin(), "consent", data)

    def _activate(self, consent, scope=("research",)):
        return self.service.transition(
            admin(), consent["id"], "activate",
            {"scope": list(scope), "version": "v1", "expires_at": "2099-12-31"},
        )

    # ---- registration -------------------------------------------------

    def test_register_authorization_fields(self):
        participant = self._participant()
        auth = self._authorization(participant["id"])
        self.assertEqual(auth["status"], "active")
        self.assertEqual(auth["data"]["agent_name"], "Zhang Spouse")
        self.assertEqual(auth["data"]["relationship"], "spouse")
        self.assertEqual(auth["data"]["purposes"], ["research"])
        self.assertEqual(auth["data"]["expires_at"], "2099-12-31")

    def test_register_requires_agent_relationship_purposes_expiry(self):
        participant = self._participant()
        base = {
            "participant_id": participant["id"],
            "agent_name": "Zhang Spouse",
            "relationship": "spouse",
            "purposes": ["research"],
            "expires_at": "2099-12-31",
        }
        for missing in ("agent_name", "relationship", "purposes", "expires_at"):
            data = dict(base)
            data[missing] = ""
            with self.assertRaises(ValidationError):
                self.service.create(admin(), "authorization", data)

    def test_register_rejects_past_expiry_and_unknown_participant(self):
        participant = self._participant()
        with self.assertRaises(ValidationError):
            self._authorization(participant["id"], expires_at="2020-01-01")
        with self.assertRaises(ValidationError):
            self._authorization("does-not-exist")
        with self.assertRaises(PermissionDenied):
            self.service.create(
                Actor("viewer-1", "viewer"), "authorization",
                {"participant_id": participant["id"], "agent_name": "A",
                 "relationship": "spouse", "purposes": ["research"],
                 "expires_at": "2099-12-31"},
            )

    # ---- scope / date checks at submission ----------------------------

    def test_agent_consent_in_scope_activates(self):
        participant = self._participant()
        auth = self._authorization(participant["id"], purposes=["research", "storage"])
        consent = self._draft_consent(participant["id"], auth["id"], ["storage"])
        activated = self._activate(consent, ["storage"])
        self.assertEqual(activated["status"], "active")
        self.assertEqual(activated["data"]["authorization_id"], auth["id"])
        self.assertEqual(activated["data"]["activated_by"], "admin-1")

    def test_agent_consent_scope_exceeded_is_rejected_with_reason(self):
        participant = self._participant()
        auth = self._authorization(participant["id"], purposes=["research"])
        with self.assertRaises(ValidationError) as caught:
            self._draft_consent(participant["id"], auth["id"], ["storage"])
        self.assertIn("exceeds authorized purposes", str(caught.exception))

    def test_agent_consent_widened_at_activation_is_rejected(self):
        participant = self._participant()
        auth = self._authorization(participant["id"], purposes=["research"])
        consent = self._draft_consent(participant["id"], auth["id"], ["research"])
        with self.assertRaises(ValidationError) as caught:
            self._activate(consent, ["research", "storage"])
        self.assertIn("exceeds authorized purposes", str(caught.exception))

    def test_expired_authorization_rejects_consent(self):
        participant = self._participant()
        auth = self._authorization(participant["id"])
        # simulate the expiry date passing without any status change
        expired_data = dict(auth["data"])
        expired_data["expires_at"] = "2026-01-01"
        self.repo.apply_unit_of_work(updates=[{
            "id": auth["id"], "expected_version": auth["version"],
            "status": "active", "data": expired_data,
        }])
        with self.assertRaises(ValidationError) as caught:
            self._draft_consent(participant["id"], auth["id"])
        self.assertIn("expired", str(caught.exception))

    def test_revoked_authorization_and_other_participant_rejected(self):
        participant = self._participant()
        other = self._participant("Other Participant")
        auth = self._authorization(participant["id"])
        self.service.transition(
            admin(), auth["id"], "revoke", {"reason": "participant request"}
        )
        with self.assertRaises(ValidationError) as caught:
            self._draft_consent(participant["id"], auth["id"])
        self.assertIn("revoked", str(caught.exception))
        fresh = self._authorization(participant["id"])
        with self.assertRaises(ValidationError) as caught:
            self._draft_consent(other["id"], fresh["id"])
        self.assertIn("belongs to participant", str(caught.exception))

    # ---- revocation cascade -------------------------------------------

    def test_revoke_stops_draft_consent_but_keeps_effective_conclusions(self):
        participant = self._participant()
        auth = self._authorization(participant["id"], purposes=["research"])
        pending = self._draft_consent(participant["id"], auth["id"])
        effective = self._draft_consent(participant["id"], auth["id"])
        self._activate(effective)
        sample = self.service.create(admin(), "sample", {
            "participant_id": participant["id"],
            "sample_code": "B-001",
            "collected_at": "2026-09-01",
        })
        self.service.transition(admin(), sample["id"], "store", {
            "freezer": "F1", "position": "A1", "consent_id": effective["id"],
        })

        revoked = self.service.transition(
            admin(), auth["id"], "revoke", {"reason": "participant request"}
        )

        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(self.service.get(pending["id"])["status"], "stopped")
        self.assertEqual(self.service.get(effective["id"])["status"], "active")
        self.assertEqual(self.service.get(sample["id"])["status"], "stored")

        actions = [
            (row["entity_id"], row["action"], row["from_status"], row["to_status"])
            for row in self.service.audit_log()
        ]
        self.assertIn((auth["id"], "revoke", "active", "revoked"), actions)
        self.assertIn((pending["id"], "stop", "draft", "stopped"), actions)
        self.assertNotIn((effective["id"], "stop", "active", "stopped"), actions)

    def test_revoke_with_stale_version_rolls_back_everything(self):
        participant = self._participant()
        auth = self._authorization(participant["id"])
        pending = self._draft_consent(participant["id"], auth["id"])
        audit_before = len(self.service.audit_log())

        with self.assertRaises(ConflictError):
            self.service.transition(
                admin(), auth["id"], "revoke",
                {"reason": "stale"}, expected_version=999,
            )

        self.assertEqual(self.service.get(auth["id"])["status"], "active")
        self.assertEqual(self.service.get(pending["id"])["status"], "draft")
        self.assertEqual(len(self.service.audit_log()), audit_before)

    def test_revoke_and_activation_race_never_tears_state(self):
        # Service-level race: threads may interleave arbitrarily, so both can
        # legitimately succeed when activation commits before revocation reads.
        # The invariant is that the final state is always a consistent
        # serialization, never a torn one.
        consistent_outcomes = {
            ("revoked", "stopped"),  # revocation won: pending consent stopped
            ("active", "active"),    # activation won: revocation conflicted
            ("revoked", "active"),   # activation committed first: effective
                                     # consent keeps its conclusion
        }
        for round_no in range(10):
            participant = self._participant()
            auth = self._authorization(participant["id"])
            consent = self._draft_consent(participant["id"], auth["id"])
            outcomes = {}
            barrier = threading.Barrier(2)

            def do_revoke():
                try:
                    barrier.wait()
                    self.service.transition(
                        admin(), auth["id"], "revoke",
                        {"reason": "participant request"},
                    )
                    outcomes["revoke"] = "ok"
                except (ConflictError, ValidationError, InvalidTransition):
                    outcomes["revoke"] = "lost"

            def do_activate():
                try:
                    barrier.wait()
                    self._activate(consent)
                    outcomes["activate"] = "ok"
                except (ConflictError, ValidationError, InvalidTransition):
                    outcomes["activate"] = "lost"

            threads = [threading.Thread(target=do_revoke), threading.Thread(target=do_activate)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertIn(
                "ok", outcomes.values(),
                "round %s: both operations lost: %s" % (round_no, outcomes),
            )
            final = (
                self.service.get(auth["id"])["status"],
                self.service.get(consent["id"])["status"],
            )
            self.assertIn(
                final, consistent_outcomes,
                "round %s: torn state %s with outcomes %s"
                % (round_no, final, outcomes),
            )

    def test_simultaneous_commit_allows_exactly_one(self):
        # Both units of work are built from the same pre-read state, so the
        # commits truly overlap: BEGIN IMMEDIATE plus the version guard makes
        # exactly one of them succeed.
        participant = self._participant()
        auth = self._authorization(participant["id"])
        consent = self._draft_consent(participant["id"], auth["id"])
        results = []
        barrier = threading.Barrier(2)

        def run_round(auth_now, consent_now):
            def revoke_unit():
                barrier.wait()
                try:
                    self.repo.apply_unit_of_work(updates=[
                        {"id": auth["id"], "expected_version": auth_now["version"],
                         "status": "revoked", "data": auth["data"]},
                        {"id": consent["id"], "expected_version": consent_now["version"],
                         "status": "stopped", "data": consent["data"]},
                    ])
                    results.append("revoke")
                except ConflictError:
                    pass

            def activate_unit():
                barrier.wait()
                try:
                    activated = dict(consent["data"])
                    activated["version"] = "v1"
                    self.repo.apply_unit_of_work(
                        updates=[{"id": consent["id"],
                                  "expected_version": consent_now["version"],
                                  "status": "active", "data": activated}],
                        guards=[{"id": auth["id"],
                                 "expected_version": auth_now["version"],
                                 "required_status": "active"}],
                    )
                    results.append("activate")
                except ConflictError:
                    pass

            threads = [threading.Thread(target=revoke_unit),
                       threading.Thread(target=activate_unit)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        for _ in range(10):
            del results[:]
            run_round(self.service.get(auth["id"]), self.service.get(consent["id"]))
            self.assertEqual(len(results), 1)
            winner = results[0]
            auth_status = self.service.get(auth["id"])["status"]
            consent_status = self.service.get(consent["id"])["status"]
            if winner == "revoke":
                self.assertEqual((auth_status, consent_status), ("revoked", "stopped"))
            else:
                self.assertEqual((auth_status, consent_status), ("active", "active"))
            # reset for the next round
            self.repo.apply_unit_of_work(updates=[
                {"id": auth["id"], "expected_version": None,
                 "status": "active", "data": auth["data"]},
                {"id": consent["id"], "expected_version": None,
                 "status": "draft", "data": consent["data"]},
            ])

    # ---- HTTP interface ------------------------------------------------

    def test_http_returns_explicit_rejection_reason(self):
        server = create_server("127.0.0.1", 0, self.service, RuleEngine(),
                               str(Path(__file__).resolve().parent.parent / "static"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:%s" % server.server_port

            def post(path, payload):
                request = urllib.request.Request(
                    base + path,
                    data=json.dumps(payload).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json",
                             "X-User-Id": "admin-1", "X-Role": "admin"},
                )
                return request

            participant = json.load(urllib.request.urlopen(
                post("/api/participants", {"name": "HTTP Participant"})
            ))
            auth = json.load(urllib.request.urlopen(post("/api/authorizations", {
                "participant_id": participant["id"],
                "agent_name": "Zhang Spouse",
                "relationship": "spouse",
                "purposes": ["research"],
                "expires_at": "2099-12-31",
            })))
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(post("/api/consents", {
                    "participant_id": participant["id"],
                    "scope": ["storage"],
                    "authorization_id": auth["id"],
                }))
            self.assertEqual(caught.exception.code, 400)
            body = json.loads(caught.exception.read().decode("utf-8"))
            self.assertEqual(body["type"], "ValidationError")
            self.assertIn("exceeds authorized purposes", body["error"])

            revoked_request = post("/api/entities/%s/actions" % auth["id"], {
                "action": "revoke",
                "data": {"reason": "participant request"},
            })
            revoked = json.load(urllib.request.urlopen(revoked_request))
            self.assertEqual(revoked["status"], "revoked")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
