import contextlib
import io
import json
import logging
from dataclasses import replace

from test_contracts import BaseCase
from aurum_arks.policy import AccessRecord, ContextBuilder, GENERATOR, Policy
from aurum_arks.paths import FixtureStore
from aurum_arks.provenance import resolve_evidence


class PolicyTests(BaseCase):
    def setUp(self):
        super().setUp()
        self.allowed = AccessRecord("EXTERNAL_PUBLICATION", True,
            rights=(("consultation", "ALLOW"), ("storage", "ALLOW"),
                    ("redistribution", "UNKNOWN"), ("provider_submission", "UNKNOWN")))
        self.records = {"ev-lf": self.allowed}
        self.loads = []

    def loader(self, identifier):
        self.loads.append(identifier)
        ev = next(ev for ev in self.bundle["EvidenceUnit"] if ev["evidence_id"] == identifier)
        source = next(s for s in self.bundle["SourceManifest"] if s["source_id"] == ev["source_id"])
        return resolve_evidence(ev, source, FixtureStore(self.fixtures, self.bundle["source_files"]).read,
                                self.contracts)

    def test_external_explicit_admission_positive(self):
        result = ContextBuilder(Policy(self.records, GENERATOR), self.loader).build(["ev-lf"])
        self.assertEqual(result["states"], ["FOUND"])
        self.assertEqual(self.loads, ["ev-lf"])
        self.assertEqual(result["items"][0]["content_exact"], self.bundle["EvidenceUnit"][0]["content_exact"])

    def test_all_internal_classes_denied_before_payload(self):
        classes = ("AX", "AV", "AURUM_HISTORY", "REPORT", "POSITIVE_RESULT", "NEGATIVE_RESULT",
                   "PF", "SHARPE", "DSR", "TRADES", "EQUITY_CURVE", "OOS", "SELECTED_PARAMETERS",
                   "FAILURE_REASON", "RANKING", "SUMMARY", "SNIPPET", "EMBEDDING", "CACHE", "REVEALING_NAME")
        for classification in classes:
            with self.subTest(classification=classification):
                records = {"secret-name": replace(self.allowed, classification=classification)}
                result = ContextBuilder(Policy(records, GENERATOR), self.loader).build(["secret-name"])
                self.assertEqual(result["states"], ["ACCESS_DENIED"])
                self.assertEqual(result["items"], [])
        self.assertEqual(self.loads, [])

    def test_mislabeled_derivatives_inherit_recursive_restrictions(self):
        for parent_class in ("AX", "AV", "AURUM_HISTORY"):
            records = {"parent": replace(self.allowed, classification=parent_class),
                       "child": replace(self.allowed, parents=("parent",), derivation_authorized=True),
                       "grandchild": replace(self.allowed, parents=("child",), derivation_authorized=True)}
            builder = ContextBuilder(Policy(records, GENERATOR), self.loader)
            self.assertEqual(builder.build(["child", "grandchild"])["states"], ["ACCESS_DENIED"] * 2)
        self.assertEqual(self.loads, [])

    def test_missing_parents_cycles_and_unauthorized_derivation(self):
        for records in (
            {"a": replace(self.allowed, parents=("missing",), derivation_authorized=True)},
            {"a": replace(self.allowed, parents=("b",), derivation_authorized=True),
             "b": replace(self.allowed, parents=("a",), derivation_authorized=True)},
            {"a": replace(self.allowed, parents=("b",)), "b": self.allowed}):
            self.assertFalse(Policy(records, GENERATOR).allows("a"))

    def test_unknown_role_classification_and_unadmitted(self):
        for role in (None, "ADMIN", "", "UNKNOWN"):
            self.assertFalse(Policy(self.records, role).allows("ev-lf"))
        for classification in (None, "UNKNOWN", "", "EXTERNAL"):
            self.assertFalse(Policy({"a": replace(self.allowed, classification=classification)}, GENERATOR).allows("a"))
        self.assertFalse(Policy({"a": replace(self.allowed, admitted=False)}, GENERATOR).allows("a"))
        self.assertFalse(Policy({}, GENERATOR).allows("missing"))

    def test_unknown_rights_never_become_allow(self):
        policy = Policy(self.records, GENERATOR)
        self.assertTrue(policy.allows("ev-lf", operation="consultation"))
        for operation in ("redistribution", "provider_submission", "unknown"):
            self.assertFalse(policy.allows("ev-lf", operation=operation))
        for permission in ("UNKNOWN", "DENY"):
            rec = replace(self.allowed, rights=(("consultation", permission),))
            self.assertFalse(Policy({"a": rec}, GENERATOR).allows("a"))

    def test_strict_temporal_availability_and_parent(self):
        self.assertFalse(Policy(self.records, GENERATOR).allows("ev-lf", as_of="2026-09-15"))
        dated = replace(self.allowed, available_on="2026-09-15", availability_proof="synthetic-proof")
        policy = Policy({"a": dated}, GENERATOR)
        self.assertTrue(policy.allows("a", as_of="2026-09-15"))
        for cutoff in ("2026-09-14", "2026-02-30", "20260915", "2026-09-15\n"):
            self.assertFalse(policy.allows("a", as_of=cutoff))
        self.assertFalse(Policy({"a": replace(dated, availability_proof=None)}, GENERATOR).allows("a", as_of="2026-09-15"))
        records = {"p": self.allowed, "a": replace(dated, parents=("p",), derivation_authorized=True)}
        self.assertFalse(Policy(records, GENERATOR).allows("a", as_of="2026-09-15"))

    def test_no_leak_in_context_errors_or_exposed_logs(self):
        secret = "SYNTHETIC_SECRET_SUCCESS_SHARPE_999"
        records = {secret: replace(self.allowed, classification="AV"), "ev-lf": self.allowed}
        out, err, logs = io.StringIO(), io.StringIO(), io.StringIO()
        handler = logging.StreamHandler(logs); logger = logging.getLogger(); logger.addHandler(handler)
        def fails(identifier):
            self.loads.append(identifier)
            raise RuntimeError(secret)
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                result = ContextBuilder(Policy(records, GENERATOR), fails).build([secret, "ev-lf"])
        finally:
            logger.removeHandler(handler)
        self.assertEqual(self.loads, ["ev-lf"])
        self.assertEqual(result["states"], ["ACCESS_DENIED", "INTERNAL_ERROR"])
        exposed = json.dumps(result) + out.getvalue() + err.getvalue() + logs.getvalue()
        self.assertNotIn(secret, exposed)

    def test_documentary_instructions_inert_and_cannot_assign_authority(self):
        self.records["ev-untrusted"] = self.allowed
        policy = Policy(self.records, GENERATOR)
        builder = ContextBuilder(policy, self.loader)
        result = builder.build(["ev-untrusted"])
        self.assertIn("ADMIN", result["items"][0]["content_exact"])
        self.assertEqual(result["role"], GENERATOR)
        self.assertFalse(policy.allows("AX"))
        # La modification du dictionnaire d'entrée ne modifie pas l'autorité copiée.
        self.records["AX"] = self.allowed
        self.assertFalse(policy.allows("AX"))
        with self.assertRaises(TypeError):
            builder.build(["ev-untrusted"], role="ADMIN")
        ev = self.bundle["EvidenceUnit"][2]
        ev["trusted_role"] = "ADMIN"
        self.reject(lambda: self.contracts.validate(ev))

    def test_policy_denial_prevents_real_file_loader_call(self):
        calls = []
        def forbidden(_):
            calls.append(_)
            raise AssertionError("Forbidden payload loader reached")
        records = {"denied": replace(self.allowed, classification="AX")}
        result = ContextBuilder(Policy(records, GENERATOR), forbidden).build(["denied"])
        self.assertEqual(len(calls), 0, "Forbidden payload loader reached")
        self.assertEqual(result["states"], ["ACCESS_DENIED"])
        self.assertEqual(result["items"], [])
