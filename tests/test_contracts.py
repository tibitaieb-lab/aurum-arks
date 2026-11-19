import copy
import unittest
from pathlib import Path

from aurum_arks.serialization import ContractError, business_bytes, fingerprint, strict_loads
from aurum_arks.validation import CONTRACTS, Contracts, PREFIX
from aurum_arks.provenance import validate_graph
from jsonschema import Draft202012Validator
from referencing.exceptions import Unresolvable


class BaseCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.arks = Path(__file__).resolve().parents[1]
        cls.fixtures = cls.arks / "tests/fixtures"
        cls.contracts = Contracts(cls.arks / "schemas/v0.1")
        cls.fixed = strict_loads((cls.fixtures / "examples.json").read_bytes())

    def setUp(self):
        self.bundle = copy.deepcopy(self.fixed)

    def reject(self, fn, code=None):
        with self.assertRaises(ContractError) as ctx:
            fn()
        if code:
            self.assertEqual(str(ctx.exception), code)


class ContractsTests(BaseCase):
    def test_all_schema_metas_and_local_refs(self):
        self.assertEqual(len(self.contracts.schemas), 8)
        self.assertEqual(set(self.contracts.validators), {"common", *CONTRACTS})
        validate_graph(self.bundle, self.contracts)

    def test_unknown_contract_version_and_fields(self):
        for name in CONTRACTS:
            for field, value in (("schema_version", "9.9"), ("unexpected", 0)):
                with self.subTest(contract=name, field=field):
                    obj = copy.deepcopy(self.bundle[name][0]); obj[field] = value
                    self.reject(lambda: self.contracts.validate(obj))
        self.reject(lambda: self.contracts.validate({"contract_type": "Unknown"}))

    def test_duplicate_keys_nested_and_top(self):
        for raw in ('{"x":1,"x":2}', '{"outer":{"x":1,"x":1}}'):
            with self.subTest(raw=raw):
                self.reject(lambda: strict_loads(raw), "JSON_DUPLICATE_KEY")

    def test_non_json_and_nonfinite(self):
        for raw in ('NaN', 'Infinity', '-Infinity', '1e999', '{"v":NaN}', '"\\ud800"'):
            with self.subTest(raw=raw):
                self.reject(lambda: strict_loads(raw))
        for value in ({1: "x"}, {"x": (1, 2)}, float("nan")):
            self.reject(lambda: self.contracts.validate(value))

    def test_formats_are_assertions(self):
        for field, value in (("publication_date", "2026-02-30"),
                             ("publication_date", "2026-13-01")):
            obj = copy.deepcopy(self.bundle["SourceManifest"][0])
            obj[field] = {"state": "KNOWN", "value": value}
            self.reject(lambda: self.contracts.validate(obj))
        obj = self.bundle["SourceManifest"][0]
        obj["acquisition"]["acquired_at"] = {"state": "KNOWN", "value": "2026-09-15T25:00:00Z"}
        self.reject(lambda: self.contracts.validate(obj))

    def test_unknown_reference_no_retrieval(self):
        for uri in ("urn:unknown", "https://example.invalid/forbidden.json"):
            with self.subTest(uri=uri), self.assertRaises(Unresolvable):
                self.contracts.registry.resolver().lookup(uri)
            self.reject(lambda: self.contracts._check_refs({"$ref": uri}), "SCHEMA_REF_NOT_LOCAL")

    def test_strict_terminal_and_decimal_grammar(self):
        for definition, good, bad in (
            ("id", "valid-id", "valid-id\n"),
            ("sha256", "a" * 64, "a" * 64 + "\n"),
            ("decimal", "-2.5", "-2.5\n")):
            val = Draft202012Validator({"$ref": PREFIX + "common#/$defs/" + definition},
                                       registry=self.contracts.registry)
            self.assertTrue(val.is_valid(good)); self.assertFalse(val.is_valid(bad))
        for value in (True, 0, 2.5, "01", "+1", "1e3", "1,2", " 2", "2.", "2\n"):
            obj = copy.deepcopy(self.bundle["NumericFact"][0]); obj["normalized_value"] = value
            with self.subTest(value=value):
                self.reject(lambda: self.contracts.validate(obj))
        obj = self.bundle["NumericFact"][0]
        obj["currency"] = {"state": "KNOWN", "value": "EUR\n"}
        self.reject(lambda: self.contracts.validate(obj))

    def test_bool_is_not_byte_quantity(self):
        obj = self.bundle["SourceManifest"][0]; obj["byte_length"] = True
        self.reject(lambda: self.contracts.validate(obj))

    def test_attribution_requires_attributed_evidence(self):
        claim = self.bundle["ClaimRecord"][0]
        claim["evidence_links"] = []
        self.reject(lambda: self.contracts.validate(claim))
        claim["evidence_links"] = [{"evidence_id": "ev-lf", "relation": "CONTEXT"}]
        self.reject(lambda: self.contracts.validate(claim))

    def test_conjecture_is_preserved_unestablished(self):
        claim = self.bundle["ClaimRecord"][1]
        self.contracts.validate(claim)
        self.assertEqual(claim["truth_status"], "NOT_ESTABLISHED")
        self.assertEqual(claim["evidence_links"], [])
        claim["truth_status"] = "PROVEN"
        self.reject(lambda: self.contracts.validate(claim))

    def test_no_semantic_or_downstream_promotion(self):
        claim = self.bundle["ClaimRecord"][0]
        claim["verdicts"]["semantic_faithfulness"] = "PASS_FAITHFUL"
        self.reject(lambda: self.contracts.validate(claim))
        for name in ("ResearchProposalEnvelope", "ExperimentReference"):
            obj = self.bundle[name][0]
            obj["downstream_status"]["BT_LAUNCH_ALLOWED"] = True
            self.reject(lambda: self.contracts.validate(obj))

    def test_fingerprint_fixed_expected_and_unicode(self):
        pack = self.bundle["EvidencePack"][0]["corpus_manifest"]
        obj = {"manifest_id": pack["manifest_id"], "source_ids": pack["source_ids"]}
        self.assertEqual(business_bytes(obj).decode("utf-8"), self.bundle["corpus_fingerprint_input_utf8"])
        self.assertEqual(fingerprint(obj), "6c4ba7bd180f13f1d8f783b04a939dae87f5dda84c87e5b949bfc49afee692a7")
        self.assertNotEqual(fingerprint({"x": "é"}), fingerprint({"x": "e\u0301"}))
        self.assertEqual(fingerprint({"a": 1, "b": 2}), fingerprint({"b": 2, "a": 1}))
        self.reject(lambda: business_bytes({"value": 1.0}))


def _valid(name):
    def test(self):
        for obj in self.bundle[name]:
            self.contracts.validate(obj, name)
    return test


def _invalid(name):
    def test(self):
        obj = self.bundle[name][0]
        del obj[self.contracts.schemas[name]["required"][-1]]
        self.reject(lambda: self.contracts.validate(obj, name))
    return test


for _name in CONTRACTS:
    setattr(ContractsTests, "test_valid_" + _name, _valid(_name))
    setattr(ContractsTests, "test_invalid_" + _name, _invalid(_name))
