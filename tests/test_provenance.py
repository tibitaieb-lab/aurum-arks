import copy

from test_contracts import BaseCase
from aurum_arks.paths import FixtureStore
from aurum_arks.provenance import resolve_evidence, validate_graph, verify_numeric
from aurum_arks.serialization import sha256


class ProvenanceTests(BaseCase):
    def setUp(self):
        super().setUp()
        self.store = FixtureStore(self.fixtures, self.bundle["source_files"])

    def resolve(self, ev=None, source=None, loader=None):
        return resolve_evidence(ev or self.bundle["EvidenceUnit"][0],
                                source or self.bundle["SourceManifest"][0],
                                loader or self.store.read, self.contracts)

    def graph(self):
        return validate_graph(self.bundle, self.contracts)

    def test_fixed_lf_crlf_sources_and_exact_bytes(self):
        for ev, source in zip(self.bundle["EvidenceUnit"], self.bundle["SourceManifest"]):
            with self.subTest(source=source["source_id"]):
                trace = self.resolve(ev, source)
                self.assertEqual(trace["content_exact"], ev["content_exact"])
                self.assertEqual(trace["source_sha256"], source["raw_sha256"])
        raw = self.store.read("src-crlf")
        self.assertIn(b"\r\n", raw)
        self.reject(lambda: self.resolve(self.bundle["EvidenceUnit"][1],
                    self.bundle["SourceManifest"][1], lambda _: raw.replace(b"\r\n", b"\n")))

    def test_source_absent(self):
        self.bundle["SourceManifest"].pop(0)
        self.reject(self.graph, "SOURCE_ORPHAN")

    def test_orphan_evidence_all_consumers(self):
        mutations = (
            ("NumericFact", lambda o: o.update(evidence_id="missing")),
            ("ClaimRecord", lambda o: o["evidence_links"][0].update(evidence_id="missing")),
            ("ResearchProposalEnvelope", lambda o: o.update(evidence_ids=["missing"])),
            ("EvidencePack", lambda o: o.update(admitted_evidence_ids=["missing"])))
        for name, mutate in mutations:
            self.bundle = copy.deepcopy(self.fixed); mutate(self.bundle[name][0])
            with self.subTest(contract=name):
                self.reject(self.graph, "EVIDENCE_ORPHAN")

    def test_version_and_document_identity(self):
        for field in ("document_version", "document_id"):
            self.bundle = copy.deepcopy(self.fixed)
            self.bundle["EvidenceUnit"][0][field] = "wrong"
            self.reject(self.graph, "DOCUMENT_VERSION_MISMATCH")
            self.reject(self.resolve, "DOCUMENT_VERSION_MISMATCH")

    def test_duplicate_ids_and_version_conflict(self):
        self.bundle["EvidenceUnit"].append(copy.deepcopy(self.bundle["EvidenceUnit"][0]))
        self.reject(self.graph, "DUPLICATE_ID")
        self.bundle = copy.deepcopy(self.fixed)
        source = copy.deepcopy(self.bundle["SourceManifest"][0]); source["source_id"] = "another"
        source["raw_sha256"] = "0" * 64
        self.bundle["SourceManifest"].append(source)
        self.reject(self.graph, "VERSION_BYTES_CONFLICT")

    def test_same_bytes_do_not_merge_acquisitions_or_rights(self):
        source = copy.deepcopy(self.bundle["SourceManifest"][0])
        source["source_id"] = "acquisition-other"
        source["acquisition"]["acquisition_id"] = "acq-other"
        source["rights"]["consultation"] = "DENY"
        self.bundle["SourceManifest"].append(source)
        tables = self.graph()
        self.assertEqual(len(tables["SourceManifest"]), 4)
        self.assertNotEqual(tables["SourceManifest"]["src-lf"]["rights"], source["rights"])

    def test_raw_hash_and_length_tampering(self):
        raw = self.store.read("src-lf")
        self.reject(lambda: self.resolve(loader=lambda _: b"X" + raw[1:]), "RAW_HASH_MISMATCH")
        self.reject(lambda: self.resolve(loader=lambda _: raw + b"x"), "RAW_SIZE_MISMATCH")

    def test_excerpt_content_and_hash_tampering(self):
        ev = copy.deepcopy(self.bundle["EvidenceUnit"][0]); ev["content_exact"] += "!"
        self.reject(lambda: self.resolve(ev), "EXCERPT_MISMATCH")
        ev = copy.deepcopy(self.bundle["EvidenceUnit"][0]); ev["excerpt_sha256"] = "0" * 64
        self.reject(lambda: self.resolve(ev), "EXCERPT_HASH_MISMATCH")

    def test_locator_bounds_inversion_and_utf8_cuts(self):
        for start, end in ((65, 99999), (141, 65), (65, 65), (1, 2)):
            ev = copy.deepcopy(self.bundle["EvidenceUnit"][0])
            ev["locator"].update(start=start, end=end)
            self.reject(lambda: self.resolve(ev))
        raw = self.store.read("src-lf"); accent = raw.index("é".encode())
        for start, end in ((accent + 1, accent + 2), (accent, accent + 1)):
            ev = copy.deepcopy(self.bundle["EvidenceUnit"][0]); ev["locator"].update(start=start, end=end)
            self.reject(lambda: self.resolve(ev), "UTF8_BOUNDARY_OR_ENCODING")

    def test_repeated_excerpt_second_occurrence(self):
        raw = self.store.read("src-lf"); text = "Répétition : café ☕."; data = text.encode()
        first = raw.index(data); second = raw.index(data, first + 1)
        self.assertNotEqual(first, second)
        ev = copy.deepcopy(self.bundle["EvidenceUnit"][0])
        ev.update(content_exact=text, excerpt_sha256=sha256(data))
        ev["locator"].update(start=second, end=second + len(data), start_line=4, end_line=4)
        self.assertEqual(self.resolve(ev)["range"][0], second)

    def test_unicode_no_normalization_and_auxiliary_line(self):
        raw = self.store.read("src-lf"); data = "e\u0301".encode(); start = raw.index(data)
        ev = copy.deepcopy(self.bundle["EvidenceUnit"][0])
        ev.update(content_exact="e\u0301", excerpt_sha256=sha256(data))
        ev["locator"].update(start=start, end=start + len(data), start_line=None, end_line=None)
        self.assertEqual(self.resolve(ev)["content_exact"], "e\u0301")
        ev["content_exact"] = "é"
        self.reject(lambda: self.resolve(ev), "EXCERPT_MISMATCH")
        ev = copy.deepcopy(self.bundle["EvidenceUnit"][0]); ev["locator"]["start_line"] = 99
        self.reject(lambda: self.resolve(ev), "AUXILIARY_LINE_MISMATCH")

    def test_unsupported_source_no_read(self):
        source = self.bundle["SourceManifest"][0]
        source.update(declared_media_type="application/pdf", encoding="NOT_APPLICABLE",
                      admission_status="PENDING_REVIEW")
        def forbidden(_):
            self.fail("Unsupported source was read")
        self.reject(lambda: self.resolve(source=source, loader=forbidden), "SOURCE_NOT_SUPPORTED_OR_ADMITTED")

    def test_reserved_extraction_is_not_operational(self):
        ev = self.bundle["EvidenceUnit"][0]
        ev["content_type"] = "RESERVED_NON_TEXT"
        ev["transformation"]["rule_version"] = "NOT_IMPLEMENTED"
        ev["locator"] = {"kind": "EXTRACTION_RESERVED", "reference_frame": "VERSIONED_EXTRACTION",
                         "extraction_id": "future", "extraction_version": "v1",
                         "parameters_sha256": "a" * 64, "original_source_sha256": "b" * 64,
                         "physical_page": 1, "printed_page_label": "i", "resolution_status": "NOT_IMPLEMENTED"}
        self.contracts.validate(ev)
        self.reject(self.resolve, "EXTRACTION_NOT_IMPLEMENTED")

    def test_numeric_identity_sign_unit_scale_inputs(self):
        numeric, ev = self.bundle["NumericFact"][0], self.bundle["EvidenceUnit"][0]
        self.assertEqual(verify_numeric(numeric, ev, self.contracts)["normalization"],
                         "DECIMAL_LITERAL_IDENTITY_V1_VERIFIED")
        for mutate, error in (
            (lambda n: n.update(normalized_value="2.5"), "NUMERIC_IDENTITY_MISMATCH"),
            (lambda n: n["unit"].update(value="BASIS_POINT"), "NUMERIC_UNIT_MISMATCH"),
            (lambda n: n["scale"].update(value="THOUSAND"), "NUMERIC_SCALE_UNSUPPORTED"),
            (lambda n: n["normalization"].update(input_expression="0"), "NUMERIC_INPUT_MISMATCH")):
            obj = copy.deepcopy(numeric); mutate(obj)
            with self.subTest(error=error):
                self.reject(lambda: verify_numeric(obj, ev, self.contracts), error)
        obj = copy.deepcopy(numeric); obj.update(expression_original="2.5", normalized_value="2.5")
        obj["normalization"]["input_expression"] = "2.5"
        self.reject(lambda: verify_numeric(obj, ev, self.contracts), "NUMERIC_EXPRESSION_NOT_FOUND")

    def test_zero_unknown_and_basis_points(self):
        raw = self.store.read("src-lf")
        ev = copy.deepcopy(self.bundle["EvidenceUnit"][0])
        # Une Evidence de test supplémentaire, dérivée des octets fixes existants.
        text = "Zéro : 0 ; quantité inconnue : inconnue ; taux : 25 points de base."
        start = raw.index(text.encode()); ev.update(content_exact=text, excerpt_sha256=sha256(text.encode()))
        ev["locator"].update(start=start, end=start + len(text.encode()), start_line=5, end_line=5)
        self.resolve(ev)
        numeric = copy.deepcopy(self.bundle["NumericFact"][0])
        numeric.update(expression_original="0", normalized_value="0", unit={"state": "NOT_APPLICABLE", "value": None})
        numeric["normalization"]["input_expression"] = "0"
        verify_numeric(numeric, ev, self.contracts)
        numeric.update(expression_original="inconnue", normalized_value=None, unit={"state": "UNKNOWN", "value": None})
        numeric["normalization"].update(input_expression="inconnue", status="NOT_EVALUATED", rule_version=None)
        self.assertEqual(verify_numeric(numeric, ev, self.contracts)["normalization"], "NOT_EVALUATED")
        numeric.update(expression_original="25", normalized_value="25", unit={"state": "KNOWN", "value": "BASIS_POINT"})
        numeric["normalization"].update(input_expression="25", status="DECLARED_FOR_TEST", rule_version="DECIMAL_LITERAL_IDENTITY_V1")
        verify_numeric(numeric, ev, self.contracts)

    def test_period_and_availability_proof(self):
        self.bundle["NumericFact"][0]["period"]["value"].update(start="2025-01-01")
        self.reject(self.graph, "PERIOD_REVERSED")
        self.bundle = copy.deepcopy(self.fixed)
        self.bundle["SourceManifest"][0]["proven_availability"] = {
            "date": {"state": "KNOWN", "value": "2026-09-15"}, "proof_reference": None}
        self.reject(self.graph, "AVAILABILITY_PROOF_MISSING")

    def test_pack_states_and_manifest(self):
        for state in ("NOT_FOUND", "NOT_SEARCHED", "ACCESS_DENIED", "INSUFFICIENT_EVIDENCE"):
            self.bundle["EvidencePack"][0]["channels"][0]["state"] = state
            self.graph()
        self.bundle["EvidencePack"][0]["channels"][0]["state"] = "FOUND"
        self.reject(self.graph, "FOUND_EMPTY")
        self.bundle = copy.deepcopy(self.fixed)
        pack = self.bundle["EvidencePack"][0]
        pack["channels"][0]["evidence_ids"] = ["ev-lf"]
        self.reject(self.graph, "CHANNEL_NOT_ADMITTED")
        pack["admitted_evidence_ids"] = ["ev-lf"]
        self.reject(self.graph, "CHANNEL_STATE_CONFLICT")
        pack["channels"][0]["state"] = "FOUND"
        self.graph()
        pack["corpus_manifest"]["fingerprint"] = "0" * 64
        self.reject(self.graph, "CORPUS_FINGERPRINT")
