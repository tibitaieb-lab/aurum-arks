"""Démonstration fixe J0A ; toutes les données sont synthétiques."""
from pathlib import Path

from .paths import FixtureStore, confined
from .policy import AccessRecord, ContextBuilder, GENERATOR, Policy
from .provenance import require, resolve_evidence, validate_graph, verify_numeric
from .serialization import fingerprint, strict_loads
from .validation import CONTRACTS, Contracts


def trace_claim(claim, policy, load, contracts):
    """Trace unique du démonstrateur ; seules les relations suivies sont attestées."""
    contracts.validate(claim, "ClaimRecord")
    result = {"claim_id": claim["claim_id"], "claim_text": claim["text"],
              "attribution": "NOT_EVALUATED"}
    if claim["epistemic_status"] != "ATTRIBUTED_ASSERTION":
        return result
    links = [link for link in claim["evidence_links"] if link["relation"] == "ATTRIBUTED_TO"]
    require(len(links) == 1, "TRACE_ATTRIBUTION_CARDINALITY")
    identifier = links[0]["evidence_id"]
    require(policy.allows(identifier), "ACCESS_DENIED")
    resolved = load(identifier)
    require(resolved["evidence_id"] == identifier, "LOADER_ID_MISMATCH")
    return {**resolved, **result, "attribution": "EXPLICIT_CONSTRAINTS_VERIFIED"}


def demonstrate(arks_root):
    arks_root = Path(arks_root)
    fixture_root = confined(arks_root, "tests/fixtures")
    contracts = Contracts(confined(arks_root, "schemas/v0.1"))
    examples = strict_loads(confined(fixture_root, "examples.json").read_bytes())
    tables = validate_graph(examples, contracts)
    store = FixtureStore(fixture_root, examples["source_files"])
    loads = []

    def load(identifier):
        loads.append(identifier)
        ev = tables["EvidenceUnit"][identifier]
        return resolve_evidence(ev, tables["SourceManifest"][ev["source_id"]], store.read, contracts)

    records = {}
    rights = (("consultation", "ALLOW"), ("storage", "ALLOW"),
              ("provider_submission", "UNKNOWN"), ("redistribution", "UNKNOWN"))
    # Classification externe SIMULÉE et explicitement fournie par ce harness.
    # Aucun de ces objets n'est une publication réelle ou une autorité AURUM.
    for source_id in tables["SourceManifest"]:
        records[source_id] = AccessRecord("EXTERNAL_PUBLICATION", True, rights=rights)
    for ev in tables["EvidenceUnit"].values():
        records[ev["evidence_id"]] = AccessRecord("EXTERNAL_PUBLICATION", True,
                                                (ev["source_id"],), True, rights)
    records["synthetic-internal"] = AccessRecord("AX", True, rights=rights)
    records["synthetic-mislabeled"] = AccessRecord("EXTERNAL_PUBLICATION", True,
                                                  ("synthetic-internal",), True, rights)
    policy = Policy(records, GENERATOR)
    context = ContextBuilder(policy, load).build(
        [*tables["EvidenceUnit"], "synthetic-internal", "synthetic-mislabeled"])
    if loads != list(tables["EvidenceUnit"]):
        raise RuntimeError("UNEXPECTED_PAYLOAD_LOAD")
    claim = tables["ClaimRecord"]["claim-source"]
    trace = trace_claim(claim, policy, load, contracts)
    support = [trace["evidence_id"]] if trace["attribution"] == "EXPLICIT_CONSTRAINTS_VERIFIED" else []
    pack = strict_loads(__import__("json").dumps(examples["EvidencePack"][0]))
    pack["pack_id"] = "pack-demonstration"
    pack["admitted_evidence_ids"] = [item["evidence_id"] for item in context["items"]]
    require(set(support) <= set(pack["admitted_evidence_ids"]), "TRACE_NOT_ADMITTED")
    contextual = [identifier for identifier in pack["admitted_evidence_ids"] if identifier not in support]
    pack["channels"] = [
        {"name": "SUPPORT", "state": "FOUND" if support else "NOT_SEARCHED", "evidence_ids": support},
        {"name": "CONTRADICTION", "state": "NOT_SEARCHED", "evidence_ids": []},
        {"name": "CONTEXT", "state": "FOUND" if contextual else "NOT_SEARCHED", "evidence_ids": contextual}]
    validate_graph({**examples, "EvidencePack": [pack]}, contracts)
    business = {"demo_version": "J0A_DEMO_V2", "synthetic": True,
                "contract_objects": {n: examples[n] for n in CONTRACTS}, "trace": trace,
                "numeric_rule": verify_numeric(examples["NumericFact"][0],
                                                examples["EvidenceUnit"][0], contracts),
                "evidence_pack": pack, "context": context,
                "semantic_faithfulness": "NOT_EVALUATED",
                "methodological_admissibility": "NOT_EVALUATED"}
    return {"business": business, "business_fingerprint": fingerprint(business),
            "forbidden_payload_reads": 0}
