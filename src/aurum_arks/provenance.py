"""Vérifications inter-objets et résolution TXT sur octets originaux."""
import re

from .serialization import ContractError, fingerprint, sha256
from .validation import CONTRACTS

ID_FIELDS = dict(zip(CONTRACTS, ("source_id", "evidence_id", "numeric_fact_id",
                 "claim_id", "pack_id", "proposal_id", "reference_id")))


def require(condition, code):
    if not condition:
        raise ContractError(code)


def validate_txt_bounds(ev, length=None):
    """Restriction métier RAW UTF-8 ; aucun changement du type JSON Schema integer."""
    locator = ev.get("locator") if isinstance(ev, dict) else None
    if not isinstance(locator, dict) or locator.get("kind") != "RAW_UTF8_BYTE_RANGE":
        return  # La forme et les champs obligatoires restent contrôlés par le schéma.
    if not {"start", "end"} <= locator.keys():
        return
    start, end = locator["start"], locator["end"]
    require(type(start) is int and type(end) is int, "LOCATOR_INDEX_REPRESENTATION")
    require(0 <= start < end and (length is None or end <= length), "LOCATOR_BOUNDS")


def _periods(node):
    if isinstance(node, dict):
        if node.get("state") == "KNOWN" and isinstance(node.get("value"), dict):
            val = node["value"]
            if set(val) == {"start", "end"}:
                require(val["start"] <= val["end"], "PERIOD_REVERSED")
        for value in node.values():
            _periods(value)
    elif isinstance(node, list):
        for value in node:
            _periods(value)


def validate_graph(bundle, contracts):
    """Les métadonnées sont déjà en mémoire ; ne charge aucun octet source."""
    tables = {}
    for name in CONTRACTS:
        table = {}
        for obj in bundle.get(name, []):
            if name == "EvidenceUnit":
                validate_txt_bounds(obj)
            contracts.validate(obj, name)
            _periods(obj)
            identifier = obj[ID_FIELDS[name]]
            require(identifier not in table, "DUPLICATE_ID")
            table[identifier] = obj
        tables[name] = table
    sources, evidence = tables["SourceManifest"], tables["EvidenceUnit"]
    versions = {}
    for source in sources.values():
        key = (source["document_id"], source["document_version"])
        identity = (source["raw_sha256"], source["byte_length"])
        require(key not in versions or versions[key] == identity, "VERSION_BYTES_CONFLICT")
        versions[key] = identity
        availability = source["proven_availability"]
        if availability["date"]["state"] == "KNOWN":
            require(bool(availability["proof_reference"]), "AVAILABILITY_PROOF_MISSING")
    for ev in evidence.values():
        require(ev["source_id"] in sources, "SOURCE_ORPHAN")
        source = sources[ev["source_id"]]
        validate_txt_bounds(ev, source["byte_length"])
        require((ev["document_id"], ev["document_version"]) ==
                (source["document_id"], source["document_version"]), "DOCUMENT_VERSION_MISMATCH")
    for numeric in tables["NumericFact"].values():
        require(numeric["evidence_id"] in evidence, "EVIDENCE_ORPHAN")
        require(numeric["normalization"]["input_evidence_id"] == numeric["evidence_id"],
                "NUMERIC_INPUT_MISMATCH")
        require(numeric["normalization"]["input_expression"] == numeric["expression_original"],
                "NUMERIC_INPUT_MISMATCH")
        verify_numeric(numeric, evidence[numeric["evidence_id"]], contracts)
    for claim in tables["ClaimRecord"].values():
        for link in claim["evidence_links"]:
            require(link["evidence_id"] in evidence, "EVIDENCE_ORPHAN")
    for proposal in tables["ResearchProposalEnvelope"].values():
        for identifier in proposal["evidence_ids"]:
            require(identifier in evidence, "EVIDENCE_ORPHAN")
    for pack in tables["EvidencePack"].values():
        corpus = pack["corpus_manifest"]
        for identifier in corpus["source_ids"]:
            require(identifier in sources, "SOURCE_ORPHAN")
        require(corpus["fingerprint"] == fingerprint({"manifest_id": corpus["manifest_id"],
                "source_ids": corpus["source_ids"]}), "CORPUS_FINGERPRINT")
        admitted = set(pack["admitted_evidence_ids"])
        for identifier in admitted:
            require(identifier in evidence, "EVIDENCE_ORPHAN")
            require(evidence[identifier]["source_id"] in corpus["source_ids"], "PACK_SOURCE_MISSING")
        names = [c["name"] for c in pack["channels"]]
        require(len(set(names)) == len(names), "CHANNEL_DUPLICATE")
        for channel in pack["channels"]:
            ids = channel["evidence_ids"]
            require(set(ids) <= admitted, "CHANNEL_NOT_ADMITTED")
            if channel["state"] == "FOUND":
                require(bool(ids), "FOUND_EMPTY")
            elif channel["state"] in ("NOT_FOUND", "NOT_SEARCHED", "ACCESS_DENIED"):
                require(not ids, "CHANNEL_STATE_CONFLICT")
    return tables


def resolve_evidence(ev, source, load_source, contracts):
    validate_txt_bounds(ev)
    contracts.validate(ev, "EvidenceUnit")
    contracts.validate(source, "SourceManifest")
    require((ev["source_id"], ev["document_id"], ev["document_version"]) ==
            (source["source_id"], source["document_id"], source["document_version"]),
            "DOCUMENT_VERSION_MISMATCH")
    require(ev["locator"]["kind"] == "RAW_UTF8_BYTE_RANGE", "EXTRACTION_NOT_IMPLEMENTED")
    require(source["declared_media_type"] == "text/plain" and source["encoding"] == "UTF-8"
            and source["admission_status"] == "FIXTURE_ONLY" and source["synthetic"],
            "SOURCE_NOT_SUPPORTED_OR_ADMITTED")
    validate_txt_bounds(ev, source["byte_length"])
    raw = load_source(source["source_id"])
    require(type(raw) is bytes and len(raw) == source["byte_length"] and len(raw) <= 65536,
            "RAW_SIZE_MISMATCH")
    require(sha256(raw) == source["raw_sha256"], "RAW_HASH_MISMATCH")
    start, end = ev["locator"]["start"], ev["locator"]["end"]
    require(0 <= start < end <= len(raw), "LOCATOR_BOUNDS")
    try:
        raw.decode("utf-8", errors="strict")
        raw[:start].decode("utf-8", errors="strict")
        raw[:end].decode("utf-8", errors="strict")
        text = raw[start:end].decode("utf-8", errors="strict")
    except UnicodeError:
        raise ContractError("UTF8_BOUNDARY_OR_ENCODING") from None
    require(text == ev["content_exact"], "EXCERPT_MISMATCH")
    require(sha256(raw[start:end]) == ev["excerpt_sha256"], "EXCERPT_HASH_MISMATCH")
    for field, position in (("start_line", start), ("end_line", end - 1)):
        line = ev["locator"][field]
        require(line is None or line == raw[:position].count(b"\n") + 1, "AUXILIARY_LINE_MISMATCH")
    return {"evidence_id": ev["evidence_id"], "source_id": source["source_id"],
            "document_id": source["document_id"], "document_version": source["document_version"],
            "range": [start, end], "content_exact": text,
            "source_sha256": sha256(raw), "excerpt_sha256": sha256(raw[start:end]),
            "raw_bytes": "VERIFIED", "locator": "RESOLVED"}


def verify_numeric(numeric, evidence, contracts):
    contracts.validate(numeric, "NumericFact")
    contracts.validate(evidence, "EvidenceUnit")
    require(numeric["evidence_id"] == evidence["evidence_id"], "NUMERIC_INPUT_MISMATCH")
    expression = numeric["expression_original"]
    norm = numeric["normalization"]
    require(norm["input_expression"] == expression and norm["input_evidence_id"] == evidence["evidence_id"],
            "NUMERIC_INPUT_MISMATCH")
    pattern = r"(?<![\w.+-])" + re.escape(expression) + r"(?![\w.])"
    matches = list(re.finditer(pattern, evidence["content_exact"]))
    require(bool(matches), "NUMERIC_EXPRESSION_NOT_FOUND")
    if numeric["normalized_value"] is None:
        return {"normalization": "NOT_EVALUATED", "unit": "NOT_EVALUATED"}
    require(numeric["normalized_value"] == expression, "NUMERIC_IDENTITY_MISMATCH")
    # L'identité ne convertit ni échelle ni unité. Ces contrôles lexicaux ne
    # constituent pas une interprétation générale du langage documentaire.
    require(numeric["scale"] == {"state": "KNOWN", "value": "ONE"}, "NUMERIC_SCALE_UNSUPPORTED")
    unit = numeric["unit"]
    unit_status = "NOT_EVALUATED"
    if unit["state"] == "KNOWN" and unit["value"] in ("PERCENT", "BASIS_POINT"):
        unit_pattern = r"\s*%(?!\w)" if unit["value"] == "PERCENT" else r"\s+points de base(?!\w)"
        require(any(re.match(unit_pattern, evidence["content_exact"][match.end():])
                    is not None for match in matches), "NUMERIC_UNIT_MISMATCH")
        unit_status = "LEXICAL_UNIT_V1_VERIFIED"
    return {"normalization": "DECIMAL_LITERAL_IDENTITY_V1_VERIFIED", "unit": unit_status}
