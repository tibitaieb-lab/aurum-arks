"""Explicit, fail-closed scientific bundles; no parser or persistence backend.

Scientific equivalence is a source-review obligation, never inferred from a
hash or a successful extraction. Records bind that review to exact text.
"""
import copy
import re
from .provenance import require
from .serialization import fingerprint, sha256

PROFILE = 'ARKS_MATH_FINANCE_TRANSCRIPTION_V1'
FLAGS = {'DOCUMENT_CLASS': 'MATHEMATICAL_FINANCE',
         'DOCUMENT_TYPE': 'DERIVED_CLEAN_TRANSCRIPTION',
         'ADMISSION_PROFILE': PROFILE}
TYPES = {'TEXT', 'FORMULA', 'FORMULA_DEFINITIONS', 'FORMULA_CONTEXT',
         'TABLE', 'FIGURE', 'CAPTION', 'REFERENCE'}
GATES = ('IDENTIFICATION', 'TECHNICAL_INTEGRITY', 'CONTENT_FIDELITY',
         'NATIVE_EXTRACTION', 'GLYPH_INTEGRITY', 'READING_ORDER',
         'SEMANTIC_CHUNKING', 'FORMULA_INTEGRITY', 'TABLE_INTEGRITY',
         'PROVENANCE', 'RAG_READABILITY', 'QUALIFICATION', 'NON_REGRESSION')
UNRESOLVED = re.compile(r'\x00|\ufffd|\ufffc|GLYPH\s*[<(:]|\(cid:\s*\d+\)|CID\s*[<(:]|UNRESOLVED_SOURCE_CONTENT', re.I)


def selected(metadata):
    """Only a complete explicit triple selects this profile. No symbol heuristic."""
    name = metadata.get('ADMISSION_PROFILE')
    if name != PROFILE:
        return False
    require(all(metadata.get(k) == v for k, v in FLAGS.items()), 'MF_EXPLICIT_FLAGS')
    return True


def _hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def contract(metadata):
    require(selected(metadata), 'MF_PROFILE_REQUIRED')
    c = metadata.get('scientific_object_bundle', {})
    require(c.get('version') == PROFILE, 'MF_CONTRACT_VERSION')
    scope = c.get('scope', {})
    require(all(scope.get(k) is True for k in ('scientific', 'financial_or_econometric',
                'substantial_formulas', 'fragile_original_glyphs')), 'MF_SCOPE')
    origin = c.get('original', {})
    require(_hash(origin.get('sha256')) and bool(origin.get('filename')) and
            type(origin.get('physical_pages')) is int and origin['physical_pages'] > 0,
            'MF_ORIGINAL_PROVENANCE')
    require(bool(c.get('document_id')) and bool(c.get('transformation_date')) and
            c.get('transformation_type') == 'DERIVED_CLEAN_TRANSCRIPTION', 'MF_DERIVATION')
    records = c.get('records', [])
    require(isinstance(records, list) and 0 < len(records) <= 10000, 'MF_RECORDS')
    ids = set(); bundles = {}; pages = {}; source_pages = set()
    for r in records:
        require(all(r.get(k) for k in ('BLOCK_ID', 'SECTION_ID', 'SCIENTIFIC_OBJECT_ID')),
                'MF_OBJECT_IDENTITY')
        require(r.get('DOCUMENT_ID') == c['document_id'] and r.get('OBJECT_TYPE') in TYPES,
                'MF_OBJECT_TYPE')
        require(r['BLOCK_ID'] not in ids, 'MF_DUPLICATE_BLOCK'); ids.add(r['BLOCK_ID'])
        require(type(r.get('SOURCE_PAGE')) is int and 1 <= r['SOURCE_PAGE'] <= origin['physical_pages'],
                'MF_SOURCE_PAGE')
        source_pages.add(r['SOURCE_PAGE'])
        require(type(r.get('DERIVED_PAGE')) is int and r['DERIVED_PAGE'] > 0 and
                type(r.get('START')) is int and type(r.get('END')) is int and
                0 <= r['START'] < r['END'] and _hash(r.get('TEXT_SHA256')), 'MF_RECORD_RANGE')
        require(type(r.get('SEQUENCE_INDEX')) is int and r['SEQUENCE_INDEX'] > 0,
                'MF_SEQUENCE')
        require(r.get('BOUNDARY_REVIEW') == 'COMPLETE_SEMANTIC_UNIT' and
                r.get('SOURCE_REVIEW') == 'VERIFIED_AGAINST_ORIGINAL' and
                bool(r.get('REVIEW_REFERENCE')), 'MF_SOURCE_REVIEW_REQUIRED')
        if r['OBJECT_TYPE'].startswith('FORMULA'):
            require(bool(r.get('FORMULA_ID')), 'MF_FORMULA_ID')
        if r['OBJECT_TYPE'] == 'FORMULA':
            require(bool(r.get('ASCII_SAFE_EQUATION')) and bool(r.get('TEXTUAL_LATEX')) and
                    r['ASCII_SAFE_EQUATION'].isascii() and r['TEXTUAL_LATEX'].isascii(),
                    'MF_FORMULA_REPRESENTATION')
            require(_hash(r.get('REVIEWED_FORMULA_SHA256')) and
                    r['REVIEWED_FORMULA_SHA256'] == fingerprint({k: r[k] for k in
                        ('ASCII_SAFE_EQUATION', 'TEXTUAL_LATEX')}), 'MF_FORMULA_ALTERED')
        bundles.setdefault(r['SCIENTIFIC_OBJECT_ID'], []).append(r)
        pages.setdefault(r['DERIVED_PAGE'], []).append(r)
    require(source_pages == set(range(1, origin['physical_pages'] + 1)), 'MF_SOURCE_PAGE_MISSING')
    require(set(pages) == set(range(1, max(pages) + 1)), 'MF_DERIVED_PAGE_MISSING')
    require(any(r['OBJECT_TYPE'] == 'FORMULA' for r in records), 'MF_SUBSTANTIAL_FORMULA_REQUIRED')
    for parts in pages.values():
        end = 0
        for r in sorted(parts, key=lambda x: x['START']):
            require(r['START'] == end, 'MF_UNACCOUNTED_TEXT_OR_OVERLAP'); end = r['END']
    for oid, parts in bundles.items():
        require(sorted(r['SEQUENCE_INDEX'] for r in parts) == list(range(1, len(parts) + 1)),
                'MF_BUNDLE_SEQUENCE')
        formulas = [r for r in parts if r['OBJECT_TYPE'].startswith('FORMULA')]
        if formulas:
            require(sum(r['OBJECT_TYPE'] == 'FORMULA' for r in formulas) == 1 and
                    len({r['FORMULA_ID'] for r in formulas}) == 1, 'MF_BUNDLE_FORMULA')
        for r in parts:
            parent = r.get('PARENT_OBJECT_ID')
            require(parent is None or (parent in bundles and parent != oid), 'MF_PARENT_OBJECT')
    # Parent links must form an acyclic graph.
    def visit(oid, ancestors):
        require(oid not in ancestors, 'MF_PARENT_CYCLE')
        for parent in {r.get('PARENT_OBJECT_ID') for r in bundles[oid]} - {None}:
            visit(parent, ancestors | {oid})
    for oid in bundles:
        visit(oid, set())
    return c


def records_for_evidence(e, metadata, model=None):
    c = contract(metadata); ref = e['locator']['reference']; text = e['content_exact']
    require(not UNRESOLVED.search(text), 'MF_UNRESOLVED_GLYPH')
    require(ref['end'] - ref['start'] == len(text), 'MF_EVIDENCE_RANGE')
    require(sha256(text.encode()) == e['excerpt_sha256'], 'MF_EVIDENCE_HASH')
    records = sorted((r for r in c['records'] if r['DERIVED_PAGE'] == ref['physical_page'] and
                      r['START'] < ref['end'] and r['END'] > ref['start']), key=lambda r: r['START'])
    pos = ref['start']; out = []
    for r in records:
        require(r['START'] == pos and r['END'] <= ref['end'], 'MF_UNIT_MATERIALLY_SPLIT')
        start, end = r['START'] - ref['start'], r['END'] - ref['start']; exact = text[start:end]
        require(sha256(exact.encode()) == r['TEXT_SHA256'], 'MF_REVIEWED_TEXT_ALTERED')
        if r['OBJECT_TYPE'] == 'FORMULA':
            require(r['ASCII_SAFE_EQUATION'] in exact and r['TEXTUAL_LATEX'] in exact,
                    'MF_FORMULA_TRUNCATED')
        if model is not None:
            from .rag_chunk import retrieval_text, PARAMETERS
            require(model.count('passage: ' + retrieval_text(exact)) <= PARAMETERS['max_tokens'],
                    'MF_ATOMIC_UNIT_TOO_LARGE')
        out.append((start, end, r)); pos = r['END']
    require(pos == ref['end'] and out, 'MF_UNACCOUNTED_TEXT')
    return out


def chunk_binding(record, metadata):
    c = metadata['scientific_object_bundle']
    return {'profile': PROFILE, 'contract_sha256': fingerprint(c),
            'record': copy.deepcopy(record), 'original': copy.deepcopy(c['original'])}


def validate_chunk(chunk, evidence):
    require(chunk.get('chunker_version') == PROFILE and len(chunk['evidence_spans']) == 1,
            'MF_CHUNK_VERSION')
    span = chunk['evidence_spans'][0]; e = evidence[span['evidence_id']]
    parts = records_for_evidence(e, chunk['metadata'])
    matched = [r for start, end, r in parts if (start, end) == (span['start'], span['end'])]
    require(len(matched) == 1 and chunk.get('scientific_object') == chunk_binding(matched[0], chunk['metadata']),
            'MF_CHUNK_BINDING')


def bundle_chunks(seed, chunks):
    """Deterministic same-source expansion; incomplete or altered bundles fail."""
    if not selected(seed['metadata']):
        return [seed]
    c = contract(seed['metadata']); oid = seed['scientific_object']['record']['SCIENTIFIC_OBJECT_ID']
    required = {r['BLOCK_ID'] for r in c['records'] if r['SCIENTIFIC_OBJECT_ID'] == oid}
    result = [x for x in chunks if x['source_id'] == seed['source_id'] and
              x['source_sha256'] == seed['source_sha256'] and
              x.get('scientific_object', {}).get('record', {}).get('SCIENTIFIC_OBJECT_ID') == oid]
    require(len(result) == len(required) and
            {x['scientific_object']['record']['BLOCK_ID'] for x in result} == required,
            'MF_BUNDLE_RETRIEVAL_INCOMPLETE')
    require(all(x['scientific_object']['contract_sha256'] == fingerprint(c) for x in result),
            'MF_BUNDLE_CONTRACT_MISMATCH')
    return sorted(result, key=lambda x: x['scientific_object']['record']['SEQUENCE_INDEX'])


def readability_case(query, retrieved, expected_blocks, answer_spans, *, negative=False):
    """Exact extractive answers with offsets; no generative understanding claim.

    Expected blocks and spans are authored from the source before retrieval.
    Negative cases abstain. Their absence premise requires a source review.
    """
    byid = {c['chunk_id']: c for c in retrieved}
    found = {c.get('scientific_object', {}).get('record', {}).get('BLOCK_ID') for c in retrieved}
    ok = bool(query) and bool(expected_blocks or negative) and set(expected_blocks) <= found
    quotes = []; provenance = []
    for span in answer_spans:
        chunk = byid.get(span.get('chunk_id')); start, end = span.get('start'), span.get('end')
        valid = (chunk is not None and type(start) is int and type(end) is int and
                 0 <= start < end <= len(chunk['exact_text']) and
                 chunk['exact_text'][start:end] == span.get('text'))
        ok = ok and valid
        if valid:
            quotes.append(span['text'])
            provenance.append({'chunk_id': chunk['chunk_id'], 'answer_range': [start, end],
                'evidence_spans': chunk['evidence_spans'], 'source_id': chunk['source_id'],
                'derived_sha256': chunk['source_sha256'], 'scientific_object': chunk.get('scientific_object')})
    ok = ok and (not answer_spans if negative else bool(quotes))
    return {'query': query, 'retrieved_chunks': list(byid),
            'scientific_object_ids': sorted({c['scientific_object']['record']['SCIENTIFIC_OBJECT_ID'] for c in retrieved if 'scientific_object' in c}),
            'source_pages': sorted({c['scientific_object']['record']['SOURCE_PAGE'] for c in retrieved if 'scientific_object' in c}),
            'expected_evidence': list(expected_blocks),
            'answer': 'Information non disponible dans le document.' if negative else '\n'.join(quotes),
            'provenance': provenance, 'negative': negative, 'status': 'PASS' if ok else 'FAIL',
            'proof_scope': 'EXTRACTIVE_RETRIEVAL_NOT_LLM_COMPREHENSION'}


def admission_check(qualification, source_sha256):
    """Additional gate only. Canonical preflight and qualification still apply."""
    if not selected(qualification):
        return
    c = contract(qualification)
    receipt = qualification.get('math_finance_admission', {})
    require(receipt.get('source_sha256') == source_sha256 and
            receipt.get('original_sha256') == c['original']['sha256'] and
            receipt.get('contract_sha256') == fingerprint(c), 'MF_ADMISSION_IDENTITY')
    require(receipt.get('gates') == dict.fromkeys(GATES, 'PASS'), 'MF_ADMISSION_GATES')
    require(receipt.get('full_certification') == 'PASS' and
            receipt.get('profile_certification') == 'PASS', 'MF_CERTIFICATION_REQUIRED')
    cases = receipt.get('readability_cases', [])
    require(len(cases) == 12 and all(x.get('status') == 'PASS' for x in cases) and
            len({x.get('query') for x in cases}) == 12 and
            sum(x.get('negative') is True for x in cases) == 1, 'MF_READABILITY_12_REQUIRED')
    require(all(all(k in x for k in ('query', 'retrieved_chunks', 'scientific_object_ids',
                'source_pages', 'expected_evidence', 'answer', 'provenance')) for x in cases),
            'MF_READABILITY_RECEIPT')


def content_qualification(chunk, evidence=()):
    """Byte provenance is distinct from mathematical fidelity or relevance.

    Inspect the full canonical Evidence, not only the displayed excerpt. Never
    repair symbols or claim that a neighbouring passage answers the question.
    """
    metadata = chunk.get('metadata', {})
    coverage = metadata.get('coverage', {})
    scientific = chunk.get('scientific_object')
    reviewed = bool(selected(metadata) and scientific and
                    scientific.get('contract_sha256') == fingerprint(contract(metadata)))
    pdf_unreviewed = coverage.get('semantic_layout') == 'NOT_QUALIFIED'
    warnings = []
    for unit in evidence:
        text = unit.get('content_exact', '')
        if any(0xE000 <= ord(char) <= 0xF8FF or 0xF0000 <= ord(char) <= 0xFFFFD or
               0x100000 <= ord(char) <= 0x10FFFD for char in text):
            reference = unit.get('locator', {}).get('reference', {})
            warnings.append({'code': 'UNREVIEWED_PRIVATE_USE_GLYPHS',
                             'evidence_id': unit.get('evidence_id'),
                             'physical_page': reference.get('physical_page')})
    if warnings:
        reviewed = False
    return {'schema': 'ARKS_CONTENT_QUALIFICATION_V1',
            'provenance_scope': 'SOURCE_IDENTITY_AND_EXACT_TEXT_ONLY',
            'mathematics_validated': reviewed,
            'mathematics_status': 'QUALIFIED_EXPLICIT_SCIENTIFIC_BUNDLE' if reviewed else 'NOT_VALIDATED',
            'usage': 'PROSE_ONLY_FOR_UNREVIEWED_MATH' if pdf_unreviewed or warnings else
                     'EXPLICIT_SCIENTIFIC_BUNDLE' if reviewed else 'TEXT_WITHOUT_INFERRED_MATHEMATICAL_VALIDITY',
            'physical_pages': sorted({p['physical_page'] for p in chunk.get('page_refs', [])}),
            'warnings': warnings,
            'documentary_support': 'CANDIDATE_REQUIRES_RELEVANCE_REVIEW',
            'message': ('Formules non validées : consulter la page originale ; le texte extrait ne prouve pas l’équation.'
                        if not reviewed and (pdf_unreviewed or warnings) else
                        'L’identité et le texte sont contrôlés ; le rang ne valide ni la pertinence ni la vérité scientifique.')}
