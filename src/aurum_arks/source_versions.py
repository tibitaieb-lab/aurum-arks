"""Canonical derived-document revisions, selected by an immutable index generation.

Source IDs remain acquisition IDs. The scientific work is an explicit separate
identity. No mutable active-version registry, schema migration, or PDF parser.
All production mutations use the documentary writer and canonical store/index.
"""
import copy
import json
import re
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

from .doc_checkpoint import atomic_json, utcnow
from .documentary import identifier, MAX_POLICY_ACQUISITIONS, MAX_POLICY_BYTES
from .paths import reject_links
from .store_relocation import relocated_reference  # P3-404 (P3-7c)
from .provenance import require
from .serialization import fingerprint
from .rag_writer import writer

VERSION = 'ARKS_DOCUMENTARY_VERSIONS_V1'


def read(path):
    return json.loads(Path(path).read_bytes())


def digest(path):
    import hashlib
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def original_hash(qualification):
    value = qualification.get('scientific_object_bundle', {}).get('original', {}).get('sha256')
    explicit = qualification.get('scientific_original', {}).get('sha256')
    require(not value or not explicit or value == explicit, 'VERSION_ORIGINAL_CONFLICT')
    value = value or explicit
    require(_hash(value), 'VERSION_ORIGINAL_REQUIRED')
    return value


def empty_catalog():
    return {'version': VERSION, 'works': {}}


def register_initial_version(catalog, record, *, authority_sha256):
    """Pure, validated V1 registration, bound to evidence by the operator API."""
    result = copy.deepcopy(catalog); wid = record['SCIENTIFIC_WORK_ID']; sid = record['SOURCE_ID']
    require(wid not in result['works'] and binding(result, sid) is None, 'VERSION_WORK_ALREADY_EXISTS')
    require(record['VERSION_STATUS'] == 'ACTIVE' and record.get('SUPERSEDES') is None and
            record.get('SUPERSEDED_BY') is None and _hash(authority_sha256), 'VERSION_INITIAL_STATE')
    result['works'][wid] = {'SCIENTIFIC_WORK_ID': wid, 'ORIGINAL_SHA256': record['ORIGINAL_SHA256'],
        'LOGICAL_SOURCE_ID': sid, 'ACTIVE_SOURCE_ID': sid, 'versions': {sid: copy.deepcopy(record)},
        'events': [{'type': 'REGISTER_EXISTING_V1', 'source_id': sid,
                    'utc': record['RECORDED_AT'], 'authority_sha256': authority_sha256}]}
    return validate_catalog(result)


def validate_catalog(catalog):
    require(isinstance(catalog, dict) and catalog.get('version') == VERSION and
            isinstance(catalog.get('works'), dict), 'VERSION_CATALOG')
    sources = set(); originals = set()
    for wid, work in catalog['works'].items():
        original = work.get('ORIGINAL_SHA256')
        require(_hash(original) and wid == 'WORK_' + original and
                work.get('SCIENTIFIC_WORK_ID') == wid and original not in originals,
                'VERSION_WORK_IDENTITY')
        originals.add(original); identifier(work['LOGICAL_SOURCE_ID'])
        versions = work.get('versions', {})
        require(isinstance(versions, dict) and 0 < len(versions) <= 256, 'VERSION_MEMBERS')
        active = []
        hashes = set()
        for sid, v in versions.items():
            identifier(sid)
            require(sid not in sources and v.get('SOURCE_ID') == sid and
                    v.get('SCIENTIFIC_WORK_ID') == wid and v.get('ORIGINAL_SHA256') == original,
                    'VERSION_MEMBER_WORK')
            sources.add(sid)
            derived = v.get('DERIVED_SHA256')
            require(_hash(derived) and derived not in hashes and
                    v.get('DOCUMENT_VERSION_ID') == 'v' + derived, 'VERSION_DERIVED_IDENTITY')
            hashes.add(derived)
            require(v.get('VERSION_STATUS') in ('ACTIVE', 'SUPERSEDED', 'HISTORICAL') and
                    bool(v.get('RECORDED_AT')) and isinstance(v.get('PROVENANCE'), dict) and
                    _hash(v['PROVENANCE'].get('qualification_sha256')), 'VERSION_PROVENANCE')
            if v['VERSION_STATUS'] == 'ACTIVE': active.append(sid)
            parent = v.get('SUPERSEDES'); child = v.get('SUPERSEDED_BY')
            require(parent is None or (parent != sid and parent in versions and
                    versions[parent].get('SUPERSEDED_BY') == sid), 'VERSION_SUPERSEDES')
            require(child is None or (child != sid and child in versions and
                    versions[child].get('SUPERSEDES') == sid), 'VERSION_SUPERSEDED_BY')
            seen = {sid}; cursor = parent
            while cursor is not None:
                require(cursor not in seen, 'VERSION_CYCLE'); seen.add(cursor)
                cursor = versions[cursor].get('SUPERSEDES')
        require(len(active) == 1 and work.get('ACTIVE_SOURCE_ID') == active[0],
                'VERSION_EXACTLY_ONE_ACTIVE')
        require(work['LOGICAL_SOURCE_ID'] in versions and
                sum(v.get('SUPERSEDES') is None for v in versions.values()) == 1,
                'VERSION_ROOT')
        require(isinstance(work.get('events'), list) and bool(work['events']), 'VERSION_EVENTS')
    return catalog


def binding(catalog, source_id):
    for work in catalog['works'].values():
        if source_id in work['versions']:
            return copy.deepcopy(work['versions'][source_id]) | {
                'LOGICAL_SOURCE_ID': work['LOGICAL_SOURCE_ID'],
                'ACTIVE_SOURCE_ID': work['ACTIVE_SOURCE_ID']}
    return None


def validate_selection(catalog, snapshot, metadata=None):
    validate_catalog(catalog)
    sources = {s['source_id']: s for s in snapshot['sources']}
    require(len(sources) == len(snapshot['sources']), 'VERSION_DUPLICATE_SOURCE')
    for wid, work in catalog['works'].items():
        present = set(work['versions']) & set(sources)
        require(present == {work['ACTIVE_SOURCE_ID']}, 'VERSION_INDEX_SELECTION')
        sid = work['ACTIVE_SOURCE_ID']; version = work['versions'][sid]; source = sources[sid]
        require(source['source_sha256'] == version['DERIVED_SHA256'] and
                source['document_version'] == version['DOCUMENT_VERSION_ID'], 'VERSION_INDEX_IDENTITY')
        if metadata is not None:
            for key, meta in metadata.items():
                original = (meta.get('scientific_object_bundle', {}).get('original', {}).get('sha256')
                            or meta.get('scientific_original', {}).get('sha256'))
                if key in sources and original == work['ORIGINAL_SHA256']:
                    require(key == sid, 'VERSION_DUPLICATE_SCIENTIFIC_WORK')
    return catalog


def validate_transition(previous, current, old_snapshot, new_snapshot, metadata=None, *, rollback=False):
    """Only explicit same-work replacements may remove indexed acquisitions."""
    validate_catalog(previous); validate_catalog(current)
    if not previous['works'] and not current['works']: return set()
    validate_selection(current, new_snapshot, metadata)
    require(set(previous['works']) <= set(current['works']), 'VERSION_HISTORY_REMOVED')
    immutable = ('SCIENTIFIC_WORK_ID', 'SOURCE_ID', 'DOCUMENT_VERSION_ID', 'ORIGINAL_SHA256',
                 'DERIVED_SHA256', 'RECORDED_AT', 'PROVENANCE', 'SUPERSEDES')
    for wid, old in previous['works'].items():
        new = current['works'][wid]
        require(old['LOGICAL_SOURCE_ID'] == new['LOGICAL_SOURCE_ID'] and
                set(old['versions']) <= set(new['versions']) and
                new['events'][:len(old['events'])] == old['events'], 'VERSION_HISTORY_CHANGED')
        for sid, record in old['versions'].items():
            require(all(record.get(k) == new['versions'][sid].get(k) for k in immutable),
                    'VERSION_HISTORY_CHANGED')
            if record.get('SUPERSEDED_BY'):
                require(record['SUPERSEDED_BY'] == new['versions'][sid].get('SUPERSEDED_BY'),
                        'VERSION_HISTORY_CHANGED')
        if old['ACTIVE_SOURCE_ID'] != new['ACTIVE_SOURCE_ID'] and not rollback:
            require(new['ACTIVE_SOURCE_ID'] not in old['versions'], 'VERSION_REACTIVATION_REQUIRES_ROLLBACK')
    old_sources = {s['source_id']: s for s in old_snapshot['sources']}
    new_sources = {s['source_id']: s for s in new_snapshot['sources']}
    removed = set(old_sources) - set(new_sources)
    for sid in removed:
        record = binding(current, sid)
        require(record is not None and record['VERSION_STATUS'] != 'ACTIVE' and
                record['ACTIVE_SOURCE_ID'] in new_sources and
                record['DERIVED_SHA256'] == old_sources[sid]['source_sha256'],
                'VERSION_UNAUTHORIZED_SOURCE_REMOVAL')
    for sid in set(old_sources) & set(new_sources):
        require(old_sources[sid] == new_sources[sid], 'VERSION_UNRELATED_SOURCE_CHANGED')
    return removed


def active_manifest(root):
    root = Path(root); active = read(root / 'ACTIVE.json')
    folder = root / active['generation_id']; manifest = read(folder / 'MANIFEST.json')
    require(digest(folder / 'MANIFEST.json') == active['manifest_sha256'], 'VERSION_BASE_MANIFEST')
    require(digest(folder / 'index.sqlite3') == manifest['index_sha256'], 'VERSION_BASE_INDEX')
    seal = read(root / active['release_seal'])
    require(digest(root / active['release_seal']) == active['release_sha256'] and
            seal['manifest_sha256'] == active['manifest_sha256'] and
            seal['index_sha256'] == manifest['index_sha256'] and
            seal['acceptance']['status'] == 'PASS', 'VERSION_BASE_RELEASE')
    validate_selection(manifest.get('documentary_versions', empty_catalog()), manifest['input_snapshot'])
    return active, manifest, seal


class DocumentaryVersioning:
    """Trusted local operator API; not exposed to PDF contents or HTTP uploads."""
    def __init__(self, store, root, operation_dir, *, marker=None):
        self.store = store; self.root = Path(root).resolve(); self.operation = Path(operation_dir).resolve()
        from .rag_index import A
        require(self.operation.is_relative_to(A / 'reports'), 'VERSION_OPERATION_SCOPE')
        reject_links(self.operation); self.operation.mkdir(parents=True, exist_ok=True)
        self.marker = Path(marker or A / 'DOCUMENTAIRE_V1_WRITER.json')

    def _state(self, state, **extra):
        atomic_json(self.operation / 'STATE.json', {'state': state, 'utc': utcnow(), **extra})

    def _plan(self):
        envelope = read(self.operation / 'PLAN.json'); plan = envelope['plan']
        require(fingerprint(plan) == envelope['sha256'], 'VERSION_PLAN_CHANGED')
        require(plan['store_root'] == str(self.store.root) and plan['rag_root'] == str(self.root),
                'VERSION_STORE_IDENTITY')
        require(digest(plan['authority_reference']) == plan['authority_sha256'], 'VERSION_AUTHORITY_CHANGED')
        require(digest(plan['qualification_reference']) == plan['qualification_sha256'],
                'VERSION_QUALIFICATION_CHANGED')
        return plan

    def plan_revision(self, previous_source_id, candidate, qualification, original, authority_reference):
        from .math_finance import admission_check
        from . import doc_pdf_store
        from .doc_pdf_scope import check_coverage
        candidate = Path(candidate).resolve(); original = Path(original).resolve()
        authority_reference = Path(authority_reference).resolve()
        for p in (candidate, original, authority_reference): reject_links(p)
        h = digest(candidate); oh = digest(original); ah = digest(authority_reference)
        require(h == qualification['source_sha256'] and oh == original_hash(qualification),
                'VERSION_CANDIDATE_IDENTITY')
        require(qualification.get('DOCUMENT_TYPE') == 'DERIVED_CLEAN_TRANSCRIPTION' or
                qualification.get('publication', {}).get('source_type') == 'DERIVED_CLEAN_TRANSCRIPTION',
                'VERSION_DERIVED_ONLY')
        require(qualification.get('selection_status') == 'OK' and
                qualification.get('rights_and_exposure', {}).get('provider_submission') is False and
                qualification.get('rights_and_exposure', {}).get('redistribution') is False,
                'VERSION_LOCAL_QUALIFICATION')
        admission_check(qualification, h)
        prepath = Path(qualification['preflight_reference']); require(digest(prepath) == qualification['preflight_sha256'], 'VERSION_PREFLIGHT_CHANGED')
        pre = read(prepath); doc_pdf_store._identity(pre)
        scope = pre['extractor']['parameters']['selection']; check_coverage(pre, scope)
        require(pre['source_sha256'] == h and pre['source_id'] == qualification['candidate_id'], 'VERSION_PREFLIGHT_IDENTITY')
        request = fingerprint({'previous': previous_source_id, 'derived': h, 'original': oh,
                               'qualification': qualification, 'authority': ah})
        if (self.operation / 'PLAN.json').exists():
            plan = self._plan(); require(plan['request_identity'] == request, 'VERSION_RETRY_CONFLICT'); return plan
        active, manifest, seal = active_manifest(self.root); cfg = self.store.config()
        old = self.store.source(previous_source_id); self.store.original(previous_source_id)
        require(any(s['source_id'] == previous_source_id for s in manifest['input_snapshot']['sources']), 'VERSION_PREVIOUS_NOT_ACTIVE')
        decision = cfg['acquisitions'][previous_source_id]; oldqpath = Path(decision['qualification_reference'])  # valeur enregistree (politique)
        oldqfile = relocated_reference(decision['qualification_reference'])  # P3-404 (P3-7c) : seule la lecture est relue
        require(oldqfile.is_file(), 'VERSION_PREVIOUS_QUALIFICATION_MISSING'); oldq = read(oldqfile)
        require(oldq['source_id'] == previous_source_id and oldq['source_sha256'] == old['raw_sha256'] and
                original_hash(oldq) == oh and h != old['raw_sha256'], 'VERSION_WRONG_WORK_OR_IDENTICAL')
        catalog = copy.deepcopy(manifest.get('documentary_versions', empty_catalog())); wid = 'WORK_' + oh
        timestamp = utcnow()
        def record(sid, dh, qpath, qh):
            return {'SCIENTIFIC_WORK_ID': wid, 'SOURCE_ID': sid, 'DOCUMENT_VERSION_ID': 'v' + dh,
                    'ORIGINAL_SHA256': oh, 'DERIVED_SHA256': dh, 'VERSION_STATUS': 'ACTIVE',
                    'SUPERSEDES': None, 'SUPERSEDED_BY': None, 'RECORDED_AT': timestamp,
                    'PROVENANCE': {'qualification_reference': str(qpath), 'qualification_sha256': qh,
                        'original_reference': str(original), 'original_sha256': oh,
                        'authority_reference': str(authority_reference), 'authority_sha256': ah}}
        if wid not in catalog['works']:
            require(binding(catalog, previous_source_id) is None, 'VERSION_WRONG_WORK')
            catalog = register_initial_version(catalog, record(previous_source_id, old['raw_sha256'], oldqpath, digest(oldqfile)), authority_sha256=ah)
        work = catalog['works'][wid]
        require(work['ACTIVE_SOURCE_ID'] == previous_source_id and
                not work['versions'][previous_source_id]['SUPERSEDED_BY'], 'VERSION_PREVIOUS_NOT_HEAD')
        sid = work['LOGICAL_SOURCE_ID'] + '_V_' + h[:12]
        if len(sid) > 96: sid = 'SOURCE_V_' + fingerprint({'work': wid, 'derived': h})[:40]
        identifier(sid); require(sid not in cfg['acquisitions'], 'VERSION_SOURCE_ID_COLLISION')
        q = copy.deepcopy(qualification); q['source_id'] = sid
        qpath = self.operation / 'QUALIFICATION.json'
        if qpath.exists(): require(read(qpath) == q, 'VERSION_QUALIFICATION_CHANGED')
        else: atomic_json(qpath, q, exclusive=True)
        rec = record(sid, h, qpath, digest(qpath)); rec['SUPERSEDES'] = previous_source_id
        work['versions'][previous_source_id].update(VERSION_STATUS='SUPERSEDED', SUPERSEDED_BY=sid)
        work['versions'][sid] = rec; work['ACTIVE_SOURCE_ID'] = sid
        work['events'].append({'type': 'SELECT_REVISION', 'from_source': previous_source_id,
                              'to_source': sid, 'utc': timestamp, 'authority_sha256': ah})
        validate_catalog(catalog)
        new_scope = copy.deepcopy(scope); new_scope.update(source_id=sid,
            decision_reference=str(self.operation / 'PLAN.json'))
        if 'qualification_reference' in new_scope: new_scope['qualification_reference'] = str(qpath)
        entry = copy.deepcopy(decision)
        entry.update(candidate_id=q['candidate_id'], expected_bytes=candidate.stat().st_size,
            expected_sha256=h, relative_path='UNKNOWN_' + h[:24] + '.pdf',
            decision_reference=str(self.operation / 'PLAN.json'), qualification_reference=str(qpath),
            qualification_sha256=digest(qpath), pdf_scope=new_scope,
            pdf_profile='ARKS_PDF_PASSIVE_V2' if new_scope['version']=='ARKS_PDF_SCOPE_V2' else 'ARKS_PDF_LOCAL_V1',
            rights_basis='EXPLICIT_DOCUMENTARY_REVISION_AUTHORITY; SAME_SCIENTIFIC_WORK; LOCAL_ONLY')
        require(entry['rights'].get('storage') and entry['rights'].get('indexation') and
                not entry['rights'].get('provider_submission') and not entry['rights'].get('redistribution'),
                'VERSION_RIGHTS')
        require(len(cfg['acquisitions']) < MAX_POLICY_ACQUISITIONS, 'POLICY_BATCH_LIMIT')
        after = copy.deepcopy(cfg); after['acquisitions'][sid] = entry
        require(len(json.dumps(after, ensure_ascii=False, indent=2).encode()) <= MAX_POLICY_BYTES, 'CONFIG_SIZE_LIMIT')
        plan = {'version': VERSION, 'request_identity': request, 'created_utc': timestamp,
            'store_root': str(self.store.root), 'rag_root': str(self.root),
            'scientific_work_id': wid, 'previous_source_id': previous_source_id, 'source_id': sid,
            'candidate': str(candidate), 'derived_sha256': h, 'original': str(original), 'original_sha256': oh,
            'authority_reference': str(authority_reference), 'authority_sha256': ah,
            'qualification_reference': str(qpath), 'qualification_sha256': digest(qpath),
            'base_active': active, 'base_policy': cfg, 'new_policy': after,
            'base_manifest_sha256': active['manifest_sha256'], 'base_index_sha256': manifest['index_sha256'],
            'fusion_policy': seal['fusion_policy'], 'catalog': catalog}
        require(read(self.root / 'ACTIVE.json') == active and self.store.config() == cfg, 'VERSION_CONCURRENT_CHANGE')
        atomic_json(self.operation / 'PLAN.json', {'sha256': fingerprint(plan), 'plan': plan}, exclusive=True)
        atomic_json(self.operation / 'POLICY_DELTA.json', {'source_id_added': sid,
            'before': fingerprint(cfg), 'after': fingerprint(after), 'old_entries_changed': [],
            'entry': entry, 'authority_reference': str(authority_reference)}, exclusive=True)
        self._state('PLANNED'); return plan

    def admit(self, *, interrupt_at=None):
        with writer(self.marker, 'ARKS_DOCUMENTARY_VERSIONING', self.operation):
            p = self._plan(); require(read(self.root / 'ACTIVE.json') == p['base_active'], 'VERSION_ACTIVE_CONFLICT')
            require(digest(p['candidate']) == p['derived_sha256'] and digest(p['original']) == p['original_sha256'], 'VERSION_SOURCE_CHANGED')
            cfg = self.store.config(); require(cfg == p['base_policy'] or cfg == p['new_policy'], 'VERSION_POLICY_CONFLICT')
            path = Path(cfg['source_root']) / p['new_policy']['acquisitions'][p['source_id']]['relative_path']; reject_links(path)
            if not path.exists():
                with path.open('xb') as f: f.write(Path(p['candidate']).read_bytes())
            require(digest(path) == p['derived_sha256'], 'VERSION_COPY_CHANGED')
            if cfg == p['base_policy']: atomic_json(self.store.config_path, p['new_policy'])
            self._state('POLICY_PREPARED')
            if interrupt_at == 'AFTER_POLICY': raise InterruptedError('VERSION_TEST_AFTER_POLICY')
            source = self.store.admit(p['source_id'])
            if interrupt_at == 'AFTER_ADMIT': raise InterruptedError('VERSION_TEST_AFTER_ADMIT')
            result = self.store.extract(p['source_id'], work_dir=self.operation / 'extraction')
            atomic_json(self.operation / 'ADMISSION.json', {'status': 'PASS', 'source': source, 'extraction': result})
            self._state('ADMITTED'); return source

    def _input(self, p):
        from . import doc_pdf_store
        from .rag_index import source_metadata
        manifest = read(self.root / p['base_active']['generation_id'] / 'MANIFEST.json')
        cfg = self.store.config(); key = p['source_id']; source = self.store.source(key)
        report, coverage = doc_pdf_store.load_report(self.store, key)
        units = [json.loads(r[0]) for r in self.store.db.execute('select object from evidence where acquisition_id=? order by id', (key,))]
        item = {'source_id': key, 'source_sha256': source['raw_sha256'], 'document_version': source['document_version'],
                'consultable_status': True, 'evidence_count': len(units), 'source': source, 'coverage': coverage,
                'decision_hash': self.store.decision_hash(key, cfg), 'metadata': {}, 'evidence_identity': fingerprint(units)}
        sources = [s for s in manifest['input_snapshot']['sources'] if s['source_id'] != p['previous_source_id']] + [item]
        metadata = {}
        with closing(sqlite3.connect((self.root / p['base_active']['generation_id'] / 'index.sqlite3').as_uri() + '?mode=ro', uri=True)) as db:
            for sid, obj in db.execute('select source_id,object from chunks group by source_id'):
                if sid != p['previous_source_id']: metadata[sid] = json.loads(obj)['metadata']
        metadata[key] = source_metadata(item, cfg, self.store)
        snapshot = {'version': 'RAG_DOCUMENTARY_REVISION_INPUT_V1', 'store_identity': {'root': str(self.store.root)},
                    'sources': sorted(sources, key=lambda s:s['source_id']), 'source_count': len(sources),
                    'evidence_count': sum(s['evidence_count'] for s in sources)}
        return snapshot, metadata

    def build(self, model, *, embedding_donor=None, interrupt_after=None):
        from .rag_index import IndexBuilder
        with writer(self.marker, 'ARKS_DOCUMENTARY_VERSIONING', self.operation):
            p = self._plan(); require(read(self.root / 'ACTIVE.json') == p['base_active'], 'VERSION_ACTIVE_CONFLICT')
            require(self.store.config() == p['new_policy'], 'VERSION_POLICY_CONFLICT')
            receipt = self.operation / 'BUILD.json'
            if receipt.exists():
                saved = read(receipt); folder = self.root / saved['generation_id']
                require(digest(folder / 'MANIFEST.json') == saved['manifest_sha256'] and
                        digest(folder / 'index.sqlite3') == saved['index_sha256'], 'VERSION_BUILD_CHANGED')
                return folder
            snapshot, meta = self._input(p); builder = IndexBuilder(self.root, model)
            try:
                if embedding_donor: builder.import_verified_embeddings(embedding_donor)
                folder, m = builder.build(snapshot, self.store.root / 'catalogue.sqlite3', meta,
                    interrupt_after=interrupt_after, version_catalog=p['catalog'], expected_active=p['base_active'])
            finally: builder.close()
            require(read(self.root / 'ACTIVE.json') == p['base_active'], 'VERSION_ACTIVE_CONFLICT')
            atomic_json(receipt, {'status': 'PASS', 'generation_id': folder.name,
                'manifest_sha256': digest(folder / 'MANIFEST.json'), 'index_sha256': m['index_sha256'],
                'plan_sha256': fingerprint(p), 'counts': m['counts']}, exclusive=True)
            self._state('VERIFIED'); return folder

    def prepare_rollback(self):
        p = self._plan(); active, manifest, seal = active_manifest(self.root)
        require(active == p['base_active'] and self.store.config() == p['new_policy'], 'VERSION_ACTIVE_CONFLICT')
        old = p['previous_source_id']; self.store.source(old); self.store.original(old)
        from . import doc_pdf_store
        doc_pdf_store.load_report(self.store, old)
        capsule = {'status': 'PASS', 'plan_sha256': fingerprint(p), 'base_active': active,
            'base_index_sha256': manifest['index_sha256'], 'base_manifest_sha256': active['manifest_sha256'],
            'fusion_policy': seal['fusion_policy'], 'historical_source_id': old,
            'original_sha256': p['original_sha256'], 'method': 'FORWARD_GENERATION_FROM_VERIFIED_PRIOR_INDEX'}
        path = self.operation / 'ROLLBACK_CAPSULE.json'
        if path.exists(): require(read(path) == capsule, 'VERSION_ROLLBACK_CAPSULE_CHANGED')
        else: atomic_json(path, capsule, exclusive=True)
        return capsule

    def activate(self, acceptance, *, interrupt_at=None):
        with writer(self.marker, 'ARKS_DOCUMENTARY_VERSIONING', self.operation):
            with writer(self.root / 'INDEX_WRITER.json', 'ARKS_RAG_INDEX_BUILDER', self.root):
                return self._activate(acceptance, interrupt_at=interrupt_at)

    def _activate(self, acceptance, *, interrupt_at=None):
        from .rag_index import publish_verified
        # Both canonical writer guards are held by activate().
        p = self._plan(); built = read(self.operation / 'BUILD.json'); target = self.root / built['generation_id']
        current = read(self.root / 'ACTIVE.json')
        if current.get('generation_id') == target.name and current.get('manifest_sha256') == built['manifest_sha256']:
            active_manifest(self.root); self._state('ACTIVE', active=current); return current
        require(current == p['base_active'] and self.store.config() == p['new_policy'], 'VERSION_ACTIVE_CONFLICT')
        require(digest(target / 'MANIFEST.json') == built['manifest_sha256'] and built['plan_sha256'] == fingerprint(p), 'VERSION_BUILD_CHANGED')
        self.prepare_rollback()
        require(acceptance.get('status') == 'PASS' and acceptance.get('scope') == 'DOCUMENTARY_VERSION_ACTIVATION', 'VERSION_ACCEPTANCE_REQUIRED')
        if interrupt_at == 'BEFORE_ACTIVATE': raise InterruptedError('VERSION_TEST_BEFORE_ACTIVATE')
        publish_verified(self.root, target, acceptance=acceptance, fusion_policy=p['fusion_policy'])
        if interrupt_at == 'AFTER_ACTIVATE': raise InterruptedError('VERSION_TEST_AFTER_ACTIVATE')
        current = read(self.root / 'ACTIVE.json'); self._state('ACTIVE', active=current); return current

    def rollback(self, reason, *, interrupt_at=None):
        """Before activation: no pointer change. After activation: forward generation."""
        from .rag_index import publish_verified
        require(isinstance(reason, str) and reason.strip(), 'VERSION_ROLLBACK_REASON')
        with writer(self.marker, 'ARKS_DOCUMENTARY_VERSIONING', self.operation):
            p = self._plan(); current, current_m, current_seal = active_manifest(self.root)
            if current == p['base_active']:
                self._state('ABORTED_BEFORE_ACTIVATION', reason=reason); return current
            done = self.operation / 'ROLLBACK.json'
            if done.exists():
                receipt = read(done); require(current == receipt['active'], 'VERSION_ACTIVE_CONFLICT'); return current
            # The ACTIVE pointer is authoritative even if the process stopped
            # before its diagnostic completion receipt was persisted.
            if current_m.get('version_rollback', {}).get('plan_sha256') == fingerprint(p):
                atomic_json(done, {'status': 'PASS', 'active': current, 'reason': current_m['version_rollback']['reason'],
                                  'utc': utcnow(), 'recovered_after_publication': True}, exclusive=True)
                self._state('ROLLED_BACK', active=current); return current
            capsule = read(self.operation / 'ROLLBACK_CAPSULE.json')
            require(capsule['status'] == 'PASS' and capsule['plan_sha256'] == fingerprint(p), 'VERSION_ROLLBACK_CAPSULE_CHANGED')
            built = read(self.operation / 'BUILD.json')
            require(current['generation_id'] == built['generation_id'] and current['manifest_sha256'] == built['manifest_sha256'], 'VERSION_ACTIVE_CONFLICT')
            base = self.root / p['base_active']['generation_id']; m = read(base / 'MANIFEST.json')
            require(digest(base / 'MANIFEST.json') == capsule['base_manifest_sha256'] and
                    digest(base / 'index.sqlite3') == capsule['base_index_sha256'], 'VERSION_ROLLBACK_BASE_CHANGED')
            catalog = copy.deepcopy(current_m['documentary_versions']); work = catalog['works'][p['scientific_work_id']]
            for sid, v in work['versions'].items(): v['VERSION_STATUS'] = 'ACTIVE' if sid == p['previous_source_id'] else 'HISTORICAL'
            work['ACTIVE_SOURCE_ID'] = p['previous_source_id']
            pending = self.operation / 'ROLLBACK_PREPARED.json'
            with writer(self.root / 'INDEX_WRITER.json', 'ARKS_RAG_INDEX_BUILDER', self.root):
                if pending.exists():
                    prep = read(pending); target = self.root / prep['generation_id']; rollback_m = read(target / 'MANIFEST.json')
                    require(digest(target / 'MANIFEST.json') == prep['manifest_sha256'], 'VERSION_ROLLBACK_PREPARED_CHANGED')
                else:
                    work['events'].append({'type': 'ROLLBACK', 'from_source': p['source_id'],
                        'to_source': p['previous_source_id'], 'utc': utcnow(), 'reason': reason,
                        'authority_sha256': p['authority_sha256']})
                    validate_transition(current_m['documentary_versions'], catalog, current_m['input_snapshot'], m['input_snapshot'], rollback=True)
                    number = max(int(d.name[-4:]) for d in self.root.glob('INDEX_GEN_[0-9][0-9][0-9][0-9]')) + 1
                    target = self.root / f'INDEX_GEN_{number:04d}'; target.mkdir()
                    shutil.copyfile(base / 'index.sqlite3', target / 'index.sqlite3')
                    require(digest(target / 'index.sqlite3') == m['index_sha256'], 'VERSION_ROLLBACK_COPY')
                    rollback_m = copy.deepcopy(m); rollback_m.update(generation_id=target.name, documentary_versions=catalog)
                    rollback_m['version_rollback'] = {'plan_sha256': fingerprint(p), 'base_active': p['base_active'], 'reason': reason}
                    atomic_json(target / 'MANIFEST.json', rollback_m, exclusive=True)
                    atomic_json(pending, {'generation_id': target.name, 'manifest_sha256': digest(target / 'MANIFEST.json')}, exclusive=True)
                if interrupt_at == 'BEFORE_ACTIVATE': raise InterruptedError('VERSION_TEST_ROLLBACK_BEFORE_ACTIVATE')
                require(read(self.root / 'ACTIVE.json') == current, 'VERSION_ACTIVE_CONFLICT')
                publish_verified(self.root, target, acceptance={'status': 'PASS', 'scope': 'VERIFIED_CANONICAL_VERSION_ROLLBACK'}, fusion_policy=p['fusion_policy'])
                if interrupt_at == 'AFTER_ACTIVATE': raise InterruptedError('VERSION_TEST_ROLLBACK_AFTER_ACTIVATE')
            active = read(self.root / 'ACTIVE.json')
            atomic_json(done, {'status': 'PASS', 'active': active, 'reason': reason, 'utc': utcnow()}, exclusive=True)
            self._state('ROLLED_BACK', active=active); return active
