"""Local documentary V1: trusted decisions, recoverable TXT vault, exact evidence.

No provider, source discovery, shell, OCR, or network access in this module.
The operator config is an authority supplied by the local service, never by a
document or HTTP request. This is not a boundary against a hostile developer.
"""
from copy import deepcopy
from contextlib import contextmanager
from contextvars import ContextVar
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import uuid

from .doc_contracts import DocumentaryContracts
from .doc_inventory import local_regular
from .doc_parser import txt_ranges
from .paths import confined, reject_links
from .policy import AccessRecord, Policy, GENERATOR, ContextBuilder
from .provenance import require
from .serialization import ContractError, fingerprint, sha256, strict_loads
from . import doc_pdf_store
from .doc_checkpoint import atomic_json, atomic_bytes

VERSION = 'DOC_APP_V1'
EXTRACTOR = 'TXT_RAW_LINES_V1'
UNKNOWN = {'state':'UNKNOWN','value':None}
MAX_SOURCE = 65536
MAX_POLICY_ACQUISITIONS = 256
MAX_POLICY_BYTES = 2 * 1024 * 1024


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,95}',value), 'INVALID_ID')
    return value


def stable_identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns



# Versioned bounded lexical ranking; this is not a semantic search engine.
LEXICAL_PROFILE = 'UNICODE_SCRIPT_COMPONENT_COVERAGE_V4'
LEXICAL_GRAMMAR = frozenset('le la les un une des de du sur et en dans pour au aux l d the a an and of in for to on with'.split())
def lexical_components(text):
    import unicodedata
    result=[]
    for word in re.findall(r'[^\W_]+',text):
        start=0;previous=None
        for i,char in enumerate(word):
            name=unicodedata.name(char,'')
            script='LATIN' if name.startswith('LATIN ') else 'GREEK' if name.startswith('GREEK ') else None
            if script:
                if previous and script!=previous:
                    result.append(word[start:i]);start=i
                previous=script
            elif char.isalpha():previous=None
        result.append(word[start:])
    return result

def lexical_query_terms(terms):
    unique=list(dict.fromkeys(part for term in terms for part in lexical_components(term)))
    meaningful=[t for t in unique if t not in LEXICAL_GRAMMAR]
    return meaningful or unique
def lexical_word_score(text,terms):
    from collections import Counter
    tokens=Counter(lexical_components(text.casefold()))
    counts=[tokens[t] for t in terms if tokens[t]]
    return 1000*len(counts)+sum(min(n,3) for n in counts) if counts else 0

class DocumentaryStore:
    def __init__(self, root, schema_root, config_path):
        self.root=Path(root).absolute()
        reject_links(self.root)
        self.root.mkdir(parents=True,exist_ok=True)
        for name in ('originals','staging'):
            confined(self.root,name).mkdir(exist_ok=True)
        self.config_path=Path(config_path).absolute()
        reject_links(self.config_path)
        self.contracts=DocumentaryContracts(Path(schema_root).absolute())
        self.restore_ready=not (self.root/'RESTORE_INACTIVE.json').exists()
        self.db=sqlite3.connect(confined(self.root,'catalogue.sqlite3'))
        self.db.row_factory=sqlite3.Row
        self.db.executescript('''
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS acquisitions(
          id TEXT PRIMARY KEY, operation_key TEXT UNIQUE NOT NULL, state TEXT NOT NULL,
          decision_hash TEXT NOT NULL, source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(
          id TEXT PRIMARY KEY, acquisition_id TEXT NOT NULL REFERENCES acquisitions(id),
          extractor TEXT NOT NULL, decision_hash TEXT NOT NULL, object TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS evidence_acquisition_id_id ON evidence(acquisition_id,id);
        CREATE TABLE IF NOT EXISTS events(
          number INTEGER PRIMARY KEY, acquisition_id TEXT NOT NULL, state TEXT NOT NULL);
        ''')
        doc_pdf_store.init_table(self.db)

    def close(self):
        self.db.close()

    def config(self):
        scope=getattr(self,'_configuration_context',None)
        current=scope.get() if scope is not None else None
        return current if current is not None else self._read_config()

    @contextmanager
    def configuration_scope(self):
        """Share validated POLICY only inside one pass; re-read it at exit."""
        scope=getattr(self,'_configuration_context',None)
        if scope is None:
            scope=self._configuration_context=ContextVar('documentary_configuration',default=None)
        if scope.get() is not None:
            yield
            return
        config=self._read_config();token=scope.set(config)
        try:
            yield
            require(fingerprint(config)==fingerprint(self._read_config()),'POLICY_CHANGED_DURING_CATALOGUE')
        finally:
            scope.reset(token)

    def _read_config(self):
        require(local_regular(self.config_path).st_size<=MAX_POLICY_BYTES,'CONFIG_SIZE_LIMIT')
        config=strict_loads(self.config_path.read_bytes())
        require(config.get('version')=='DOC_POLICY_V1','POLICY_VERSION')
        # 146 existing acquisitions plus at most 65 frozen September 22 files.
        # Keep explicit finite bounds; per-source authorization is unchanged.
        require(type(config.get('acquisitions')) is dict and len(config['acquisitions'])<=MAX_POLICY_ACQUISITIONS,'POLICY_BATCH_LIMIT')
        return config

    @staticmethod
    def policy(config):
        records={}
        for key,d in config['acquisitions'].items():
            identifier(key)
            rights=d.get('rights',{})
            records[key]=AccessRecord(classification=d.get('classification'),
                admitted=d.get('approved') is True and bool(d.get('decision_reference')),
                parents=tuple(d.get('parents',[])),derivation_authorized=d.get('derivation_authorized') is True,
                rights=tuple((k,'ALLOW' if rights.get(k) is True else 'DENY') for k in
                    ('storage','consultation','provider_submission','redistribution')),
                available_on=d.get('available_on'),availability_proof=d.get('availability_proof'))
        # Only the existing trusted operator policy can supply these grants.
        # Complete decision fingerprints bind SHA, parents, rights and identity.
        methods=[]
        grants=config.get('trusted_internal_method_grants',{})
        if type(grants) is dict:
            for key,grant in grants.items():
                d=config['acquisitions'].get(key)
                if not isinstance(d,dict) or not isinstance(grant,dict):continue
                if (d.get('classification')=='INTERNAL_REFERENCE'
                    and grant.get('version')=='ARKS_INTERNAL_METHOD_GRANT_V1'
                    and grant.get('role')==GENERATOR and grant.get('content_scope')=='METHOD_ONLY'
                    and grant.get('decision_sha256')==fingerprint(d)
                    and type(grant.get('authority_sha256')) is str
                    and re.fullmatch('[a-f0-9]{64}',grant['authority_sha256'])
                    and grant.get('authority_reference') and grant.get('review_reference')):
                    try:
                        from .store_relocation import resolve_reference
                        authority=resolve_reference(grant['authority_reference'])
                        if local_regular(authority).st_size<=65536 and sha256(authority.read_bytes())==grant['authority_sha256']:
                            methods.append(key)
                    except (OSError,ContractError,ValueError):pass
        return Policy(records,GENERATOR,trusted_internal_methods=methods)

    def decision(self, key, operation, config=None, as_of=None):
        identifier(key)
        require(self.restore_ready,'RESTORE_CURRENT_POLICY_REQUIRED')
        config=config if config is not None else self.config()
        require(config.get('enabled') is True,'POLICY_INACTIVE')
        require(self.policy(config).allows(key,operation=operation,as_of=as_of),'ACCESS_DENIED')
        d=config['acquisitions'][key]
        require(type(d.get('synthetic')) is bool,'SYNTHETIC_STATUS_REQUIRED')
        require(type(d.get('expected_sha256')) is str and re.fullmatch('[a-f0-9]{64}',d['expected_sha256']), 'EXPECTED_HASH_REQUIRED')
        require(d.get('rights_basis') and d.get('candidate_id'),'DECISION_PROVENANCE_REQUIRED')
        return d

    def decision_hash(self, key, config):
        # Include every ancestor decision: rights cannot be unioned by blob hash.
        seen={}
        def visit(k):
            if k in seen: return
            d=config['acquisitions'][k]; seen[k]=d
            for parent in d.get('parents',[]): visit(parent)
        visit(key)
        return fingerprint({'version':config['version'],'decisions':seen})

    def free_space(self):
        require(shutil.disk_usage(self.root).free >= 2*1024**3,'DISK_RESERVE_LIMIT')

    def _event(self,key,state):
        self.db.execute('insert into events(acquisition_id,state) values (?,?)',(key,state))

    def _selected_bytes(self,path,before,expected_hash,limit=MAX_SOURCE):
        with path.open('rb') as stream:
            opened=os.fstat(stream.fileno()); raw=stream.read(min(limit,before.st_size)+1); after=os.fstat(stream.fileno())
        require(stable_identity(before)==stable_identity(opened)==stable_identity(after)==stable_identity(local_regular(path)),
                'SOURCE_CHANGED_DURING_ACQUISITION')
        require(len(raw)==before.st_size and sha256(raw)==expected_hash,'SOURCE_VERSION_CHANGED')
        return raw

    def admit(self,key,*,interrupt_at=None):
        config=self.config(); d=self.decision(key,'storage',config)
        require(d['rights'].get('hash_local') is True,'HASH_AUTHORIZATION_REQUIRED')
        pdf=d.get('media_type')=='application/pdf'
        if pdf: doc_pdf_store.profile(d,key)
        else:
            require(d.get('media_type')=='text/plain','PDF_READER_NOT_CONFIGURED')
            require(d.get('encoding')=='UTF-8','UTF8_REQUIRED')
        maximum=100*1024**2 if pdf else MAX_SOURCE
        source_root=Path(config['source_root'])
        path=confined(source_root,d['relative_path'])
        if not d['synthetic']:
            required_root=Path(__file__).resolve().parents[3]/'CORPUS_SOURCE'
            require(source_root.resolve()==required_root,'REAL_SOURCE_ROOT_REQUIRED')
        before=local_regular(path)
        require(0 < before.st_size <= maximum,'SOURCE_SIZE_LIMIT')
        require(type(d.get('expected_bytes')) is int and d['expected_bytes']==before.st_size,'SOURCE_VERSION_CHANGED')
        dh=self.decision_hash(key,config)
        op=fingerprint({'acquisition':key,'sha256':d['expected_sha256']})
        row=self.db.execute('select * from acquisitions where id=?',(key,)).fetchone()
        if row:
            require(row['operation_key']==op,'ACQUISITION_VERSION_CONFLICT')
            if row['state']=='ACTIVE':
                require(row['decision_hash']==dh,'POLICY_CHANGED_REVIEW_REQUIRED')
                self._selected_bytes(path,before,d['expected_sha256'],maximum)
                self.original(key,operation='storage')
                return json.loads(row['source'])
        source={'contract_type':'SourceManifest','schema_version':self.contracts.PDF_SOURCE_VERSION if pdf else self.contracts.VERSION,
            'source_id':key,'document_id':'d'+d['expected_sha256'],'document_version':'v'+d['expected_sha256'],
            'acquisition':{'acquisition_id':key,'origin_kind':'SYNTHETIC_FIXTURE' if d['synthetic'] else ('INTERNAL_REFERENCE' if d['classification']=='INTERNAL_REFERENCE' else 'EXTERNAL_PUBLICATION'),
                'origin_reference':d['candidate_id'],'method':'MANUAL_LOCAL_COPY',
                'acquired_at':{'state':'KNOWN','value':datetime.datetime.now(datetime.timezone.utc).isoformat()}},
            'raw_sha256':d['expected_sha256'],'byte_length':before.st_size,'declared_media_type':d['media_type'],
            'encoding':d['encoding'],'document_types':[], 'title':deepcopy(UNKNOWN),'authors':deepcopy(UNKNOWN),
            'language':deepcopy(UNKNOWN),'themes':[],
            'rights':{**{k:'ALLOW' if d['rights'].get(k) is True else 'UNKNOWN' for k in
                        ('storage','consultation','provider_submission','redistribution')},'basis':d['rights_basis']},
            'admission_status':'ADMITTED_LOCAL','synthetic':d['synthetic'],
            'publication_date':deepcopy(UNKNOWN),'studied_period':deepcopy(UNKNOWN),'revision_date':deepcopy(UNKNOWN),
            'proven_availability':{'date':deepcopy(UNKNOWN),'proof_reference':None}}
        if row: source=json.loads(row['source'])
        self.contracts.validate(source,'SourceManifest')
        self.free_space()
        with self.db:
            self.db.execute('insert or ignore into acquisitions values (?,?,?,?,?)',(key,op,'STARTED',dh,json.dumps(source)))
            self._event(key,'STARTED')
        if interrupt_at=='STARTED': raise ContractError('TEST_INTERRUPTION_STARTED')
        temp=confined(self.root,'staging/'+op+'.tmp')
        target=confined(self.root,'originals/'+d['expected_sha256']+('.pdf' if pdf else '.txt'))
        raw=self._selected_bytes(path,before,d['expected_sha256'],maximum)
        if not pdf: txt_ranges(raw)
        if temp.exists():
            require(local_regular(temp).st_size==len(raw) and sha256(temp.read_bytes())==sha256(raw),'STAGING_CORRUPTION')
        else:
            with temp.open('xb') as out:
                out.write(raw); out.flush(); os.fsync(out.fileno())
        with self.db:
            self.db.execute('update acquisitions set state=? where id=?',('COPIED',key)); self._event(key,'COPIED')
        if interrupt_at=='COPIED': raise ContractError('TEST_INTERRUPTION_COPIED')
        if target.exists():
            require(local_regular(target).st_size==len(raw) and sha256(target.read_bytes())==sha256(raw),'VAULT_CORRUPTION')
        else: os.rename(temp,target)  # Windows refuses an existing target; never os.replace.
        with self.db:
            self.db.execute('update acquisitions set state=? where id=?',('PROMOTED',key)); self._event(key,'PROMOTED')
        if interrupt_at=='PROMOTED': raise ContractError('TEST_INTERRUPTION_PROMOTED')
        # Decisions may have changed while copying: publication checks them again.
        current=self.config(); self.decision(key,'storage',current)
        require(self.decision_hash(key,current)==dh,'POLICY_CHANGED_DURING_ADMISSION')
        with self.db:
            self.db.execute('update acquisitions set state=?,decision_hash=? where id=?',('ACTIVE',dh,key))
            self._event(key,'ACTIVE')
        return source

    def source(self,key,operation='consultation',as_of=None):
        config=self.config(); self.decision(key,operation,config,as_of)
        row=self.db.execute('select * from acquisitions where id=?',(key,)).fetchone()
        require(row is not None and row['state']=='ACTIVE','SOURCE_NOT_ACTIVE')
        require(row['decision_hash']==self.decision_hash(key,config),'POLICY_CHANGED_REVIEW_REQUIRED')
        source=strict_loads(row['source']); self.contracts.validate(source,'SourceManifest')
        return source

    def original(self,key,operation='consultation',as_of=None):
        source=self.source(key,operation,as_of)
        pdf=source['declared_media_type']=='application/pdf'
        path=confined(self.root,'originals/'+source['raw_sha256']+('.pdf' if pdf else '.txt'))
        require(local_regular(path).st_size==source['byte_length'],'RAW_SIZE_MISMATCH')
        with path.open('rb') as stream: raw=stream.read(min(source['byte_length'],100*1024**2 if pdf else MAX_SOURCE)+1)
        require(len(raw)==source['byte_length'] and sha256(raw)==source['raw_sha256'],'RAW_HASH_MISMATCH')
        return raw

    def extract(self,key,*,work_dir=None,interrupt_at=None,rebuild_index=False):
        marker=self.root/'RESTORE_INACTIVE.json'
        if not marker.exists():return self._extract(key,work_dir=work_dir,interrupt_at=interrupt_at,rebuild_index=rebuild_index)
        require(self.restore_ready and hasattr(self,'_restore_snapshot'),'RESTORE_CURRENT_POLICY_REQUIRED')
        prior=self._restore_snapshot; observed=self._restore_projection()
        def without_target_index(value):
            return {name:([r for r in rows if r['acquisition_id']!=key] if name=='evidence' else rows) for name,rows in value.items()}
        require((without_target_index(observed)==without_target_index(prior) if rebuild_index else observed==prior),
                'RESTORE_UNAUTHORIZED_DATABASE_DELTA')
        marker_raw=marker.read_bytes();receipt=strict_loads(marker_raw)
        require(sha256(marker_raw)==self._restore_marker_sha256,'RESTORE_CONCURRENT_CHANGE')
        config=self.config();self.decision(key,'consultation',config)
        # Restored copies support current-index reconstruction, never a hidden
        # first extraction or acquisition. Their canonical payload is immutable.
        if config['acquisitions'][key].get('media_type')=='application/pdf':
            row=self.db.execute('select state from pdf_extractions where acquisition_id=?',(key,)).fetchone()
            require(row is not None and row['state']=='ACTIVE','RESTORE_REBUILD_ACTIVE_ONLY')
        try:
            result=self._extract(key,work_dir=work_dir,interrupt_at=interrupt_at,rebuild_index=rebuild_index)
            current=self._restore_projection()
            require(set(current)==set(prior),'RESTORE_UNAUTHORIZED_DATABASE_DELTA')
            for name,rows in prior.items():
                if name=='evidence':
                    require([r for r in rows if r['acquisition_id']!=key]==[r for r in current[name] if r['acquisition_id']!=key], 'RESTORE_UNAUTHORIZED_DATABASE_DELTA')
                elif name=='events':
                    require(current[name][:len(rows)]==rows and all(r['acquisition_id']==key and r['state'] in ('EXTRACTED','PDF_INDEX_REBUILT') for r in current[name][len(rows):]), 'RESTORE_UNAUTHORIZED_DATABASE_DELTA')
                else:require(current[name]==rows,'RESTORE_UNAUTHORIZED_DATABASE_DELTA')
            if config['acquisitions'][key].get('media_type')=='application/pdf':doc_pdf_store.load_report(self,key)
            else:
                for row in self.db.execute('select id from evidence where acquisition_id=?',(key,)):self.resolve(row['id'])
            require(fingerprint(config)==fingerprint(self.config()) and marker.read_bytes()==marker_raw,'RESTORE_CONCURRENT_CHANGE')
            for item in receipt.get('files',[]):
                if item['path']=='catalogue.sqlite3':continue
                path=confined(self.root,item['path']);require(local_regular(path).st_size==item['bytes'] and sha256(path.read_bytes())==item['sha256'],'RESTORE_BACKUP_FILE_CHANGED')
            if receipt.get('version')=='DOC_BACKUP_V2':
                revision=receipt['restore_revision']+1
                atomic_bytes(self.root/f'RESTORE_MARKER.{revision:04d}.json',marker_raw,exclusive=True)
                database=confined(self.root,'catalogue.sqlite3')
                for item in receipt['files']:
                    if item['path']=='catalogue.sqlite3':item.update(bytes=database.stat().st_size,sha256=sha256(database.read_bytes()))
                receipt.update(restore_revision=revision,previous_marker_sha256=sha256(marker_raw),
                    current_policy_fingerprint=fingerprint(config),last_authorized_delta={'operation':'CANONICAL_INDEX_REBUILD','source_id':key,'no_new_pdf_extraction':True})
                atomic_json(marker,receipt)
            self._restore_snapshot=current;self._restore_marker_sha256=sha256(marker.read_bytes())
            return result
        except Exception:
            self.restore_ready=False
            raise

    def _extract(self,key,*,work_dir=None,interrupt_at=None,rebuild_index=False):
        config=self.config(); d=self.decision(key,'consultation',config)
        if d.get('media_type')=='application/pdf':
            return doc_pdf_store.extract(self,key,work_dir=work_dir,interrupt_at=interrupt_at,rebuild_index=rebuild_index)
        require(rebuild_index is False,'PDF_INDEX_REBUILD_ONLY')
        require(d['rights'].get('indexation') is True,'INDEX_AUTHORIZATION_REQUIRED')
        source=self.source(key); raw=self.original(key); dh=self.decision_hash(key,config)
        evidence=[]
        # Entire lines retain conditions and CRLF, no normalization or overlap.
        for start,end in txt_ranges(raw):
            block=raw[start:end]
            ev={'contract_type':'EvidenceUnit','schema_version':'0.1',
                'evidence_id':'e'+fingerprint({'source':key,'version':source['document_version'],'start':start,'end':end,'extractor':EXTRACTOR}),
                'source_id':key,'document_id':source['document_id'],'document_version':source['document_version'],
                'content_exact':block.decode('utf-8'),'content_type':'TEXT_UTF8','excerpt_sha256':sha256(block),
                'locator':{'kind':'RAW_UTF8_BYTE_RANGE','reference_frame':'RAW_BYTES','start':start,'end':end,
                    'start_line':raw[:start].count(b'\n')+1,'end_line':raw[:end-1].count(b'\n')+1,
                    'physical_page':None,'printed_page_label':None},
                'transformation':{'transformation_id':'t'+fingerprint({'source':key,'extractor':EXTRACTOR}),
                    'rule_version':'RAW_UTF8_SLICE_V1','normalization':'NONE'},
                'quality_alerts':['SYNTHETIC_FIXTURE'] if source['synthetic'] else []}
            self.contracts.resolve_txt(ev,source,lambda _:raw)
            evidence.append(ev); start=end
        require(self.decision_hash(key,self.config())==dh,'POLICY_CHANGED_DURING_EXTRACTION')
        self.free_space()
        with self.db:
            self.db.execute('delete from evidence where acquisition_id=?',(key,))
            self.db.executemany('insert into evidence values (?,?,?,?,?)',
                [(e['evidence_id'],key,EXTRACTOR,dh,json.dumps(e)) for e in evidence])
            self._event(key,'EXTRACTED')
        return {'source_id':key,'extractor':EXTRACTOR,'coverage':'COMPLETE_TXT_BYTES',
                'bytes':len(raw),'evidence_count':len(evidence),'physical_pages':'NOT_APPLICABLE',
                'semantic_layout':'NOT_QUALIFIED','policy_hash':dh}

    def revise_failed_pdf(self,key,previous_config):
        return doc_pdf_store.authorize_revision(self,key,previous_config)

    def resolve(self,evidence_id,as_of=None):
        identifier(evidence_id)
        row=self.db.execute('select * from evidence where id=?',(evidence_id,)).fetchone()
        require(row is not None,'EVIDENCE_NOT_FOUND')
        key=row['acquisition_id']; source=self.source(key,as_of=as_of)
        require(row['decision_hash']==self.decision_hash(key,self.config()),'STALE_EXTRACTION')
        if source['declared_media_type']=='application/pdf': return doc_pdf_store.resolve(self,row,source)
        require(row['extractor']==EXTRACTOR,'STALE_EXTRACTION')
        ev=strict_loads(row['object'])
        return self.contracts.resolve_txt(ev,source,lambda _:self.original(key,as_of=as_of))

    def catalogue(self):
        with self.configuration_scope():
            return self._catalogue()

    def _catalogue(self):
        # Operator-only metadata; never returns source names or denied content.
        config=self.config(); access=self.policy(config); output=[]
        for key,d in config['acquisitions'].items():
            row=self.db.execute('select state,decision_hash from acquisitions where id=?',(key,)).fetchone()
            allowed=config.get('enabled') is True and access.allows(key)
            current=bool(row and row['decision_hash']==self.decision_hash(key,config))
            count=self.db.execute('select count(*) from evidence where acquisition_id=?',(key,)).fetchone()[0] if allowed and current else 0
            coverage='COMPLETE_TXT_BYTES' if count else 'NOT_EXTRACTED_OR_NOT_CURRENT'
            pdf_metadata={}
            if d.get('media_type')=='application/pdf':
                coverage='PDF_NOT_EXTRACTED_OR_NOT_CURRENT'
                if allowed and current and row and row['state']=='ACTIVE':
                    try:
                        self.original(key); _,pdf_metadata=doc_pdf_store.load_report(self,key)
                        coverage=pdf_metadata['coverage']
                    except (ContractError,OSError,KeyError): count=0
            binary_available=bool(allowed and current and row and row['state']=='ACTIVE')
            passages_available=binary_available and (d.get('media_type')!='application/pdf' or bool(pdf_metadata and count))
            output.append({'source_id':key,'candidate_id':d.get('candidate_id'),
                'state':row['state'] if row else 'CANDIDATE','consultation':passages_available,
                **({'original_consultation':binary_available} if d.get('media_type')=='application/pdf' else {}),
                'coverage':coverage,'evidence_count':count,'classification_proposal':'NOT_EVALUATED',**pdf_metadata})
        return output

    def candidate_inventory(self):
        config=self.config(); path=config.get('operator_inventory_path')
        if not path: return []
        from .store_relocation import resolve_reference
        path=resolve_reference(path); require(local_regular(path).st_size<=16*1024*1024,'INVENTORY_SIZE_LIMIT')
        data=strict_loads(path.read_bytes())
        require(data.get('inventory_version')=='DOC_INVENTORY_V1' and len(data['entries'])<=10000,'INVENTORY_INVALID')
        return data['entries']

    def search(self,query,limit=8,as_of=None):
        require(type(query) is str and 0<len(query)<=256,'QUERY_LIMIT')
        require(type(limit) is int and 1<=limit<=20,'RESULT_LIMIT')
        terms=re.findall(r'\w+',query.casefold())
        require(0<len(terms)<=20,'QUERY_TERMS_LIMIT')
        terms=lexical_query_terms(terms)
        require(0<len(terms)<=20,'QUERY_TERMS_LIMIT')
        config=self.config(); policy=self.policy(config)
        ranked=[]; issues=[]
        # A bounded lexical scan avoids cross-profile FTS statistics entirely.
        for key in config['acquisitions']:
            if config.get('enabled') is not True or not policy.allows(key,as_of=as_of): continue
            try:
                source=self.source(key,as_of=as_of)
                raw=self.original(key,as_of=as_of)  # Integrity before candidate text is read.
                if source['declared_media_type']=='application/pdf': doc_pdf_store.load_report(self,key)
            except (ContractError,OSError):
                issues.append('SOURCE_UNAVAILABLE_OR_STALE'); continue
            dh=self.decision_hash(key,config)
            extractor=doc_pdf_store.EXTRACTOR if source['declared_media_type']=='application/pdf' else EXTRACTOR
            rows=self.db.execute('select * from evidence where acquisition_id=? and decision_hash=? and extractor=?', (key,dh,extractor))
            for row in rows:
                ev=strict_loads(row['object']); text=ev['content_exact'].casefold()
                score=lexical_word_score(text,terms)
                if score:
                    # PDF load_report has already checked every indexed unit.
                    # TXT candidates retain their byte-range checks, including
                    # matches below top-k, without rereading the original each time.
                    if source['declared_media_type']!='application/pdf':
                        self.contracts.resolve_txt(ev,source,lambda _:raw)
                    ranked.append({'score':score,'evidence':ev})
        require(fingerprint(config)==fingerprint(self.config()),'POLICY_CHANGED_DURING_SEARCH')
        ranked.sort(key=lambda v:(-v['score'],v['evidence']['evidence_id']))
        results=[{'score':hit['score'],'evidence':self.resolve(hit['evidence']['evidence_id'],as_of)}
                 for hit in ranked[:limit]]
        require(fingerprint(config)==fingerprint(self.config()),'POLICY_CHANGED_DURING_SEARCH')
        return {'state':'FOUND' if ranked else 'INSUFFICIENT_EVIDENCE' if issues else 'NOT_FOUND',
                'query':query,'results':results,'issues':issues,
                'scope':'admitted current local TXT/PDF; Unicode word, Greek/Latin and identifier-component coverage, bounded frequency; no translation',
                'retrieval_profile':LEXICAL_PROFILE,
                'rank_is_truth':False,'policy_fingerprint':fingerprint(config)}

    def pack(self,query,as_of=None):
        found=self.search(query,as_of=as_of)
        store=self
        class EvidencePolicy:
            def allows(self,ev,**kwargs):
                row=store.db.execute('select acquisition_id from evidence where id=?',(ev,)).fetchone()
                if row is None: return False
                try: store.source(row[0],as_of=kwargs.get('as_of')); return True
                except ContractError: return False
        ids=[r['evidence']['evidence_id'] for r in found['results']]
        context=ContextBuilder(EvidencePolicy(),lambda eid:self.resolve(eid,as_of)).build(ids,as_of=as_of)
        return {'pack_version':'DOC_EXTRACTIVE_PACK_V1','mode':'EXTRACTIVE',
                'retrieval':found,'context':context,'generation':'NOT_CONFIGURED',
                'channels':{'retrieval':found['state'],'generation':'NOT_SEARCHED'},
                'limits':['No generated answer','No semantic support qualification','PDF coverage is explicitly scoped; excluded pages unavailable',
                          'A line can omit context from adjacent lines; consult original'],
                'as_of':as_of}

    def generate(self,*args,**kwargs):
        raise ContractError('PROVIDER_NOT_CONFIGURED')

    def status(self):
        rows=self.catalogue()
        return {'application':VERSION,'generation':'NOT_CONFIGURED','research_agent_deployed':False,
            'retrieval':'LOCAL_LITERAL_LEXICAL','PDF':'LOCAL_VERSIONED_PROFILES',
            'policy_enabled':self.config().get('enabled') is True,'corpus_entries':len(rows),
            'consultable_documents':sum(r['consultation'] for r in rows),
            'evidence_units':sum(r['evidence_count'] for r in rows),
            'whole_corpus_qualification':'NOT_ASSERTED','semantic_fidelity':'NOT_EXHAUSTIVELY_QUALIFIED'}

    def render(self,key,physical_page,*,work_dir=None):
        """Passive raster of an admitted PDF. No text extraction or index change."""
        config=self.config(); source=self.source(key); dh=self.decision_hash(key,config)
        require(source['declared_media_type']=='application/pdf','PDF_RENDER_MEDIA_TYPE')
        _,coverage=doc_pdf_store.load_report(self,key)
        require(type(physical_page) is int and 1<=physical_page<=coverage['total_physical_pages'],'PDF_RENDER_PAGE_SCOPE')
        scope=deepcopy(config['acquisitions'][key]['pdf_scope'])
        scope.pop('reviewed_pages',None)  # Rendering original bytes needs no text derivative.
        scope.update(version='ARKS_PDF_SCOPE_V2',native_reader='PYPDF_PASSIVE_V2',
                     blank_page_policy='TWO_NATIVE_ZERO_AND_WHITE_RENDER',
                     qualification_reference='PASSIVE_RENDER_OF_CURRENT_ADMITTED_VERSION')
        raw=self.original(key)
        folder=Path(work_dir) if work_dir is not None else doc_pdf_store.doc_pdf.ARKS/'reports'/('DOCUMENTARY_RENDER_'+uuid.uuid4().hex)
        result=doc_pdf_store.doc_pdf.extract_pdf(raw,source_id=key,expected_sha256=source['raw_sha256'],
            work_dir=folder,selection=scope,max_pages=scope['total_physical_pages'],structural_only=True,
            render_page=physical_page,timeout_seconds=30,memory_mib=min(256,doc_pdf_store.passive_memory_request()))
        require(result['status']=='PASSIVE_RENDER_VERIFIED' and result['pages']==[],'PDF_RENDER_NOT_QUALIFIED')
        counts=result['execution_counts']
        require(counts=={'pypdf_text_calls':0,'pdfium_text_calls':0,'renders':1,'pypdf_openings':1,'pdfium_openings':1}
                and not result['audit_forbidden_events'],'PDF_RENDER_UNEXPECTED_OPERATION')
        observed=[{k:w[k] for k in ('warning_code','warning_message_sha256','warning_type')}|
                  {'module':w['warning_origin'].get('module'),'function':w['warning_origin'].get('function')}
                  for w in result['document_warnings']]
        require(observed==scope['expected_document_warnings'],'PDF_RENDER_NEW_DOCUMENT_WARNING')
        png=confined(folder,'render.png'); info=local_regular(png)
        require(info.st_size<=8*1024**2 and sha256(png.read_bytes())==result['render']['png_sha256'],'PDF_RENDER_IMAGE_IDENTITY')
        require(self.decision_hash(key,self.config())==dh and self.original(key)==raw,'PDF_RENDER_SOURCE_OR_POLICY_CHANGED')
        return {'source_id':key,'source_sha256':source['raw_sha256'],'document_version':source['document_version'],
            'physical_page':physical_page,'png_path':str(png),'render':result['render'],
            'new_text_extractions':0,'new_evidence':0,'job_result':str(folder/'RESULT.json')}

    def backup(self,destination):
        destination=Path(destination).absolute(); reject_links(destination)
        require(not destination.exists(),'BACKUP_DESTINATION_EXISTS')
        require(not destination.is_relative_to(self.root),'BACKUP_INSIDE_VAULT')
        require(not self.db.in_transaction,'BACKUP_TRANSACTION_IN_PROGRESS')
        config=self.config(); self.free_space(); destination.mkdir(parents=True)
        marker=destination/'RESTORE_INACTIVE.json'
        atomic_json(marker,{'version':'DOC_BACKUP_V2','state':'INCOMPLETE','complete':False},exclusive=True)
        target=sqlite3.connect(destination/'catalogue.sqlite3')
        target.row_factory=sqlite3.Row
        originals=[]; files={}
        try:
            self.db.backup(target)
            require(target.execute('pragma integrity_check').fetchone()[0]=='ok','BACKUP_CATALOGUE_INTEGRITY')
            (destination/'originals').mkdir(); (destination/'staging').mkdir(); (destination/'extractions').mkdir()
            def copy_exact(relative,expected_hash,expected_bytes=None):
                if relative in files:return
                src=confined(self.root,relative); before=local_regular(src)
                require(before.st_size<=doc_pdf_store.doc_pdf.PASSIVE_MAX_OUTPUT if relative.startswith('extractions/')
                        else before.st_size<=100*1024**2,'BACKUP_FILE_SIZE')
                if expected_bytes is not None:require(before.st_size==expected_bytes,'BACKUP_FILE_SIZE')
                data=src.read_bytes(); after=local_regular(src)
                require(stable_identity(before)==stable_identity(after) and sha256(data)==expected_hash,'BACKUP_FILE_IDENTITY')
                atomic_bytes(confined(destination,relative),data,exclusive=True)
                files[relative]={'path':relative,'bytes':len(data),'sha256':expected_hash}
            for row in target.execute('select * from acquisitions order by id'):
                require(row['state'] in ('ACTIVE','RESERVED'),'BACKUP_UNRESOLVED_ACQUISITION')
                key=row['id']; self.decision(key,'storage',config)
                source=strict_loads(row['source']); self.contracts.validate(source,'SourceManifest')
                require(source['source_id']==key,'BACKUP_SOURCE_IDENTITY')
                pdf=source['declared_media_type']=='application/pdf'
                name=source['raw_sha256']+('.pdf' if pdf else '.txt')
                copy_exact('originals/'+name,source['raw_sha256'],source['byte_length'])
                originals.append({'name':name,'sha256':source['raw_sha256']})
                if pdf:
                    ex=target.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone()
                    require(ex is None or ex['state'] in ('ACTIVE','FAILED'),'BACKUP_UNRESOLVED_EXTRACTION')
                    if ex and ex['state']=='ACTIVE':
                        relative='extractions/'+ex['extraction_id']+'.json'
                        copy_exact(relative,ex['artifact_sha256'])
                        report=strict_loads(confined(destination,relative).read_bytes())
                        require(report['source_id']==key and report['source_sha256']==source['raw_sha256']
                                and report['extraction_id']==ex['extraction_id'],'BACKUP_EXTRACTION_IDENTITY')
            require(fingerprint(config)==fingerprint(self.config()),'POLICY_CHANGED_DURING_BACKUP')
            target.commit()
        finally:target.close()
        database=destination/'catalogue.sqlite3'
        files['catalogue.sqlite3']={'path':'catalogue.sqlite3','bytes':database.stat().st_size,'sha256':sha256(database.read_bytes())}
        atomic_json(marker,{'version':'DOC_BACKUP_V2','state':'INACTIVE','complete':True,
            'requires':'current trusted policy and source reconciliation','originals':originals,
            'files':list(files.values()),'policy_fingerprint_at_backup':fingerprint(config),
            'historical_job_proofs':'Referenced by catalogue; not copied. Failed-attempt recovery still requires those proofs.',
            'restore_revision':0})
        return originals

    def reconcile_restore(self,expected_current_policy_hash):
        """Explicit operator/service operation; never called by an HTTP request."""
        require((self.root/'RESTORE_INACTIVE.json').is_file(),'RESTORE_MARKER_REQUIRED')
        marker_path=self.root/'RESTORE_INACTIVE.json'; marker_raw=marker_path.read_bytes(); marker=strict_loads(marker_raw)
        require(marker.get('state')=='INACTIVE','RESTORE_BACKUP_INCOMPLETE')
        if marker.get('version')=='DOC_BACKUP_V2':
            require(marker.get('complete') is True and type(marker.get('files')) is list,'RESTORE_BACKUP_INCOMPLETE')
            for item in marker['files']:
                path=confined(self.root,item['path']); info=local_regular(path)
                require(info.st_size==item['bytes'] and sha256(path.read_bytes())==item['sha256'],'RESTORE_BACKUP_FILE_CHANGED')
            require(self.db.execute('pragma integrity_check').fetchone()[0]=='ok','RESTORE_CATALOGUE_INTEGRITY')
        config=self.config()
        require(fingerprint(config)==expected_current_policy_hash,'CURRENT_POLICY_IDENTITY_MISMATCH')
        require(config.get('enabled') is True,'POLICY_INACTIVE')
        reconciled=[]
        require(marker_path.read_bytes()==marker_raw,'RESTORE_CONCURRENT_CHANGE')
        with self.db:
            for row in self.db.execute('select * from acquisitions').fetchall():
                key=row['id']; d=config['acquisitions'].get(key)
                source=strict_loads(row['source'])
                current=bool(d and d.get('expected_sha256')==source['raw_sha256']
                             and self.policy(config).allows(key)
                             and row['decision_hash']==self.decision_hash(key,config))
                if not current:
                    self.db.execute('update acquisitions set state=? where id=?',('RESERVED',key))
                    self.db.execute('delete from evidence where acquisition_id=?',(key,))
                reconciled.append({'source_id':key,'state':'CURRENT' if current else 'RESERVED'})
        if marker.get('version')=='DOC_BACKUP_V2':
            # Only the existing conservative reconciliation can change this copy:
            # unavailable/stale rights reserve sources and remove derived Evidence.
            # Preserve the previous receipt; a cut before this publication leaves
            # a hash mismatch and therefore an inactive, explicitly blocked copy.
            revision=marker['restore_revision']+1
            atomic_bytes(self.root/f'RESTORE_MARKER.{revision:04d}.json',marker_raw,exclusive=True)
            database=confined(self.root,'catalogue.sqlite3')
            for item in marker['files']:
                if item['path']=='catalogue.sqlite3':item.update(bytes=database.stat().st_size,sha256=sha256(database.read_bytes()))
            marker.update(restore_revision=revision,previous_marker_sha256=sha256(marker_raw),
                          current_policy_fingerprint=expected_current_policy_hash,reconciled=reconciled)
            atomic_json(marker_path,marker)
        self.restore_ready=True
        self._restore_snapshot=self._restore_projection()
        self._restore_marker_sha256=sha256(marker_path.read_bytes())
        return {'current_policy_hash':expected_current_policy_hash,'reconciled':reconciled,
                'activation':'THIS_PROCESS_ONLY; reconcile again on reopen'}

    def _restore_projection(self):
        """Private logical snapshot; never emitted to a report or HTTP response."""
        result={}
        for row in self.db.execute("select name from sqlite_master where type='table' order by name"):
            name=row[0];require(re.fullmatch('[a-z_]+',name),'RESTORE_TABLE_CONTRACT')
            rows=[dict(r) for r in self.db.execute('select * from "'+name+'"')]
            result[name]=sorted(rows,key=(lambda r:r['number']) if name=='events' else lambda r:json.dumps(r,sort_keys=True))
        return result
