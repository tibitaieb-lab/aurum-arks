"""Versioned local hybrid retrieval over existing ARKS Evidence."""
import json,sqlite3,collections,re,os,hashlib,time,functools
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from .serialization import fingerprint,sha256,ContractError
from .doc_checkpoint import atomic_json,atomic_bytes
from .provenance import require
from .documentary import lexical_components,lexical_query_terms,LEXICAL_PROFILE
from .rag_chunk import chunk_evidence,verify_chunk,PARAMETERS,retrieval_text
from .rag_model import LocalEmbedding
from .rag_writer import writer
A=Path(__file__).resolve().parents[2]
DEFAULT_ROOT=A/'data/rag_v1'
READ_PROJECTION_PATH=A/'runtime/rag_v1/read_cache/INDEX_GEN_0090_CHUNKS_V1.json'
READ_PROJECTION_SHA='7e281bde45fb64b8233ba2133b7c650c79ce8697391bab1e71985dc060148c3b'
READ_PROJECTION_INDEX_SHA='37162083089301477d8f32ce5511411a1bfc9c26b6028abe45020c621408656e'


def read(p):return json.loads(Path(p).read_bytes())
def dumps(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def file_sha(path,*,check=None):
    with Path(path).open('rb') as f:
        if check is None:return hashlib.file_digest(f,'sha256').hexdigest()
        digest=hashlib.sha256()
        while block:=f.read(256*1024):check();digest.update(block)
        check();return digest.hexdigest()

def index_execution_trace():
    """C174 (P3-7) : modules qui determinent passages et vecteurs (sha256) et threads ONNX reels (rag_model.py:21)."""
    here=Path(__file__).parent
    return {n:file_sha(here/n) for n in ('rag_chunk.py','rag_index.py','rag_model.py','math_finance.py')},min(4,os.cpu_count() or 1)

def source_metadata(item,policy,store=None):
    s=item['source'];d=policy['acquisitions'][item['source_id']];q={};ref=d.get('qualification_reference')
    from .store_relocation import relocated_reference  # P3-401 (P3-7b) : ancienne racine ARKS du recu verifie -> racine ARKS courante
    path=relocated_reference(ref) if ref else None
    if path and path.exists():
        raw=path.read_bytes()
        q=read(path)
        # Historical campaigns updated technical status after recording a policy
        # hash. Bind metadata to its actual artifact and exact source, retaining
        # both hashes instead of silently claiming an old hash still matches.
        if q.get('source_sha256')!=item['source_sha256'] or q.get('source_id')!=item['source_id']:q={}
    meta={'title':q.get('title') or s.get('title',{}).get('value') or 'UNKNOWN','category':q.get('domains') or s.get('themes') or ['UNKNOWN'],'document_type':q.get('publication',{}).get('source_type') or (s.get('document_types') or ['UNKNOWN'])[0],'language':s.get('language',{}).get('value') or 'UNKNOWN','coverage':item['coverage'],'original_name':q.get('source_original_filename') or Path(d['relative_path']).name,'qualification_reference':ref,'qualification_sha256':d.get('qualification_sha256'),'verified_caption_pages':{}}
    if q:meta['metadata_artifact_sha256']=sha256(raw)
    if d.get('classification')=='INTERNAL_REFERENCE':meta['internal_method_reference']=True
    if q.get('scientific_original'):meta['scientific_original']=q['scientific_original']
    from .math_finance import selected,contract,FLAGS
    if selected(q):
        contract(q)
        meta.update(FLAGS);meta['scientific_object_bundle']=q['scientific_object_bundle']
    if item['coverage']['coverage']=='COMPLETE_PHYSICAL_PAGES_WITH_SOURCE_FACSIMILES' and store:
        from . import doc_pdf_store
        report,_=doc_pdf_store.load_report(store,item['source_id'])
        for page in report['pages']:
            reviewed=page.get('reviewed_page',{})
            # Only existing, qualified artifacts are consulted. No OCR is run.
            if reviewed and reviewed.get('content',{}).get('caption_regions'):
                meta['verified_caption_pages'][str(page['physical_page'])]=True
    return meta

def native_method_text_input(store,key):
    """Existing UTF8 Evidence projected into the existing builder input contract."""
    cfg=store.config();d=store.decision(key,'consultation',cfg)
    require(d.get('classification')=='INTERNAL_REFERENCE' and d.get('media_type')=='text/plain'
            and d.get('rights',{}).get('indexation') is True,'TXT_METHOD_PROFILE_REQUIRED')
    source=store.source(key);raw=store.original(key)
    units=[json.loads(r[0]) for r in store.db.execute('select object from evidence where acquisition_id=? order by id',(key,))]
    require(bool(units),'TXT_EVIDENCE_REQUIRED')
    for e in units:store.resolve(e['evidence_id'])
    spans=sorted((e['locator']['start'],e['locator']['end']) for e in units)
    require(spans[0][0]==0 and spans[-1][1]==len(raw) and all(a[1]==b[0] for a,b in zip(spans,spans[1:])),'TXT_COVERAGE_GAP')
    return {'source_id':key,'source_sha256':source['raw_sha256'],'document_version':source['document_version'],
        'consultable_status':True,'evidence_count':len(units),'source':source,
        'coverage':{'coverage':'COMPLETE_TXT_BYTES','total_physical_pages':None,'bytes':len(raw)},
        'decision_hash':store.decision_hash(key,cfg),'metadata':{},'evidence_identity':fingerprint(units)}

def connect(path):
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    db.executescript('''PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY, object TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES sources(id),state TEXT NOT NULL,object TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS chunks(id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES sources(id),object TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS postings(term TEXT NOT NULL,chunk_id TEXT NOT NULL REFERENCES chunks(id),frequency INTEGER NOT NULL,PRIMARY KEY(term,chunk_id));
    CREATE TABLE IF NOT EXISTS vectors(chunk_id TEXT PRIMARY KEY REFERENCES chunks(id),cache_key TEXT NOT NULL,vector BLOB NOT NULL);
    CREATE INDEX IF NOT EXISTS postings_cover_term_chunk_frequency ON postings(term,chunk_id,frequency);
    ''');return db

class IndexBuilder:
    def __init__(self,root=DEFAULT_ROOT,model=None):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.model=model or LocalEmbedding()
        self.cache=sqlite3.connect(self.root/'embedding_cache.sqlite3');self.cache.execute('CREATE TABLE IF NOT EXISTS embeddings(key TEXT PRIMARY KEY,vector BLOB NOT NULL)');self.cache.commit()
    def close(self):self.cache.close()
    def import_verified_embeddings(self,folder):
        """Reuse a verified local generation; never infer vectors or alter model keys."""
        import numpy as np
        folder=Path(folder);m=read(folder/'MANIFEST.json')
        require(m['state'] in ('VERIFIED','ACCEPTED') and m['embedding_model']==self.model.manifest,'EMBEDDING_DONOR_MODEL')
        require(file_sha(folder/'index.sqlite3')==m['index_sha256'],'EMBEDDING_DONOR_CHANGED')
        with writer(self.root/'INDEX_WRITER.json','ARKS_RAG_INDEX_BUILDER',self.root):
            donor=sqlite3.connect((folder/'index.sqlite3').resolve().as_uri()+'?mode=ro',uri=True)
            try:
                require(donor.execute('pragma integrity_check').fetchone()[0]=='ok','EMBEDDING_DONOR_INTEGRITY')
                count=0
                with self.cache:
                    for obj,key,blob in donor.execute('select c.object,v.cache_key,v.vector from chunks c join vectors v on v.chunk_id=c.id'):
                        c=read_object(obj);v=np.frombuffer(blob,dtype='<f4')
                        require(sha256(c['retrieval_text'].encode())==c['retrieval_text_sha256'] and
                            key==fingerprint({'model':self.model.manifest,'text_sha256':c['retrieval_text_sha256']}),'EMBEDDING_DONOR_KEY')
                        require(v.shape==(self.model.dimension,) and np.isfinite(v).all() and abs(float(np.linalg.norm(v))-1)<1e-4,'VECTOR_INVALID')
                        # Existing valid model/text cache values remain authoritative.
                        self.cache.execute('insert or ignore into embeddings values (?,?)',(key,blob));count+=1
                    require(count==m['counts']['vector_entries'],'EMBEDDING_DONOR_COUNT')
                return count
            finally:donor.close()
    def build(self,snapshot,evidence_db,metadata,*,interrupt_after=None,version_catalog=None,expected_active=None):
        with writer(self.root/'INDEX_WRITER.json','ARKS_RAG_INDEX_BUILDER',self.root):
            return self._build(snapshot,evidence_db,metadata,interrupt_after=interrupt_after,version_catalog=version_catalog,expected_active=expected_active)
    def _build(self,snapshot,evidence_db,metadata,*,interrupt_after=None,version_catalog=None,expected_active=None):
        from .source_versions import empty_catalog,validate_selection,validate_transition
        active=read(self.root/'ACTIVE.json') if (self.root/'ACTIVE.json').exists() else None
        if expected_active is not None:require(active==expected_active,'VERSION_ACTIVE_CONFLICT')
        previous=read(self.root/active['generation_id']/'MANIFEST.json') if active else None
        old_catalog=previous.get('documentary_versions',empty_catalog()) if previous else empty_catalog()
        catalog=version_catalog if version_catalog is not None else old_catalog
        validate_selection(catalog,snapshot,metadata)
        removable=validate_transition(old_catalog,catalog,previous['input_snapshot'],snapshot,metadata) if previous else set()
        material={'input':snapshot,'metadata':metadata,'chunker':PARAMETERS,'model':self.model.manifest}
        if catalog['works']:material['documentary_versions']=catalog
        identity=fingerprint(material)
        statepath=self.root/'RAG_BUILD_STATE.json';state=read(statepath) if statepath.exists() else {}
        if state.get('input_identity')!=identity:
            number=max([int(p.name[-4:]) for p in self.root.glob('INDEX_GEN_[0-9][0-9][0-9][0-9]')]+[0])+1
            state={'generation_id':f'INDEX_GEN_{number:04d}','input_identity':identity,'phase':'BUILD','sources_done':[],'embeddings_computed':0,'embeddings_reused':0}
            atomic_json(statepath,state)
        folder=self.root/state['generation_id'];folder.mkdir(exist_ok=True)
        state['last_run']={'sources_reused':0,'sources_created':0,'embeddings_computed':0,'embeddings_reused_from_cache':0}
        dbpath=folder/'index.sqlite3'
        if not dbpath.exists() and (self.root/'ACTIVE.json').exists():
            require(file_sha(self.root/active['generation_id']/'index.sqlite3')==previous['index_sha256'],'VERSION_BASE_INDEX')
            active=read(self.root/'ACTIVE.json');old=sqlite3.connect(self.root/active['generation_id']/'index.sqlite3');new=sqlite3.connect(dbpath);old.backup(new);new.close();old.close()
        db=connect(dbpath);inputdb=sqlite3.connect(evidence_db);inputdb.row_factory=sqlite3.Row
        try:
            expected={x['source_id'] for x in snapshot['sources']};old={r[0] for r in db.execute('select id from sources')};require(old<=expected|removable,'INCREMENTAL_SOURCE_REMOVAL_REQUIRES_EXPLICIT_REBUILD')
            # Only a validated same-work transition can remove a source, and only
            # in this detached generation. Historical index and store are immutable.
            with db:
                for sid in old-expected:
                    db.execute('delete from postings where chunk_id in (select id from chunks where source_id=?)',(sid,))
                    db.execute('delete from vectors where chunk_id in (select id from chunks where source_id=?)',(sid,))
                    db.execute('delete from chunks where source_id=?',(sid,))
                    db.execute('delete from evidence where source_id=?',(sid,))
                    db.execute('delete from sources where id=?',(sid,))
            processed=0
            for item in snapshot['sources']:
                key=item['source_id'];existing=db.execute('select object from sources where id=?',(key,)).fetchone()
                if existing:
                    require(read_object(existing[0])==item,'INDEX_SOURCE_CHANGED')
                    # Metadata controls filters, title postings, language and
                    # scientific/facsimile chunking. Reuse only an exact match
                    # from the verified donor index. Empty sources must be
                    # reconsidered because corrected metadata can unlock text.
                    prior=db.execute("select json_extract(object,'$.metadata') from chunks where source_id=? order by id limit 1",(key,)).fetchone()
                    if prior is not None and read_object(prior[0])==metadata[key]:
                        state['last_run']['sources_reused']+=1;continue
                units=[json.loads(r[0]) for r in inputdb.execute('select object from evidence where acquisition_id=? order by id',(key,))]
                require(len(units)==item['evidence_count'] and fingerprint(units)==item['evidence_identity'],'INPUT_EVIDENCE_CHANGED')
                with db:
                    if existing:
                        db.execute('delete from postings where chunk_id in (select id from chunks where source_id=?)',(key,))
                        db.execute('delete from vectors where chunk_id in (select id from chunks where source_id=?)',(key,))
                        db.execute('delete from chunks where source_id=?',(key,))
                        db.execute('delete from evidence where source_id=?',(key,))
                        db.execute('delete from sources where id=?',(key,))
                    db.execute('insert into sources values (?,?)',(key,dumps(item)))
                    for e in units:
                        chunks,status=chunk_evidence(e,item,metadata[key],self.model)
                        db.execute('insert into evidence values (?,?,?,?)',(e['evidence_id'],key,status,dumps(e)))
                        for c in chunks:
                            verify_chunk(c,{e['evidence_id']:e});db.execute('insert into chunks values (?,?,?)',(c['chunk_id'],key,dumps(c)))
                            counts=collections.Counter(lexical_components((c['retrieval_text']+' '+key+' '+str(metadata[key]['title'])).casefold()))
                            db.executemany('insert into postings values (?,?,?)',[(term,c['chunk_id'],n) for term,n in counts.items()])
                state['last_run']['sources_created']+=1;state['sources_done']=sorted(set(state['sources_done'])|{key});atomic_json(statepath,state);processed+=1
                print('CHUNKED',key,flush=True)
                if interrupt_after and processed>=interrupt_after:raise InterruptedError('TEST_INTERRUPTION_AFTER_COMMITTED_SOURCE')
            pending=db.execute('select c.id,c.object from chunks c left join vectors v on v.chunk_id=c.id where v.chunk_id is null order by c.id').fetchall()
            for offset in range(0,len(pending),8):
                batch=pending[offset:offset+8];new=[];cached=[]
                for row in batch:
                    c=json.loads(row['object']);cachekey=fingerprint({'model':self.model.manifest,'text_sha256':c['retrieval_text_sha256']})
                    saved=self.cache.execute('select vector from embeddings where key=?',(cachekey,)).fetchone()
                    if saved:cached.append((row['id'],cachekey,saved[0]));state['embeddings_reused']+=1;state['last_run']['embeddings_reused_from_cache']+=1
                    else:new.append((row['id'],cachekey,c['retrieval_text']))
                if new:
                    vectors=self.model.encode([n[2] for n in new])
                    for (cid,cachekey,_),vector in zip(new,vectors):
                        blob=vector.tobytes();self.cache.execute('insert or ignore into embeddings values (?,?)',(cachekey,blob));cached.append((cid,cachekey,blob))
                    self.cache.commit();state['embeddings_computed']+=len(new);state['last_run']['embeddings_computed']+=len(new)
                with db:db.executemany('insert into vectors values (?,?,?)',cached)
                state['phase']='EMBEDDING';state['vectors_done']=db.execute('select count(*) from vectors').fetchone()[0];atomic_json(statepath,state)
                if offset%256==0:print('EMBEDDED',state['vectors_done'],flush=True)
            counts=self.verify(db,snapshot)
            canonical_receipts={}
            for item in snapshot['sources']:
                if item['source']['declared_media_type']=='text/plain':
                    require(metadata[item['source_id']].get('internal_method_reference') is True,'TXT_METHOD_PROFILE_REQUIRED')
                    row=inputdb.execute('select * from acquisitions where id=?',(item['source_id'],)).fetchone()
                    require(row is not None and row['state']=='ACTIVE' and row['decision_hash']==item['decision_hash']
                            and json.loads(row['source'])==item['source'],'CANONICAL_INPUT_NOT_ACTIVE')
                    canonical_receipts[item['source_id']]={'kind':'TXT_RAW_LINES_V1','acquisition':dict(row)}
                    continue
                row=inputdb.execute('select * from pdf_extractions where acquisition_id=?',(item['source_id'],)).fetchone()
                require(row is not None and row['state']=='ACTIVE' and row['decision_hash']==item['decision_hash'],'CANONICAL_INPUT_NOT_ACTIVE')
                canonical_receipts[item['source_id']]=dict(row)
            db.close();db=None
            manifest={'version':'ARKS_HYBRID_INDEX_V1','generation_id':state['generation_id'],'input_snapshot':snapshot,'chunker':PARAMETERS,'embedding_model':self.model.manifest,'lexical_backend':LEXICAL_PROFILE+'_PERSISTED_POSTINGS','vector_backend':'SQLITE_FLOAT32_NUMPY_EXACT_COSINE','fusion_policy':{'method':'RRF','k':60,'branch_limit':100,'lexical_weight':1,'dense_weight':1,'reranking':'DISABLED'},'counts':counts,'index_sha256':file_sha(dbpath),'state':'VERIFIED','tests':{'structural_integrity':'PASS','provenance':'PASS'}}
            manifest['canonical_receipts']=canonical_receipts
            manifest['canonical_engine_files']={p.name:file_sha(p) for p in Path(__file__).parent.glob('doc*.py') if p.name!='doc_service.py'}
            engine,threads=index_execution_trace();manifest['index_engine_files']=engine  # C174 (P3-7)
            manifest['execution_bounds']={'embedding_batch':8,'cpu_threads':threads,'onnx_cpu_arena':False,'onnx_memory_pattern':False,'hashing':'STREAMING_SHA256'}
            if catalog['works']:manifest['documentary_versions']=catalog
            if expected_active is not None:require(read(self.root/'ACTIVE.json')==expected_active,'VERSION_ACTIVE_CONFLICT')
            atomic_json(folder/'MANIFEST.json',manifest);state['phase']='VERIFIED';atomic_json(statepath,state);return folder,manifest
        finally:
            if db:db.close()
            inputdb.close()
    def verify(self,db,snapshot):
        import numpy as np
        require(db.execute('pragma integrity_check').fetchone()[0]=='ok','INDEX_INTEGRITY_FAILURE')
        require(not db.execute('pragma foreign_key_check').fetchall(),'ORPHAN_CHUNK')
        units={r['id']:json.loads(r['object']) for r in db.execute('select * from evidence')};n=0
        for row in db.execute('select * from chunks'):
            c=json.loads(row['object']);verify_chunk(c,units);require(self.model.count('passage: '+c['retrieval_text'])<=480,'CHUNK_TOKEN_LIMIT');n+=1
        vectors=db.execute('select vector from vectors').fetchall();require(len(vectors)==n,'VECTOR_MISSING')
        for r in vectors:
            v=np.frombuffer(r[0],dtype='<f4');require(v.shape==(self.model.dimension,) and np.isfinite(v).all() and abs(float(np.linalg.norm(v))-1)<1e-4,'VECTOR_INVALID')
        states=dict(db.execute('select state,count(*) from evidence group by state').fetchall())
        require(set(states)<={'INDEXED_TEXT','NON_TEXT_ACCOUNTED','EMPTY_ACCOUNTED'} and len(units)==snapshot['evidence_count'],'UNACCOUNTED_EVIDENCE')
        require(db.execute('select count(distinct chunk_id) from postings').fetchone()[0]==n,'LEXICAL_MISSING')
        from .math_finance import selected,contract,bundle_chunks
        scientific=[json.loads(r[0]) for r in db.execute('select object from chunks') if selected(json.loads(r[0])['metadata'])]
        for key in {c['source_id'] for c in scientific}:
            group=[c for c in scientific if c['source_id']==key];spec=contract(group[0]['metadata'])
            require(len(group)==len(spec['records']) and
                    {c['scientific_object']['record']['BLOCK_ID'] for c in group}=={r['BLOCK_ID'] for r in spec['records']},'MF_INDEX_RECORD_MISSING')
            for c in group:bundle_chunks(c,group)
        return {'sources_accounted':db.execute('select count(*) from sources').fetchone()[0],'evidence_total':len(units),'evidence_indexed':states.get('INDEXED_TEXT',0),'evidence_non_text':states.get('NON_TEXT_ACCOUNTED',0),'evidence_empty':states.get('EMPTY_ACCOUNTED',0),'chunks':n,'lexical_entries':n,'vector_entries':n,'orphan_chunks':0,'unaccounted_evidence':0}

def read_object(text):return json.loads(text)

def publish_verified(root,folder,*,acceptance,fusion_policy=None,fresh_process=None):
    """Atomically publish an immutable generation; caller holds the ARKS writer."""
    root=Path(root);folder=Path(folder);m=read(folder/'MANIFEST.json')
    require(acceptance.get('status')=='PASS' and m['state'] in ('VERIFIED','ACCEPTED'),'GENERATION_NOT_ACCEPTED')
    require(folder.resolve()==(root/m['generation_id']).resolve(),'GENERATION_PATH')
    require(file_sha(folder/'index.sqlite3')==m['index_sha256'],'INDEX_CHANGED')
    from .source_versions import empty_catalog,validate_selection,validate_transition
    catalog=m.get('documentary_versions',empty_catalog())
    if catalog['works']:validate_selection(catalog,m['input_snapshot'])
    if (root/'ACTIVE.json').exists():
        prior=read(root/'ACTIVE.json');pm=read(root/prior['generation_id']/'MANIFEST.json')
        require(file_sha(root/prior['generation_id']/'MANIFEST.json')==prior['manifest_sha256'],'ACTIVE_INDEX_MANIFEST')
        if prior['generation_id']!=folder.name and (catalog['works'] or pm.get('documentary_versions',{}).get('works')):
            validate_transition(pm.get('documentary_versions',empty_catalog()),catalog,pm['input_snapshot'],m['input_snapshot'],rollback=bool(m.get('version_rollback')))
    for receipt in (acceptance,fresh_process):
        if receipt and 'receipt' in receipt:
            require(file_sha(receipt['receipt'])==receipt['sha256'] and read(receipt['receipt']).get('status')=='PASS','RELEASE_RECEIPT_INVALID')
    if (root/'ACTIVE.json').exists():require(read(root/'ACTIVE.json')['generation_id']<=folder.name,'INDEX_ACTIVATION_REGRESSION')
    seal={'version':'ARKS_IMMUTABLE_RELEASE_V1','generation_id':folder.name,'manifest_sha256':file_sha(folder/'MANIFEST.json'),'index_sha256':m['index_sha256'],'acceptance':acceptance,'fresh_process':fresh_process,'fusion_policy':fusion_policy or m['fusion_policy']}
    if catalog['works']:
        from .doc_checkpoint import utcnow
        seal.update(documentary_versions_sha256=fingerprint(catalog),published_utc=utcnow())
    raw=dumps(seal).encode();digest=sha256(raw);releases=root/'RELEASES';releases.mkdir(exist_ok=True);path=releases/(digest+'.json')
    if path.exists():require(path.read_bytes()==raw,'RELEASE_SEAL_CHANGED')
    else:atomic_bytes(path,raw,exclusive=True)
    atomic_json(root/'ACTIVE.json',{'generation_id':folder.name,'manifest_sha256':seal['manifest_sha256'],'release_seal':'RELEASES/'+path.name,'release_sha256':digest})

def activate(root,folder,*,acceptance,marker=A/'DOCUMENTAIRE_V1_WRITER.json',fusion_policy=None,fresh_process=None):
    with writer(marker,'ARKS_RAG_ACTIVATION',root):
        publish_verified(root,folder,acceptance=acceptance,fusion_policy=fusion_policy,fresh_process=fresh_process)


def _validation_query(function):
    @functools.wraps(function)
    def scoped(self,*args,**kwargs):
        with self._validation_scope():return function(self,*args,**kwargs)
    return scoped

class HybridRetrieval:
    """Public query(text, filters=None, limit=10). Internal storage is private."""
    def __init__(self,store,root=DEFAULT_ROOT,model=None,generation=None):
        self.store=store;self.root=Path(root);self.model=model or LocalEmbedding();self.generation=generation;self.loaded=None;self.db=None
        self._query_validations=ContextVar("arks_query_validations",default=None);self._prepare_deadline=None
    def _check_preparation(self):
        deadline=getattr(self,'_prepare_deadline',None)
        if deadline is not None and time.monotonic()>deadline:raise TimeoutError('INDEX_PREPARATION_TIMEOUT')
    def prepare(self,*,timeout=90.0):
        """Bounded local bootstrap on this run's Retrieval, never a search."""
        require(type(timeout) in (int,float) and 0<timeout<=90.0,'INDEX_PREPARATION_LIMIT')
        start=time.monotonic();self._prepare_deadline=start+timeout
        try:
            self._check_preparation();stage=time.monotonic();self._load()
            index_ms=(time.monotonic()-stage)*1000;self._check_preparation()
            stage=time.monotonic();self.model._ensure_session()
            embedding_ms=(time.monotonic()-stage)*1000;self._check_preparation()
            return dict(status='READY',index_prepare_duration_ms=index_ms,embedding_prepare_duration_ms=embedding_ms)
        finally:
            if self.db:self.db.set_progress_handler(None,0)
            self._prepare_deadline=None
    @contextmanager
    def _validation_scope(self):
        # A ContextVar per Retrieval also isolates concurrent callers. Nested
        # query() inside query_scientific() shares only that outer query's map.
        if self._query_validations.get() is not None:
            yield;return
        token=self._query_validations.set({})
        try:
            yield
            for key,identity in tuple(self._query_validations.get().items()):
                if self._validation_identity(key)!=identity:self._validate_source(key)
        finally:self._query_validations.reset(token)
    def _validation_identity(self,key):
        # Full content identities, not mtime-only trust. The existing source/
        # original readers recheck authorization and raw hash on every hit.
        cfg=self.store.config();source=self.store.source(key);raw=self.store.original(key)
        acquisition=self.store.db.execute('select * from acquisitions where id=?',(key,)).fetchone()
        require(acquisition is not None,'RETRIEVAL_EXTRACTION_CHANGED')
        evidence=[dict(row) for row in self.store.db.execute('select * from evidence where acquisition_id=? order by id',(key,))]
        return fingerprint(dict(source_id=key,source=source,original_sha256=sha256(raw),
            acquisition=dict(acquisition),configuration_sha256=fingerprint(cfg),
            decision_sha256=self.store.decision_hash(key,cfg),evidence=evidence,
            indexed_source=self.sources[key],receipt=self.manifest.get('canonical_receipts',{}).get(key),
            generation=self.loaded))
    def close(self):
        if self.db:self.db.close();self.db=None
    def _load(self):
        self._check_preparation()
        import numpy as np
        active=read(self.root/'ACTIVE.json') if self.generation is None else {'generation_id':self.generation}
        require(re.fullmatch(r'INDEX_GEN_\d{4}',active['generation_id']) is not None,'INDEX_GENERATION_ID')
        if active==self.loaded:
            if self.generation is None:
                require(file_sha(self.root/active['generation_id']/'MANIFEST.json')==active['manifest_sha256'],'ACTIVE_INDEX_MANIFEST')
                if 'release_seal' in active:require(file_sha(self.root/active['release_seal'])==active['release_sha256'],'RELEASE_SEAL_CHANGED')
            stat=(self.root/active['generation_id']/'index.sqlite3').stat()
            if (stat.st_size,stat.st_mtime_ns)!=self.index_stat:
                require(file_sha(self.root/active['generation_id']/'index.sqlite3')==self.manifest['index_sha256'],'INDEX_INTEGRITY_FAILURE')
            return
        folder=self.root/active['generation_id'];m=read(folder/'MANIFEST.json')
        from .source_versions import empty_catalog,validate_selection
        self.documentary_versions=m.get('documentary_versions',empty_catalog())
        validate_selection(self.documentary_versions,m['input_snapshot'])
        require(m['embedding_model']==self.model.manifest,'INDEX_EMBEDDING_MODEL_MISMATCH')
        from .store_relocation import verified_store_root
        require(verified_store_root(m,self.store,self.root)==self.store.root.resolve(),'INDEX_STORE_IDENTITY')
        self.fusion_policy=m['fusion_policy']
        if self.generation is None:
            require(sha256((folder/'MANIFEST.json').read_bytes())==active['manifest_sha256'],'ACTIVE_INDEX_MANIFEST')
            if 'release_seal' in active:
                require(re.fullmatch(r'RELEASES/[0-9a-f]{64}\.json',active['release_seal']) is not None,'RELEASE_SEAL_PATH')
                sealpath=self.root/active['release_seal'];require(file_sha(sealpath)==active['release_sha256'],'RELEASE_SEAL_CHANGED');seal=read(sealpath)
                require(seal['generation_id']==active['generation_id'] and seal['manifest_sha256']==active['manifest_sha256'] and seal['index_sha256']==m['index_sha256'] and seal['acceptance']['status']=='PASS','RELEASE_SEAL_IDENTITY')
                self.fusion_policy=seal['fusion_policy']
                if self.documentary_versions['works']:require(seal.get('documentary_versions_sha256')==fingerprint(self.documentary_versions),'VERSION_RELEASE_BINDING')
            else:require(m['state']=='ACCEPTED','ACTIVE_INDEX_MANIFEST')
        require(file_sha(folder/'index.sqlite3',check=self._check_preparation)==m['index_sha256'],'INDEX_INTEGRITY_FAILURE')
        stat=(folder/'index.sqlite3').stat();self.index_stat=(stat.st_size,stat.st_mtime_ns)
        self.close();self.db=sqlite3.connect((folder/'index.sqlite3').as_uri()+'?mode=ro',uri=True);self.db.row_factory=sqlite3.Row
        # Share read-only mapped pages with the OS instead of copying every large metadata page.
        self.db.execute('pragma mmap_size=2147418112')
        if self._prepare_deadline is not None:self.db.set_progress_handler(lambda:int(time.monotonic()>self._prepare_deadline),1000)
        if m['index_sha256']==READ_PROJECTION_INDEX_SHA and READ_PROJECTION_PATH.is_file():
            raw_projection=READ_PROJECTION_PATH.read_bytes()
            require(sha256(raw_projection)==READ_PROJECTION_SHA,'READ_PROJECTION_INTEGRITY')
            projection=json.loads(raw_projection);del raw_projection
            require(projection['schema']=='ARKS_INDEX_READ_PROJECTION_V1' and
                    projection['generation']==active['generation_id'] and
                    projection['index_sha256']==m['index_sha256'],'READ_PROJECTION_BINDING')
            self.chunks=projection['chunks'];self.ids=sorted(self.chunks)
            require(len(self.ids)==m['counts']['chunks'],'READ_PROJECTION_CHUNK_COUNT')
            self.chunks={key:self.chunks[key] for key in self.ids}
            for chunk in self.chunks.values():chunk['metadata']=projection['metadata'][chunk['source_id']]
        else:
            self.chunks={};metadata_ids={}
            # The sealed index repeats the same large source metadata in each
            # chunk. Project it out in SQLite; decode only the lowest-id copy per
            # source, exactly as before. All index/seal/source checks stay above.
            for row in self.db.execute("select id,json_remove(object,'$.metadata') as object from chunks"):
                self._check_preparation()
                c=json.loads(row['object']);key=c['source_id'];prior=metadata_ids.get(key)
                if prior is None or row['id']<prior:metadata_ids[key]=row['id']
                c['metadata']=None;self.chunks[row['id']]=c
            metadata_by_source={}
            for key,cid in metadata_ids.items():
                self._check_preparation()
                raw=self.db.execute('select object from chunks where id=?',(cid,)).fetchone()[0]
                metadata_by_source[key]=json.loads(raw)['metadata']
            self.ids=sorted(self.chunks)
            self.chunks={key:self.chunks[key] for key in self.ids}
            for c in self.chunks.values():c['metadata']=metadata_by_source[c['source_id']]
        blobs={r[0]:r[1] for r in self.db.execute('select chunk_id,vector from vectors')}
        self.matrix=np.vstack([np.frombuffer(blobs[k],dtype='<f4') for k in self.ids]) if self.ids else np.empty((0,self.model.dimension),dtype='<f4')
        self.sources={r[0]:json.loads(r[1]) for r in self.db.execute('select id,object from sources')};self.manifest=m;self.loaded=active
    def source_status(self,key):
        self._load();chunks=[c for c in self.chunks.values() if c['source_id']==key];item=self.sources.get(key)
        if not item:
            from .source_versions import binding
            version=binding(self.documentary_versions,key)
            if version:return {'status':'HISTORIQUE','chunks':0,'documentary_version':version}
            return {'status':'INGÉRÉ_NON_INDEXÉ','chunks':0}
        self.store.source(key);require(self.store.decision_hash(key,self.store.config())==item['decision_hash'],'INDEX_STALE_SOURCE')
        self._validate_source(key)
        return {'status':'PRÊT','chunks':len(chunks),'evidence':item['evidence_count'],'pages':item['coverage']['total_physical_pages'],'mode':item['coverage']['coverage'],'lexical_index':'OK','vector_index':'OK','name':chunks[0]['metadata']['original_name'] if chunks else key}
    def resolve_work(self,scientific_work_id):
        self._load()
        from .source_versions import binding
        work=self.documentary_versions['works'].get(scientific_work_id)
        require(work is not None,'VERSION_WORK_NOT_FOUND')
        key=work['ACTIVE_SOURCE_ID'];self.store.source(key);self._validate_source(key)
        return binding(self.documentary_versions,key)
    def content_qualification(self,chunk,evidence=()):
        from .math_finance import content_qualification
        return content_qualification(chunk,evidence)
    def _version_result(self,chunk):
        from .source_versions import binding
        version=binding(self.documentary_versions,chunk['source_id'])
        return chunk|{'documentary_version':version} if version else chunk
    @_validation_query
    def query(self,text,filters=None,limit=10,*,route='HYBRID_RRF',fusion=None):
        import numpy as np
        require(type(text) is str and 0<len(text)<=2048 and type(limit) is int and 1<=limit<=50,'QUERY_LIMIT')
        require(route in ('HYBRID_RRF','LEXICAL_ONLY','DENSE_ONLY'),'RETRIEVAL_ROUTE')
        self._load();filters={} if filters is None else filters;require(type(filters) is dict and not set(filters)-{'source_id','scientific_work_id','category','document_type','language','derivation_method'},'UNSUPPORTED_FILTER')
        require(all(isinstance(v,str) and len(v)<=128 for v in filters.values()),'FILTER_VALUE')
        cfg=self.store.config();access=self.store.policy(cfg)
        allowed={k for k,v in self.sources.items() if access.allows(k) and self.store.decision_hash(k,cfg)==v['decision_hash']}
        def matches(c):
            if c['source_id'] not in allowed:return False
            for key,value in filters.items():
                if key=='scientific_work_id':
                    work=self.documentary_versions['works'].get(value)
                    if not work or c['source_id']!=work['ACTIVE_SOURCE_ID']:return False
                    continue
                found=c.get(key,c['metadata'].get(key));found=found if isinstance(found,list) else [found]
                if value not in found:return False
            return True
        eligible={k for k,c in self.chunks.items() if matches(c)}
        policy=fusion or self.fusion_policy;prepared=retrieval_text(text)
        if policy.get('query_preparation')=='LOCAL_FR_EN' and filters.get('language') not in ('fr','FR','French','français'):
            from .rag_query_prepare import LocalQueryTranslation,is_french
            if is_french(prepared):
                if policy.get('query_translation_manifest_sha256'):
                    from .rag_query_prepare import ROOT as TRANSLATION_ROOT
                    require(file_sha(TRANSLATION_ROOT/'MANIFEST.json')==policy['query_translation_manifest_sha256'],'QUERY_TRANSLATION_MANIFEST_CHANGED')
                if not hasattr(self,'query_translator'):self.query_translator=LocalQueryTranslation()
                prepared=self.query_translator.translate(prepared)
        terms=lexical_query_terms(re.findall(r'\w+',prepared.casefold()));require(0<len(terms)<=128,'QUERY_TERMS_LIMIT')
        N=policy['branch_limit'];lex=[];dense=[]
        if eligible and route!='DENSE_ONLY':
            scores=collections.Counter()
            for term in terms:
                for cid,n in self.db.execute('select chunk_id,frequency from postings where term=?',(term,)):
                    if cid in eligible:scores[cid]+=1000+min(n,3)
            lex=self._unique_ranked(sorted(scores,key=lambda k:(-scores[k],k)),policy,N)
        if eligible and route!='LEXICAL_ONLY':
            v=self.model.encode([prepared],query=True)[0];scores=self.matrix@v
            dense=sorted((i for i,k in enumerate(self.ids) if k in eligible),key=lambda i:(-float(scores[i]),self.ids[i]));dense=self._unique_ranked([self.ids[i] for i in dense],policy,N)
        lr={k:i+1 for i,k in enumerate(lex)};dr={k:i+1 for i,k in enumerate(dense)}
        score=lambda k:policy['lexical_weight']/(policy['k']+lr[k]) if k in lr else 0
        combined={k:score(k)+(policy['dense_weight']/(policy['k']+dr[k]) if k in dr else 0) for k in set(lex)|set(dense)}
        ranked=sorted(combined,key=lambda k:(-combined[k],k));results=[];validated=set()
        for cid in ranked:
            c=self.chunks[cid]
            if any(self._duplicate(c,r,policy) for r in results):continue
            key=c['source_id']
            if key not in validated:
                self._validate_source(key);validated.add(key)
            units={sp['evidence_id']:json.loads(self.store.db.execute('select object from evidence where id=?',(sp['evidence_id'],)).fetchone()[0]) for sp in c['evidence_spans']};verify_chunk(c,units)
            results.append(self._version_result(c)|{'content_qualification':self.content_qualification(c,units.values()),'support_status':'CANDIDATE_NOT_SUFFICIENT_SUPPORT','fusion_score_or_rank':combined[cid],'fusion_rank':len(results)+1,'lexical_rank':lr.get(cid),'dense_rank':dr.get(cid),'retrieval_route':route,'provenance':'VERIFIED'})
            if len(results)>=limit:break
        require(fingerprint(cfg)==fingerprint(self.store.config()),'POLICY_CHANGED_DURING_QUERY')
        return {'query':text,'prepared_query':prepared,'generation_id':self.loaded['generation_id'],'route':route,'results':results,'state':'FOUND' if results else 'NOT_FOUND','support_status':'RANKED_CANDIDATES_NOT_AN_ANSWER' if results else 'NO_CANDIDATE','retrieval_basis':'DENSE_NEIGHBOURS_ONLY' if results and all(r['lexical_rank'] is None for r in results) else 'LEXICAL_MATCHES_OR_HYBRID_CANDIDATES','issues':[]}
    @_validation_query
    def query_scientific(self,text,filters=None,limit=10,*,route='HYBRID_RRF',fusion=None):
        """Canonical retrieval then complete, verified same-source bundles.

        Limit controls seeds. Expansion is explicit and never silently truncated.
        Existing query() behavior and results are unchanged.
        """
        from .math_finance import bundle_chunks
        cfg=self.store.config()
        result=self.query(text,filters,limit,route=route,fusion=fusion)
        expanded={};bundles=[]
        for seed in result['results']:
            parts=bundle_chunks(seed,self.chunks.values())
            for c in parts:
                self._validate_source(c['source_id'])
                units={sp['evidence_id']:json.loads(self.store.db.execute('select object from evidence where id=?',(sp['evidence_id'],)).fetchone()[0]) for sp in c['evidence_spans']}
                verify_chunk(c,units)
                expanded.setdefault(c['chunk_id'],self._version_result(c)|{'content_qualification':self.content_qualification(c,units.values()),'support_status':'CANDIDATE_NOT_SUFFICIENT_SUPPORT','provenance':'VERIFIED','bundle_seed_chunk_id':seed['chunk_id']})
            if 'scientific_object' in seed:
                bundles.append({'source_id':seed['source_id'],'scientific_object_id':seed['scientific_object']['record']['SCIENTIFIC_OBJECT_ID'],
                                'chunks':[c['chunk_id'] for c in parts]})
        require(fingerprint(cfg)==fingerprint(self.store.config()),'POLICY_CHANGED_DURING_QUERY')
        return result|{'seed_chunks':[c['chunk_id'] for c in result['results']],
                       'results':list(expanded.values()),'scientific_object_bundles':bundles}

    def _validate_source(self,key):
        cache=self._query_validations.get()
        receipt=self.manifest.get('canonical_receipts',{}).get(key)
        # Only the proven repeated TXT path is memoized. PDF validation and
        # its extraction/facsimile artifacts remain exactly as before.
        if cache is None or not isinstance(receipt,dict) or receipt.get('kind')!='TXT_RAW_LINES_V1':
            return self._validate_source_uncached(key)
        identity=self._validation_identity(key)
        if cache.get(key)==identity:return
        cache.pop(key,None)
        self._validate_source_uncached(key)
        require(self._validation_identity(key)==identity,'RETRIEVAL_VALIDATION_CHANGED_DURING_QUERY')
        cache[key]=identity
    def _validate_source_uncached(self,key):
        from . import doc_pdf_store
        item=self.sources[key];source=self.store.source(key)
        require(source['raw_sha256']==item['source_sha256'],'RETRIEVAL_SOURCE_CHANGED');self.store.original(key)
        receipt=self.manifest.get('canonical_receipts',{}).get(key)
        if source['declared_media_type']=='text/plain':
            current=native_method_text_input(self.store,key)
            require(current==item,'RETRIEVAL_EVIDENCE_CHANGED')
            row=self.store.db.execute('select * from acquisitions where id=?',(key,)).fetchone()
            require(receipt=={'kind':'TXT_RAW_LINES_V1','acquisition':dict(row)},'RETRIEVAL_EXTRACTION_CHANGED')
            return
        current_files={p.name:file_sha(p) for p in Path(__file__).parent.glob('doc*.py') if p.name!='doc_service.py'}
        if receipt is None or current_files!=self.manifest.get('canonical_engine_files'):
            # Full validation is in-process JSON/Evidence work, not a PDF worker.
            # Keep the bounded inference session for the next query. UploadQueue
            # still explicitly releases it before starting its isolated workers.
            doc_pdf_store.load_report(self.store,key);return
        row=self.store.db.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone()
        require(row is not None and dict(row)==receipt,'RETRIEVAL_EXTRACTION_CHANGED')
        path=doc_pdf_store.artifact_path(self.store,receipt['extraction_id']);require(file_sha(path)==receipt['artifact_sha256'],'PDF_EXTRACTION_FILE_CHANGED')
        units=[json.loads(r[0]) for r in self.store.db.execute('select object from evidence where acquisition_id=? order by id',(key,))]
        require(fingerprint(units)==item['evidence_identity'],'RETRIEVAL_EVIDENCE_CHANGED')
        if item['coverage']['coverage']=='COMPLETE_PHYSICAL_PAGES_WITH_SOURCE_FACSIMILES':
            report=read(path)
            for p in report['pages']:
                digest=p['reviewed_page']['content']['png_sha256'];require(file_sha(self.store.root/'extractions/reviewed/images'/f'{digest}.png')==digest,'PDF_FACSIMILE_IMAGE_FILE_HASH')
    @staticmethod
    def _duplicate(a,b,policy):
        if HybridRetrieval._overlap(a,b):return True
        if policy.get('deduplication')!='evidence' or a['source_id']!=b['source_id']:return False
        if {x['evidence_id'] for x in a['evidence_spans']}&{x['evidence_id'] for x in b['evidence_spans']}:return True
        # Equivalent normalized text, also when different Evidence carry the
        # same caption/header. Cross-source provenance is never collapsed.
        return a['retrieval_text']==b['retrieval_text']
    def _unique_ranked(self,ids,policy,limit):
        if policy.get('deduplication')!='evidence':return ids[:limit]
        kept=[]
        for cid in ids:
            if any(self._duplicate(self.chunks[cid],self.chunks[k],policy) for k in kept):continue
            kept.append(cid)
            if len(kept)>=limit:break
        return kept
    @staticmethod
    def _overlap(a,b):
        if a['source_id']!=b['source_id']:return False
        if a['exact_text_sha256']==b['exact_text_sha256']:return True
        for x in a['evidence_spans']:
            for y in b['evidence_spans']:
                if x['evidence_id']==y['evidence_id'] and max(0,min(x['end'],y['end'])-max(x['start'],y['start']))/min(x['end']-x['start'],y['end']-y['start'])>.75:return True
        return False
