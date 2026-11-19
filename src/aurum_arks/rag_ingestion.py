"""Persistent PDF upload queue, canonical ingestion, incremental generation."""
import json,re,sqlite3,time,threading,unicodedata,shutil
from pathlib import Path,PureWindowsPath
from .documentary import DocumentaryStore,MAX_POLICY_ACQUISITIONS,MAX_POLICY_BYTES
from .serialization import sha256,fingerprint,ContractError
from .provenance import require
from .paths import confined,reject_links
from .doc_checkpoint import atomic_json
from . import doc_pdf,doc_pdf_store
from .rag_writer import writer
from .rag_index import IndexBuilder,HybridRetrieval,activate,publish_verified,read,source_metadata,A,DEFAULT_ROOT,file_sha

STATES={'REÇU','HACHAGE','QUALIFICATION','INGESTION','DÉCOUPAGE','INDEXATION','INGÉRÉ_NON_INDEXÉ','PRÊT','DOUBLON EXACT','ÉCHEC LOCAL'}
MAX_TENTATIVES_INDEXATION=5  # C173 : valeur proposee par l'auditeur, a ajuster par le client

class UploadQueue:
    def __init__(self,store_root,policy_path,root=DEFAULT_ROOT,*,report_root=None,marker=None,synthetic=False,model=None):
        self.store_root=Path(store_root);self.policy_path=Path(policy_path);self.root=Path(root);reject_links(self.root);reject_links(self.policy_path);self.root.mkdir(parents=True,exist_ok=True)
        self.report_root=Path(report_root or A/'reports/RAG_UPLOADS');self.report_root.mkdir(parents=True,exist_ok=True)
        require(self.report_root.absolute().is_relative_to(A/'reports'),'PDF_WORK_DIRECTORY_SCOPE')
        self.marker=Path(marker or A/'DOCUMENTAIRE_V1_WRITER.json');self.synthetic=synthetic;self.stop_event=threading.Event();self.thread=None;self.model=model
        db=self.db();db.execute('CREATE TABLE IF NOT EXISTS uploads(sha TEXT PRIMARY KEY,name TEXT NOT NULL,state TEXT NOT NULL,source_id TEXT,detail TEXT NOT NULL,updated REAL NOT NULL,retry_after REAL NOT NULL DEFAULT 0)');db.commit();db.close()
    def db(self):
        db=sqlite3.connect(self.root/'uploads.sqlite3',timeout=30);db.row_factory=sqlite3.Row;return db
    def store(self):return DocumentaryStore(self.store_root,A/'schemas/v0.1',self.policy_path)
    def update(self,h,state,detail='',key=None,retry_after=0):
        require(state in STATES,'UPLOAD_STATE')
        with self.db() as db:db.execute('update uploads set state=?,detail=?,source_id=coalesce(?,source_id),updated=?,retry_after=? where sha=?',(state,detail,key,time.time(),retry_after,h))
    def submit(self,name,raw):
        require(type(name) is str and 0<len(name)<=240 and PureWindowsPath(name).name==name and '/' not in name and '\\' not in name and not PureWindowsPath(name).is_reserved() and not any(ord(c)<32 for c in name),'UPLOAD_FILENAME')
        require(not any(c in name for c in ':*?<>|"') and not name.endswith((' ','.')),'UPLOAD_FILENAME')
        require(name.lower().endswith('.pdf') and type(raw) is bytes and 0<len(raw)<=100*1024**2 and raw.startswith(b'%PDF-'),'UPLOAD_PDF_SIGNATURE_OR_SIZE')
        h=sha256(raw);db=self.db()
        try:
            prior=db.execute('select * from uploads where sha=?',(h,)).fetchone()
            if prior:return {'sha256':h,'state':'DOUBLON EXACT','source_id':prior['source_id'],'existing_state':prior['state']}
            cfg=read(self.policy_path);existing=next((k for k,v in cfg['acquisitions'].items() if v['expected_sha256']==h),None)
            state='DOUBLON EXACT' if existing else 'REÇU'
            folder=confined(self.root,'uploads/'+h);folder.mkdir(parents=True,exist_ok=True)
            path=confined(folder,'input.pdf')
            if not path.exists():
                with path.open('xb') as f:f.write(raw)
            else:require(sha256(path.read_bytes())==h,'UPLOAD_STAGE_CHANGED')
            db.execute('insert into uploads values (?,?,?,?,?,?,?)',(h,name,state,existing,'',time.time(),0));db.commit()
            atomic_json(folder/'RECEIPT.json',{'sha256':h,'name':name,'size':len(raw),'events':['REÇU','HACHAGE'],'authority':'Explicit local PDF upload under ARKS operator mandate; licence UNKNOWN; local storage and retrieval only.'})
            return {'sha256':h,'state':state,'source_id':existing}
        finally:db.close()
    def status(self):
        db=self.db()
        try:return [dict(r) for r in db.execute('select * from uploads order by updated desc')]
        finally:db.close()
    def submit_qualified(self,name,raw,qualification,freeze_path):
        """Trusted local batch entry; HTTP uploads cannot supply this authority.

        Freeze, qualification and canonical preflight must agree on exact bytes.
        Publication, IDs, admission and all downstream work remain process().
        """
        from .doc_pdf_scope import check_coverage
        freeze_path=Path(freeze_path).resolve();reject_links(freeze_path)
        require(freeze_path.is_relative_to(A/'reports'),'BATCH_FREEZE_SCOPE')
        frozen=read(freeze_path);h=sha256(raw)
        require(frozen.get('version')=='ARKS_CANDIDATE_FREEZE_V1' and frozen.get('operator_local_processing_permission')=='APPROVED_FOR_THIS_BATCH','BATCH_AUTHORITY')
        matches=[e for e in frozen['candidates'] if e['candidate_id']==qualification.get('candidate_id') and e['sha256']==h and e['size']==len(raw) and e['extension']=='.pdf']
        require(len(matches)==1 and Path(matches[0]['relative_path']).name==name,'BATCH_NOT_FROZEN')
        require(qualification.get('selection_status')=='OK' and qualification.get('source_sha256')==h,'BATCH_NOT_QUALIFIED')
        require(qualification.get('rights_and_exposure',{}).get('provider_submission') is False and qualification.get('rights_and_exposure',{}).get('redistribution') is False,'BATCH_EXTERNAL_RIGHTS')
        report_path=Path(qualification['preflight_reference']).resolve();reject_links(report_path)
        require(report_path.is_relative_to(freeze_path.parent) and file_sha(report_path)==qualification['preflight_sha256'],'BATCH_PREFLIGHT_IDENTITY')
        report=read(report_path);scope=report['extractor']['parameters']['selection']
        require(report['source_sha256']==h and report['source_id']==qualification['candidate_id'],'BATCH_PREFLIGHT_SOURCE')
        doc_pdf_store._identity(report);check_coverage(report,scope)
        from .math_finance import admission_check,selected
        admission_check(qualification,h)
        if selected(qualification):
            require(not scope['excluded_pages'] and scope['included_pages']==list(range(1,scope['total_physical_pages']+1)),'MF_INCOMPLETE_EXTRACTION')
        envelope={'version':'ARKS_QUALIFIED_UPLOAD_V1','freeze_path':str(freeze_path),'freeze_sha256':file_sha(freeze_path),'qualification':qualification,'scope':scope}
        with writer(self.marker,'ARKS_UPLOAD_PIPELINE',self.root):
            prior=next((j for j in self.status() if j['sha']==h),None)
            existing=any(d['expected_sha256']==h for d in read(self.policy_path)['acquisitions'].values())
            if not prior and not existing:
                stage=confined(self.root,'uploads/'+h);stage.mkdir(parents=True,exist_ok=True)
                target=stage/'BATCH_QUALIFICATION.json'
                if target.exists():require(read(target)==envelope,'BATCH_QUALIFICATION_CHANGED')
                else:atomic_json(target,envelope,exclusive=True)
            # Persist authority before making the job visible to a worker.
            return self.submit(name,raw)
    def start(self):
        if self.thread and self.thread.is_alive():return
        self.stop_event.clear();self.thread=threading.Thread(target=self._run,name='ARKS-document-queue',daemon=False);self.thread.start()
    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join()
    def _run(self):
        model=self.model
        while not self.stop_event.is_set():
            jobs=[j for j in self.status() if j['state'] not in ('PRÊT','DOUBLON EXACT','ÉCHEC LOCAL') and j['retry_after']<=time.time()]
            if not jobs:self.stop_event.wait(1);continue
            job=sorted(jobs,key=lambda j:(j['updated'],j['sha']))[0]
            try:
                with writer(self.marker,'ARKS_UPLOAD_PIPELINE',self.root):
                    if model is None:
                        from .rag_model import LocalEmbedding
                        model=LocalEmbedding();self.model=model
                    self.process(job,model)
            except ContractError as e:
                if str(e)=='WRITER_BUSY':self.stop_event.wait(2);continue
                self.fail(job,e)
            except Exception as e:self.fail(job,e)
    def fail(self,job,error):
        if str(error) in ('PDF_AVAILABLE_MEMORY_LIMIT','PDF_MEMORY_OBSERVATION_UNAVAILABLE'):
            if self.model:self.model.release_inference()
            self.update(job['sha'],'QUALIFICATION','Ressources temporairement occupées ; reprise automatique.',retry_after=time.time()+5);return
        s=self.store()
        try:
            key=next((j['source_id'] for j in self.status() if j['sha']==job['sha']),None)
            row=s.db.execute('select state from pdf_extractions where acquisition_id=?',(key,)).fetchone() if key else None
            ingested=row is not None and row[0]=='ACTIVE'
        finally:s.close()
        err=self.root/'uploads'/job['sha']/'ERROR.json'
        try:tentatives=int(read(err).get('tentatives',0))+1 if err.exists() else 1
        except Exception:tentatives=MAX_TENTATIVES_INDEXATION  # RT-057 (RT-4) : compteur illisible -> ferme par defaut, jamais remis a 1
        atomic_json(err,{'error_type':type(error).__name__,'code':str(error),'ingested':ingested,'tentatives':tentatives})
        if ingested and tentatives>=MAX_TENTATIVES_INDEXATION:
            self.update(job['sha'],'ÉCHEC LOCAL','Indexation abandonnée après '+str(tentatives)+' tentatives. Voir le diagnostic local.',retry_after=0);return
        self.update(job['sha'],'INGÉRÉ_NON_INDEXÉ' if ingested else 'ÉCHEC LOCAL','Indexation à reprendre automatiquement.' if ingested else 'Le PDF n’a pas passé les contrôles documentaires. Voir le diagnostic local.',retry_after=time.time()+10*2**min(tentatives-1,6) if ingested else 0)
    def process(self,job,model):
        model.release_inference()
        job=next(j for j in self.status() if j['sha']==job['sha'])
        h=job['sha'];stage=self.root/'uploads'/h;raw=(stage/'input.pdf').read_bytes();require(sha256(raw)==h,'UPLOAD_STAGE_CHANGED')
        if job['source_id'] and (self.root/'ACTIVE.json').exists():
            active=read(self.root/'ACTIVE.json');manifest=read(self.root/active['generation_id']/'MANIFEST.json')
            item=next((x for x in manifest['input_snapshot']['sources'] if x['source_id']==job['source_id']),None)
            if item is not None:
                require(item['source_sha256']==h,'SOURCE_ID_COLLISION')
                s=self.store();retrieval=HybridRetrieval(s,self.root,model)
                try:require(retrieval.source_status(job['source_id'])['status']=='PRÊT','INDEX_NOT_READY')
                finally:retrieval.close();s.close()
                self.update(h,'PRÊT',key=job['source_id']);return
        self.update(h,'QUALIFICATION');folder=self.report_root/h;folder.mkdir(exist_ok=True)
        metadata_file=folder/'identify/METADATA.json'
        if not metadata_file.exists():
            work=folder/'identify';work.mkdir(exist_ok=True)
            if not (work/'input.pdf').exists():(work/'input.pdf').write_bytes(raw)
            if (work/'RESULT.json').exists():raise ContractError('IDENTIFICATION_FAILED')
            bounds=doc_pdf._bounded_worker(doc_pdf.NATIVE_PYTHON,Path(__file__).with_name('rag_pdf_metadata_worker.py'),work,timeout_seconds=30,memory_mib=doc_pdf_store.passive_memory_request(),discard_output=False)
            atomic_json(work/'BOUNDS.json',bounds)
        identified=read(metadata_file);require(identified.get('status')=='IDENTIFIED','PDF_IDENTIFICATION_FAILED');n=identified['physical_pages'];require(0<n<=2048,'PDF_PAGE_LIMIT')
        cfg=read(self.policy_path);key=job['source_id']
        if key is None:
            ids=set(cfg['acquisitions'])|{p.name for p in (A/'curation').iterdir() if p.is_dir()}|{j['source_id'] for j in self.status() if j['source_id']}
            highest=max([int(re.match(r'ARKS_SRC_(\d+)',k)[1]) for k in ids if re.match(r'ARKS_SRC_(\d+)',k)]+[0]);key=f'ARKS_SRC_{highest+1:04d}'
            self.update(h,'QUALIFICATION',key=key)
        title=identified.get('metadata',{}).get('/Title') or 'UNKNOWN'
        q={'schema_version':'ARKS_DOCUMENT_QUALIFICATION_V2_BINARY','source_id':key,'source_sha256':h,'source_original_filename':job['name'],'title':title,'authors':['UNKNOWN'],'publication':{'source_type':'UNKNOWN','year':'UNKNOWN','doi':'UNKNOWN','publisher':'UNKNOWN'},'domains':['UNKNOWN'],'arks_roles':['MODEL_DOCUMENTATION'],'qualification_status':'QUALIFIED_FOR_LOCAL_OPERATOR_REFERENCE','documentary_decision':'ACCEPTED_BY_EXPLICIT_UPLOAD','physical_pages':n,'rights_and_exposure':{'license':'UNKNOWN','provider_submission':False,'redistribution':False},'critical_guardrails':['No scientific certification. Preserve exact source and extraction limitations.'],'evidence':{'metadata_reference':str(metadata_file),'metadata_is_embedded_claim_not_external_verification':True}}
        batch_file=stage/'BATCH_QUALIFICATION.json';batch=None
        if batch_file.exists():
            from .doc_pdf_scope import check_coverage
            batch=read(batch_file);bq=batch['qualification']
            require(file_sha(batch['freeze_path'])==batch['freeze_sha256'],'BATCH_FREEZE_CHANGED')
            require(bq['source_sha256']==h and bq['selection_status']=='OK' and bq['physical_pages']==n,'BATCH_QUALIFICATION_CHANGED')
            require(file_sha(bq['preflight_reference'])==bq['preflight_sha256'],'BATCH_PREFLIGHT_CHANGED')
            preflight=read(bq['preflight_reference']);doc_pdf_store._identity(preflight);check_coverage(preflight,batch['scope'])
            require(preflight['source_sha256']==h and preflight['source_id']==bq['candidate_id'],'BATCH_PREFLIGHT_SOURCE')
            q.update(bq);q.update(source_id=key,source_sha256=h,source_original_filename=job['name'])
        from .math_finance import admission_check
        admission_check(q,h)
        qpath=stage/'QUALIFICATION.json'
        if not qpath.exists():atomic_json(qpath,q)
        else:require(read(qpath)==q,'UPLOAD_QUALIFICATION_CHANGED')
        scope={'version':'ARKS_PDF_SCOPE_V2','source_id':key,'source_sha256':h,'total_physical_pages':n,'included_pages':list(range(1,n+1)),'excluded_pages':[],'decision_reference':str(stage/'RECEIPT.json'),'qualification_reference':str(qpath),'expected_document_warnings':[],'expected_page_sha256':{},'native_reader':'PDFMINER_DECLARED_GLYPHS_V4','blank_page_policy':'TWO_NATIVE_ZERO_AND_WHITE_RENDER'}
        if batch:
            scope=dict(batch['scope'],source_id=key,decision_reference=batch['freeze_path'],qualification_reference=str(qpath))
        require(key in cfg['acquisitions'] or len(cfg['acquisitions'])<MAX_POLICY_ACQUISITIONS,'POLICY_BATCH_LIMIT')
        destination=confined(Path(cfg['source_root']),'UNKNOWN_'+h[:24]+'.pdf')
        if not destination.exists():
            with destination.open('xb') as f:f.write(raw)
        require(sha256(destination.read_bytes())==h,'SOURCE_BYTES_CHANGED')
        if key not in cfg['acquisitions']:
            cfg['acquisitions'][key]={'approved':True,'candidate_id':key,'classification':'EXTERNAL_PUBLICATION','decision_reference':str(stage/'RECEIPT.json'),'derivation_authorized':False,'encoding':'NOT_APPLICABLE','expected_bytes':len(raw),'expected_sha256':h,'media_type':'application/pdf','parents':[],'pdf_profile':'ARKS_PDF_PASSIVE_V2','pdf_scope':scope,'relative_path':destination.name,'rights':{'consultation':True,'hash_local':True,'indexation':True,'provider_submission':False,'redistribution':False,'storage':True},'rights_basis':'EXPLICIT_LOCAL_OPERATOR_UPLOAD; LICENCE_UNKNOWN; NO_PROVIDER_NO_REDISTRIBUTION','synthetic':self.synthetic,'qualification_reference':str(qpath),'qualification_sha256':sha256(qpath.read_bytes())}
            if batch:
                cfg['acquisitions'][key].update(candidate_id=q['candidate_id'],decision_reference=batch['freeze_path']+'#'+q['candidate_id'],rights_basis='EXPLICIT_LOCAL_OPERATOR_FROZEN_BATCH; LICENCE_UNKNOWN; NO_PROVIDER_NO_REDISTRIBUTION')
            require(len(json.dumps(cfg,ensure_ascii=False,indent=2).encode('utf-8'))<=MAX_POLICY_BYTES,'CONFIG_SIZE_LIMIT')
            atomic_json(self.policy_path,cfg)
        require(cfg['acquisitions'][key]['expected_sha256']==h,'SOURCE_ID_COLLISION')
        s=self.store()
        try:
            self.update(h,'INGESTION',key=key);s.admit(key);s.extract(key,work_dir=folder/'extract')
            self.update(h,'DÉCOUPAGE');snapshot,meta=self.incremental_input(s,key)
            self.update(h,'INDEXATION');b=IndexBuilder(self.root,model)
            try:target,manifest=b.build(snapshot,s.root/'catalogue.sqlite3',meta)
            finally:b.close()
            # Already inside the shared writer; activate without nested lock.
            require(file_sha(target/'index.sqlite3')==manifest['index_sha256'],'INDEX_CHANGED')
            fusion_policy=None
            if (self.root/'ACTIVE.json').exists():
                previous=read(self.root/'ACTIVE.json')
                if 'release_seal' in previous:fusion_policy=read(self.root/previous['release_seal'])['fusion_policy']
            publish_verified(self.root,target,acceptance={'status':'PASS','scope':'Incremental canonical Evidence, chunk provenance, complete lexical/vector counts'},fusion_policy=fusion_policy)
            retrieval=HybridRetrieval(s,self.root,model)
            try:require(retrieval.source_status(key)['status']=='PRÊT','INDEX_NOT_READY')
            finally:retrieval.close()
            self.update(h,'PRÊT',key=key)
        finally:s.close()
    def incremental_input(self,s,key):
        cfg=s.config();sources=[];metadata={}
        if (self.root/'ACTIVE.json').exists():
            active=read(self.root/'ACTIVE.json');manifest=read(self.root/active['generation_id']/'MANIFEST.json');sources=manifest['input_snapshot']['sources'][:]
            from .source_versions import binding,empty_catalog
            version=binding(manifest.get('documentary_versions',empty_catalog()),key)
            require(version is None or version['VERSION_STATUS']=='ACTIVE','VERSION_HISTORICAL_REQUIRES_CANONICAL_ROLLBACK')
            db=sqlite3.connect(self.root/active['generation_id']/'index.sqlite3')
            for sid,obj in db.execute('select source_id,object from chunks group by source_id'):metadata[sid]=json.loads(obj)['metadata']
            db.close()
        if not any(x['source_id']==key for x in sources):
            source=s.source(key)
            if source['declared_media_type']=='text/plain':
                from .rag_index import native_method_text_input
                item=native_method_text_input(s,key)
            else:
                report,coverage=doc_pdf_store.load_report(s,key);units=[json.loads(r[0]) for r in s.db.execute('select object from evidence where acquisition_id=? order by id',(key,))]
                item={'source_id':key,'source_sha256':source['raw_sha256'],'document_version':source['document_version'],'consultable_status':True,'evidence_count':len(units),'source':source,'coverage':coverage,'decision_hash':s.decision_hash(key,cfg),'metadata':{},'evidence_identity':fingerprint(units)}
            sources.append(item);metadata[key]=source_metadata(item,cfg,s)
        return {'version':'RAG_INCREMENTAL_INPUT_V1','store_identity':{'root':str(s.root)},'sources':sorted(sources,key=lambda x:x['source_id']),'source_count':len(sources),'evidence_count':sum(x['evidence_count'] for x in sources)},metadata
