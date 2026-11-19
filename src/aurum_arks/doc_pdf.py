"""Optional PDF text adapter. No corpus discovery, admission, or pypdf import here.

Callers must already hold authorized immutable bytes. Outputs remain local in a
new report directory. This adapter does not grant document or exposure rights.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import time
import uuid

from .doc_checkpoint import atomic_json, atomic_bytes, utcnow
from .doc_job import OwnedJob, observe_process
from .paths import reject_links
from .serialization import ContractError, fingerprint, sha256, strict_loads

VERSION = 'ARKS_PDF_TEXT_V1_1'
LIBRARY_VERSION = '6.19.0'
ARKS = Path(__file__).resolve().parents[2]
DOC_PYTHON = Path(os.environ.get('ARKS_PDF_PYTHON', str(ARKS / '.venv_pdf/Scripts/python.exe')))
MAX_BYTES = 100 * 1024**2
MAX_OUTPUT = 8 * 1024**2
PASSIVE_MAX_OUTPUT = 64 * 1024**2
PASSIVE_PYTHON = Path(os.environ.get('ARKS_PASSIVE_PYTHON', str(ARKS / '.venv_pdf_passive/Scripts/python.exe')))
NATIVE_PYTHON = Path(os.environ.get('ARKS_NATIVE_PYTHON', str(ARKS / '.venv_pdf_native/Scripts/python.exe')))
TEXT_STATE = 'TEXT_EXTRACTED_UNREVIEWED'


def require(condition, code):
    if not condition:
        raise ContractError(code)


def _resume_created_process(process):
 """Resume only the one thread of our own newly CREATE_SUSPENDED process."""
 import ctypes as C
 from ctypes import wintypes as W
 k=C.WinDLL('kernel32',use_last_error=True)
 class THREADENTRY32(C.Structure):
  _fields_=[('size',W.DWORD),('usage',W.DWORD),('tid',W.DWORD),('pid',W.DWORD),('priority',W.LONG),('delta',W.LONG),('flags',W.DWORD)]
 k.CreateToolhelp32Snapshot.argtypes=[W.DWORD,W.DWORD];k.CreateToolhelp32Snapshot.restype=W.HANDLE
 for name in ('Thread32First','Thread32Next'):
  f=getattr(k,name);f.argtypes=[W.HANDLE,C.POINTER(THREADENTRY32)];f.restype=W.BOOL
 k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
 k.OpenThread.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenThread.restype=W.HANDLE
 k.ResumeThread.argtypes=[W.HANDLE];k.ResumeThread.restype=W.DWORD
 snap=k.CreateToolhelp32Snapshot(4,0)
 if snap==C.c_void_p(-1).value:raise RuntimeError('OWNED_THREAD_SNAPSHOT_FAILED')
 tids=[]
 try:
  e=THREADENTRY32();e.size=C.sizeof(e);ok=k.Thread32First(snap,C.byref(e))
  while ok:
   if e.pid==process.pid:tids.append(e.tid)
   e.size=C.sizeof(e);ok=k.Thread32Next(snap,C.byref(e))
 finally:k.CloseHandle(snap)
 if len(tids)!=1:raise RuntimeError('OWNED_SUSPENDED_THREAD_COUNT')
 h=k.OpenThread(2,False,tids[0])
 if not h:raise RuntimeError('OWNED_THREAD_OPEN_FAILED')
 try:
  if k.ResumeThread(h)!=1:raise RuntimeError('OWNED_THREAD_RESUME_FAILED')
 finally:k.CloseHandle(h)
 return tids[0]


def _bounded_worker(python, script, folder, *, timeout_seconds, memory_mib, discard_output=False, extended=False):
    """Private trusted-code runner, never populated from PDF text or actions."""
    require(type(extended) is bool, 'PDF_RESOURCE_PROFILE')
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= (600 if extended else 90), 'PDF_TIMEOUT_LIMIT')
    require(type(memory_mib) is int and 64 <= memory_mib <= (2048 if extended else 1024), 'PDF_MEMORY_LIMIT')
    output_limit=PASSIVE_MAX_OUTPUT if extended else MAX_OUTPUT
    if True:  # V3: the quarter-available bound applies to every PDF profile.
        import ctypes
        class Memory(ctypes.Structure):
            _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]
        mem=Memory();mem.length=ctypes.sizeof(mem)
        require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)) and memory_mib*1024**2<=mem.available//4,'PDF_AVAILABLE_MEMORY_LIMIT')
    folder = Path(folder)
    command = [str(python), '-I', '-B', str(script), str(folder)]
    launch = {'state':'INDETERMINEE','command':command,'started_utc':utcnow(),
              'timeout_seconds':timeout_seconds,'memory_mib':memory_mib,'output_limit_bytes':output_limit}
    atomic_json(folder/'LAUNCH.json', launch, exclusive=True)
    process = None; job = None; assigned = False; rc = None
    outcome = 'INDETERMINEE'; category = None; observed = None; actual = None; limits = None
    stage='CREATE_JOB'; error_details=None
    started = time.monotonic()
    try:
        stage='PREPARE_GATE'
        require(not any((folder/name).exists() for name in ('READY.json','READY.tmp','GATE.json')), 'PDF_WORKER_STALE_GATE')
        nonce=uuid.uuid4().hex
        atomic_json(folder/'GATE.json',{'version':'ARKS_PDF_READY_V2','nonce':nonce},exclusive=True)
        committed=folder/('READY_COMMITTED.'+nonce)
        job = OwnedJob(memory_mib); limits = job.observed
        stage='CREATE_LOGS'
        with (folder/'stdout.log').open('xb') as out, (folder/'stderr.log').open('xb') as err:
            stage='SPAWN'
            process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL if discard_output else out,
                                       stderr=subprocess.DEVNULL if discard_output else err,
                                       creationflags=subprocess.CREATE_NO_WINDOW | 0x4)  # CREATE_SUSPENDED
            stage='ASSIGN_ROOT'; job.assign(process); assigned = True
            stage='RESUME_OWNED_ROOT'; _resume_created_process(process)
            observed = observe_process(process.pid)
            stage='WRITE_PROCESS_PROOF'
            atomic_json(folder/'PROCESS.json', observed, exclusive=True)
            stage='WAIT_READY'
            ready_deadline=time.monotonic()+min(10,timeout_seconds)
            # READY can be visible while Windows still holds the rename handle.
            # The worker publishes completion only after os.replace returns.
            # Its nonce ties that completion to this launch, without retrying a
            # refused read or authorizing the parser before identity validation.
            while not committed.exists() and process.poll() is None and time.monotonic()<ready_deadline:
                time.sleep(0.01)
            require(committed.exists(), 'PDF_WORKER_GATE_NOT_READY')
            stage='READ_READY'; ready=strict_loads((folder/'READY.json').read_bytes())
            require(type(ready) is dict and set(ready)=={'version','nonce','pid'}
                    and ready['version']=='ARKS_PDF_READY_V2' and ready['nonce']==nonce, 'PDF_WORKER_GATE_IDENTITY')
            require(type(ready.get('pid')) is int and ready['pid']>0, 'PDF_WORKER_GATE_IDENTITY')
            # Windows venv python.exe may redirect into another process before
            # root assignment. Assign that known, still-gated interpreter too.
            stage='OBSERVE_ACTUAL'; actual=observe_process(ready['pid'])
            require(actual['state']=='RUNNING', 'PDF_WORKER_GATE_NOT_RUNNING')
            require(actual.get('creation_filetime') is not None and observed.get('creation_filetime') is not None
                    and actual['creation_filetime']>=observed['creation_filetime'], 'PDF_WORKER_GATE_IDENTITY')
            if ready['pid']!=process.pid:
                stage='ASSIGN_ACTUAL'
                handle=job.k.OpenProcess(0x100|0x1,False,ready['pid'])
                require(bool(handle), 'PDF_WORKER_OPEN_PROCESS_FAILED')
                try:
                    require(bool(job.k.AssignProcessToJobObject(job.handle,handle)), 'PDF_WORKER_JOB_ASSIGN_FAILED')
                finally: job.k.CloseHandle(handle)
            stage='WRITE_GATE_PROOF'; atomic_json(folder/'GATED_WORKER.json',actual,exclusive=True)
            # The worker cannot import the PDF parser or read the PDF before assignment.
            stage='OPEN_GATE'; process.stdin.write(b'RUN\n'); process.stdin.flush(); process.stdin.close()
            stage='WAIT_RESULT'
            deadline = started + timeout_seconds
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    outcome = 'TIMED_OUT'; job.terminate(); break
                if _observed_output_bytes(folder) > output_limit:
                    outcome = 'OUTPUT_LIMIT'; job.terminate(); break
                time.sleep(0.02)
            process.wait(timeout=3); rc = process.returncode
            if outcome == 'INDETERMINEE':
                outcome = 'COMPLETED' if rc == 0 else 'WORKER_ERROR'
            if _observed_output_bytes(folder) > output_limit:
                outcome = 'OUTPUT_LIMIT'
    except Exception as error:
        category = type(error).__name__; outcome = 'LAUNCH_OR_WAIT_ERROR'
        error_details={'stage':stage,'errno':getattr(error,'errno',None),'winerror':getattr(error,'winerror',None),
                       'code':str(error) if isinstance(error,ContractError) else None}
        if process and process.poll() is None:
            if job and assigned: job.terminate()
            else: process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: pass
    finally:
        if job: job.close()  # Also kills descendants after the direct worker exits.
        if process and process.stdin and not process.stdin.closed: process.stdin.close()
    def stopped_observation(known):
        if known is None: return None
        deadline=time.monotonic()+1
        while True:
            seen=observe_process(known['pid'])
            if seen.get('creation_filetime') and known.get('creation_filetime') and seen['creation_filetime']!=known['creation_filetime']:
                seen['state']='PID_REUSED_ORIGINAL_EXITED'
            if seen['state']!='RUNNING' or time.monotonic()>=deadline: return seen
            time.sleep(0.01)
    post=stopped_observation(observed)
    actual_post=stopped_observation(actual)
    if any(p and p['state'] not in ('EXITED','NOT_FOUND','PID_REUSED_ORIGINAL_EXITED') for p in (post,actual_post)):
        outcome='TERMINATION_UNCONFIRMED'
    result = {'state':outcome,'returncode':rc,'error_category':category,'error_details':error_details,'ended_utc':utcnow(),
              'duration_seconds':time.monotonic()-started,'launch_sha256':sha256((folder/'LAUNCH.json').read_bytes()),
              'job_limits':limits,'process':observed,'after_job_close':post,'gated_worker_after_job_close':actual_post,
              'logs':{name:sha256((folder/name).read_bytes()) for name in ('stdout.log','stderr.log') if (folder/name).exists()}}
    atomic_json(folder/'RESULT.json', result, exclusive=True)
    return result


def _observed_output_bytes(folder):
    """A transient result name may disappear during atomic publication.

    Stat once: exists-then-stat races the worker's tmp-to-json rename. Missing
    logs and permission failures remain errors. Completion and final JSON
    existence/size/provenance are still checked by extract_pdf after termination.
    """
    total=sum((folder/name).stat().st_size for name in ('stdout.log','stderr.log'))
    for name in ('worker-result.json','worker-result.tmp'):
        try:total+=(folder/name).stat().st_size
        except FileNotFoundError:pass
    return total


def extract_pdf(raw, *, source_id, expected_sha256, work_dir, timeout_seconds=30,
                memory_mib=256, max_pages=300, selection=None, structural_only=False, render_page=None, reviewed_pages=None, passive_object_proof=None):
    """Extract authorized bytes without opening a source path or executing actions.

Page text is unreviewed extraction, never a statement of semantic/layout quality.
The real-source admission and rights gate remains the caller's separate duty.
"""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'PDF_SOURCE_SIZE_LIMIT')
    require(type(source_id) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,95}',source_id), 'PDF_SOURCE_ID')
    require(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}',expected_sha256)
            and sha256(raw)==expected_sha256, 'PDF_SOURCE_HASH_MISMATCH')
    passive=type(selection) is dict and selection.get('version')=='ARKS_PDF_SCOPE_V2'
    require(type(structural_only) is bool and (not structural_only or passive),'PDF_STRUCTURAL_MODE_PROFILE')
    require(render_page is None or (structural_only and type(render_page) is int
            and 1<=render_page<=selection['total_physical_pages']),'PDF_RENDER_PAGE_SCOPE')
    require(type(max_pages) is int and 1 <= max_pages <= (2048 if passive else 300), 'PDF_PAGE_LIMIT')
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= (600 if passive else 90), 'PDF_TIMEOUT_LIMIT')
    require(type(memory_mib) is int and 64 <= memory_mib <= (2048 if passive else 1024), 'PDF_MEMORY_LIMIT')
    if selection is not None:
        from .doc_pdf_scope import validate_scope
        selection=validate_scope(selection,source_id,expected_sha256)
        require(max_pages>=selection['total_physical_pages'], 'PDF_SCOPE_PAGE_LIMIT')
    reviewed=passive and selection['native_reader']=='PDFMINER_REVIEWED_PAGES_V5'
    if passive and selection.get('passive_object_proof_sha256'):
        require(type(passive_object_proof) is dict and fingerprint(passive_object_proof)==selection['passive_object_proof_sha256'] and passive_object_proof.get('source_id')==source_id and passive_object_proof.get('source_sha256')==expected_sha256,'PDF_PASSIVE_OBJECT_PROOF_IDENTITY')
    else:require(passive_object_proof is None,'PDF_UNAUTHORIZED_PASSIVE_OBJECT_PROOF')
    require(reviewed or reviewed_pages is None,'PDF_UNAUTHORIZED_REVIEW_BUNDLE')
    if reviewed and not structural_only:
        from .doc_pdf_review import validate_bundle
        validate_bundle(reviewed_pages,selection)
    folder = Path(work_dir).absolute(); reject_links(folder)
    require(folder.is_relative_to(ARKS/'reports'), 'PDF_WORK_DIRECTORY_SCOPE')
    require(shutil.disk_usage(ARKS).free >= 2*1024**3 + len(raw) + MAX_OUTPUT, 'DISK_RESERVE_LIMIT')
    folder.mkdir(parents=False, exist_ok=False)
    worker = Path(__file__).with_name('doc_pdf_worker.py'); runtime=PASSIVE_PYTHON if passive else DOC_PYTHON
    if passive and selection['native_reader'] in ('PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):runtime=NATIVE_PYTHON
    reject_links(worker); reject_links(runtime)
    config = {'adapter':VERSION,'library':'pypdf','library_version':LIBRARY_VERSION,
              'adapter_sha256':sha256(Path(__file__).read_bytes()),'worker_sha256':sha256(worker.read_bytes()),
              'warnings_sha256':sha256(Path(__file__).with_name('doc_pdf_warnings.py').read_bytes()),
              'warning_policy':'ARKS_PDF_WARNINGS_V1_DOCUMENT_REVIEW_PAGE_GATE',
              'parameters':{'strict':True,'extraction_mode':'plain','orientations':[0,90,180,270],
                            'max_pages':max_pages,'max_page_characters':200000,'max_document_characters':1000000,
                            'max_content_bytes':8*1024**2,'normalization':'NONE','offset_unit':'UNICODE_CODEPOINT'}}
    if selection is not None:
        config['adapter']='ARKS_PDF_TEXT_SELECTED_V1'
        config['scope_sha256']=sha256(Path(__file__).with_name('doc_pdf_scope.py').read_bytes())
        config['parameters']['selection']=selection
    if passive:
        config['adapter']='ARKS_PDF_TEXT_SELECTED_V2'
        config['native_reader']=selection['native_reader']
        config['passive_reader_contract']='NO_FORMS_NO_ACTIONS_NO_V8_XFA_V2'
        config['runtime_executable_sha256']=sha256(runtime.read_bytes())
        config['pdfium_version']='5.13.0'
        if selection['native_reader'] in ('PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
            config['pdfminer_version']='20260107'
            config['parameters']['native_layout']='PDFMINER_DEFAULT_GEOMETRY_SOURCE_ORDER_TIEBREAK_V2'
            if selection['native_reader'] in ('PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
                config['declared_glyph_table_sha256']=sha256((NATIVE_PYTHON.parent.parent/'Lib/site-packages/pypdf/_codecs/adobe_glyphs.py').read_bytes())
            if reviewed:
                config['review_adapter_sha256']=sha256(Path(__file__).with_name('doc_pdf_review.py').read_bytes())
                if not structural_only:config['review_bundle_fingerprint']=fingerprint(reviewed_pages)
        config['parameters'].update(max_document_characters=32000000,max_output_bytes=PASSIVE_MAX_OUTPUT)
        config['parameters']['structural_only']=structural_only
        if render_page is not None:config['parameters']['render_page']=render_page
    request = {'source_id':source_id,'source_sha256':expected_sha256,'source_bytes':len(raw),'extractor':config}
    atomic_json(folder/'REQUEST.json', request, exclusive=True)
    atomic_bytes(folder/'input.pdf', raw, exclusive=True)
    if reviewed and not structural_only:atomic_json(folder/'REVIEWED_PAGES.private.json',reviewed_pages,exclusive=True)
    if passive_object_proof is not None:atomic_json(folder/'PASSIVE_OBJECT_PROOF.private.json',passive_object_proof,exclusive=True)
    bounds = _bounded_worker(runtime,worker,folder,timeout_seconds=timeout_seconds,memory_mib=memory_mib,
                             discard_output=selection is not None and not passive,extended=passive)
    if bounds['state'] != 'COMPLETED':
        return {'status':'FAILED','code':'PDF_'+bounds['state'],'source_id':source_id,
                'source_sha256':expected_sha256,'pages':[],'coverage':'UNKNOWN','bounds':bounds}
    output = folder/'worker-result.json'
    require(output.is_file() and output.stat().st_size <= (PASSIVE_MAX_OUTPUT if passive else MAX_OUTPUT), 'PDF_WORKER_RESULT_MISSING_OR_LARGE')
    report = strict_loads(output.read_bytes())
    require(report.get('source_id')==source_id and report.get('source_sha256')==expected_sha256
            and report.get('extractor')==config, 'PDF_WORKER_PROVENANCE_MISMATCH')
    require(report.get('extraction_id')==fingerprint({k:v for k,v in report.items() if k!='extraction_id'}), 'PDF_EXTRACTION_HASH_MISMATCH')
    report['bounds'] = bounds
    if passive:
        require(all((folder/name).stat().st_size==0 for name in ('stdout.log','stderr.log')), 'PDF_UNREVIEWED_NATIVE_OUTPUT')
    atomic_json(folder/'EXTRACTION.json', report, exclusive=True)
    return report


def _validated_body(extraction):
    body = {k:v for k,v in extraction.items() if k not in ('extraction_id','bounds')}
    require(extraction.get('extraction_id')==fingerprint(body), 'PDF_EXTRACTION_HASH_MISMATCH')
    return body


def locator(extraction, physical_page, start, end):
    _validated_body(extraction)
    require(type(physical_page) is int and type(start) is int and type(end) is int, 'PDF_LOCATOR_INTEGER_REQUIRED')
    pages = [p for p in extraction['pages'] if p['physical_page']==physical_page]
    require(len(pages)==1 and pages[0]['status']==TEXT_STATE, 'PDF_PAGE_NOT_EXTRACTED')
    page = pages[0]; text = page['text']
    require(0 <= start < end <= len(text), 'PDF_LOCATOR_BOUNDS')
    return {'source_id':extraction['source_id'],'source_sha256':extraction['source_sha256'],
            'extraction_id':extraction['extraction_id'],'physical_page':physical_page,
            'offset_unit':'UNICODE_CODEPOINT','start':start,'end':end,'page_text_sha256':page['text_sha256'],
            'excerpt_sha256':sha256(text[start:end].encode('utf-8'))}


def resolve_locator(extraction, reference, *, expected_source_id, expected_source_sha256):
    _validated_body(extraction)
    require(extraction['source_id']==expected_source_id and extraction['source_sha256']==expected_source_sha256,
            'PDF_EXPECTED_SOURCE_MISMATCH')
    generated = locator(extraction,reference.get('physical_page'),reference.get('start'),reference.get('end'))
    require(reference==generated, 'PDF_LOCATOR_PROVENANCE_MISMATCH')
    page = next(p for p in extraction['pages'] if p['physical_page']==reference['physical_page'])
    require(sha256(page['text'].encode('utf-8'))==page['text_sha256'], 'PDF_PAGE_TEXT_HASH_MISMATCH')
    return page['text'][reference['start']:reference['end']]
