"""One cooperating writer with an OS lock and the existing ARKS reservation."""
import json,os,contextlib,msvcrt
from pathlib import Path
from .doc_checkpoint import atomic_json
from .serialization import ContractError

@contextlib.contextmanager
def writer(marker,owner,run):
    marker=Path(marker);marker.parent.mkdir(parents=True,exist_ok=True)
    lock=marker.with_suffix('.guard');stream=lock.open('a+b')
    if lock.stat().st_size==0:stream.write(b'0');stream.flush()
    stream.seek(0)
    try:msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
    except OSError:stream.close();raise ContractError('WRITER_BUSY')
    claimed=False
    try:
        previous=json.loads(marker.read_bytes()) if marker.exists() else {'state':'RELEASED'}
        if previous.get('state') not in ('RELEASED','AVAILABLE','CLOSED') and previous.get('owner')!=owner:raise ContractError('WRITER_BUSY')
        # A matching owner can resume only after acquiring the OS guard. A live
        # instance retains it; a crash releases it without removing any file.
        atomic_json(marker,{'state':'COOPERATIVE_OWNER_RESERVATION','owner':owner,'run':str(run),'pid':os.getpid(),'mechanism':'OS_BYTE_LOCK_AND_ARKS_MARKER'});claimed=True
        yield
    finally:
        if claimed:
            current=json.loads(marker.read_bytes())
            if current.get('owner')==owner:atomic_json(marker,current|{'state':'RELEASED'})
        stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1);stream.close()
