"""Versioned checkpoints for the operator's campaign, never corpus authority."""
from contextlib import contextmanager
from copy import deepcopy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import uuid

from .paths import reject_links
from .serialization import ContractError, strict_loads


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode('utf-8')


def atomic_bytes(path, raw, *, exclusive=False, after_temp=None):
    """Validate and flush the new file before replacing an existing pointer.

    No promise of power-loss atomicity for an entire collection of files.
    The old checkpoint remains valid until os.replace succeeds.
    """
    path=Path(path); reject_links(path)
    if exclusive and path.exists(): raise ContractError('TARGET_ALREADY_EXISTS')
    temp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    with temp.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if temp.read_bytes()!=raw: raise ContractError('TEMP_READBACK_MISMATCH')
    if after_temp: after_temp(temp)
    if exclusive and path.exists(): raise ContractError('TARGET_ALREADY_EXISTS')
    os.replace(temp,path)


def atomic_json(path,value,**kwargs):
    raw=encoded(value)
    if strict_loads(raw)!=value: raise ContractError('CHECKPOINT_SERIALIZATION')
    atomic_bytes(path,raw,**kwargs)


def unpack(raw):
    data=strict_loads(raw)
    if data.get('format')=='ARKS_CHECKPOINT_ENVELOPE_V1':
        state=data['state']
        if digest(encoded(state))!=data['state_sha256']: raise ContractError('CHECKPOINT_HASH_MISMATCH')
    elif data.get('checkpoint_version')=='ARKS_CHECKPOINT_V1' and data.get('sequence',99)<=3:
        state=data  # The initial bootstrap is retained as such, without invented checksum.
    else: raise ContractError('CHECKPOINT_FORMAT')
    required=('owner','campaign','sequence','budgets','next_action','operations')
    if not all(k in state for k in required): raise ContractError('CHECKPOINT_FIELDS')
    return state


class Checkpoints:
    def __init__(self,run,owner):
        self.run=Path(run).absolute(); reject_links(self.run)
        self.owner=owner
        self.path=self.run/'CHECKPOINT.json'
        self.history=self.run/'checkpoints'; self.history.mkdir(exist_ok=True)

    @contextmanager
    def mutex(self):
        import msvcrt
        path=self.run/'.checkpoint-mutex'; reject_links(path)
        with path.open('a+b') as stream:
            if stream.tell()==0: stream.write(b'0'); stream.flush()
            stream.seek(0)
            try: msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            except OSError: raise ContractError('CHECKPOINT_WRITER_BUSY') from None
            try: yield
            finally:
                stream.seek(0); msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)

    def load(self):
        candidates=[self.path,self.run/'CHECKPOINT.previous.json']
        candidates+=sorted(self.history.glob('*.json'),reverse=True)
        errors=[]
        for path in candidates:
            if not path.is_file(): continue
            reject_links(path)
            try:
                raw=path.read_bytes(); state=unpack(raw)
                if state['owner']!=self.owner or Path(state['campaign'])!=self.run:
                    raise ContractError('CHECKPOINT_OWNER_OR_CAMPAIGN')
                return deepcopy(state),{'loaded_from':str(path),'fallback_used':path!=self.path,
                                        'file_sha256':digest(raw),'invalid_candidates':errors}
            except (ContractError,ValueError,KeyError,TypeError):
                errors.append(str(path))
        raise ContractError('NO_VALID_CHECKPOINT')

    def _commit(self,state,previous,*,after_temp=None):
        if state['owner']!=self.owner: raise ContractError('CHECKPOINT_OWNER')
        seq=state['sequence']
        if self.path.exists():
            current_raw=self.path.read_bytes()
            try: unpack(current_raw)
            except (ContractError,ValueError,KeyError,TypeError):
                atomic_bytes(self.history/('invalid-current-'+uuid.uuid4().hex+'.bin'),current_raw,exclusive=True)
        if previous is not None:
            archive=self.history/(f'{previous["sequence"]:06d}-'+uuid.uuid4().hex+'.json')
            old=encoded({'format':'ARKS_CHECKPOINT_ENVELOPE_V1','state':previous,'state_sha256':digest(encoded(previous))})
            atomic_bytes(archive,old,exclusive=True)
            atomic_bytes(self.run/'CHECKPOINT.previous.json',old)
        state['checkpoint_version']='ARKS_CHECKPOINT_V2'
        envelope={'format':'ARKS_CHECKPOINT_ENVELOPE_V1','state':state,'state_sha256':digest(encoded(state))}
        raw=encoded(envelope)
        if unpack(raw)!=state: raise ContractError('CHECKPOINT_READBACK')
        atomic_bytes(self.path,raw,after_temp=after_temp)
        if unpack(self.path.read_bytes())['sequence']!=seq: raise ContractError('CHECKPOINT_PROMOTION_MISMATCH')

    def initialize(self,state):
        if self.path.exists(): raise ContractError('CHECKPOINT_EXISTS')
        with self.mutex(): self._commit(deepcopy(state),None)

    def update(self,mutator=None,*,next_action=None,last_verified=None,mode=None,after_temp=None,now=None):
        with self.mutex():
            old,origin=self.load(); new=deepcopy(old)
            timestamp=now or utcnow()
            start=new.get('budget_accounted_utc',new['started_utc'])
            elapsed=max(0,(dt.datetime.fromisoformat(timestamp)-dt.datetime.fromisoformat(start)).total_seconds())
            budget=new['budgets']; previous_mode=new.get('clock_mode','ACTIVE')
            field='continuation_active_seconds' if previous_mode=='ACTIVE' else 'operator_wait_seconds' if previous_mode=='WAITING_OPERATOR' else 'paused_seconds'
            budget[field]=round(budget.get(field,0)+elapsed,3)
            budget['remaining_active_seconds']=max(0,round(budget['limit_active_seconds']-budget['prior_active_seconds']-budget.get('continuation_active_seconds',0)-budget.get('conservative_gap_debit_seconds',0),3))
            new.update(sequence=old['sequence']+1,updated_utc=timestamp,budget_accounted_utc=timestamp,
                       clock_mode=mode or previous_mode)
            if origin['fallback_used']: new['recovery_from']=origin
            if mutator: mutator(new)
            if next_action is not None: new['next_action']=next_action
            if last_verified is not None: new['last_verified_step']=last_verified
            self._commit(new,old,after_temp=after_temp)
        return new

    def reconcile_gap(self,now=None):
        """Use after an unexpected session loss. Unobserved active gap stays explicit.

        Conservatively debit that gap until operator accounting can resolve it;
        do not pretend it was observed active work or reset prior consumption.
        """
        timestamp=now or utcnow()
        def change(state):
            state.setdefault('recovery_notes',[]).append('Unexpected active gap requires accounting review; no operation outcome inferred.')
        old,_=self.load()
        if old.get('clock_mode','ACTIVE')=='ACTIVE':
            gap=round(max(0,(dt.datetime.fromisoformat(timestamp)-dt.datetime.fromisoformat(old.get('budget_accounted_utc',old['started_utc']))).total_seconds()),3)
            def debit(state):
                change(state)
                state['budgets']['unobserved_gap_seconds']=state['budgets'].get('unobserved_gap_seconds',0)+gap
                state['budgets']['continuation_active_seconds']=max(0,round(state['budgets']['continuation_active_seconds']-gap,3))
                state['budgets']['conservative_gap_debit_seconds']=state['budgets'].get('conservative_gap_debit_seconds',0)+gap
                state['budgets']['remaining_active_seconds']=max(0,state['budgets']['limit_active_seconds']-state['budgets']['prior_active_seconds']-state['budgets']['continuation_active_seconds']-state['budgets']['conservative_gap_debit_seconds'])
            return self.update(debit,now=timestamp,mode='PAUSED')
        return self.update(change,now=timestamp,mode='PAUSED')

    def publish_resume(self,root_pointer=None):
        state,origin=self.load()
        text=('# Point de reprise ARKS documentaire V2.1\n\n'
              'Maître actif : '+state['master']['path']+'\n\n'
              'Campagne : '+str(self.run)+'\n\n'
              'Checkpoint : '+str(self.path)+'\n\n'
              'Dernière étape vérifiée : '+state['last_verified_step']+'\n\n'
              'Prochaine action : '+state['next_action']+'\n\n'
              'État : '+state['state']+' ; séquence '+str(state['sequence'])+'.\n\n'
              'Budget : '+str(state['budgets']['prior_active_seconds'])+' s antérieures + '
              +str(state['budgets']['continuation_active_seconds'])+' s actives de continuation ; '
              +str(state['budgets']['operator_wait_seconds'])+' s d’attente opérateur. Budget applicatif : 0 EUR.\n\n'
              'Relire le dernier checkpoint valide et ses opérations. Un lancement sans résultat final '
              'vérifié reste INDETERMINEE. Ne pas relancer une installation/import sur ce seul constat.\n'
              'Aucune reprise automatique, aucun solde de crédits supposé.\n')
        atomic_bytes(self.run/'REPRISE.md',text.encode('utf-8'))
        if root_pointer:
            pointer=Path(root_pointer); reject_links(pointer)
            if pointer.exists():
                previous=pointer.read_bytes()
                if str(self.run) not in previous.decode('utf-8'): raise ContractError('RESUME_POINTER_OTHER_CAMPAIGN')
                dest=self.history/(f'pointer-{state["sequence"]:06d}-'+uuid.uuid4().hex+'.md')
                atomic_bytes(dest,previous,exclusive=True)
            atomic_bytes(pointer,text.encode('utf-8'))
        return origin
