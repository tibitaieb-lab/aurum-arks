"""Metadata only. Names stay in the operator artifact, never in the summary."""
import html
import os
from pathlib import Path
import stat
import uuid

from .paths import reject_links
from .serialization import ContractError

# Offline, recall on open/access, and reparse all require a separate decision.
UNSAFE_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000 | 0x400


def local_regular(path):
    path = Path(path)
    reject_links(path)
    for part in (path, *path.parents):
        info = part.lstat()
        if getattr(info, 'st_file_attributes', 0) & UNSAFE_ATTRIBUTES:
            raise ContractError('LOCAL_AVAILABILITY_NOT_ESTABLISHED')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ContractError('REGULAR_FILE_REQUIRED')
    return info


def inventory(root, limit=10000):
    root = Path(root)
    reject_links(root)
    for part in (root, *root.parents):
        if getattr(part.lstat(), 'st_file_attributes', 0) & UNSAFE_ATTRIBUTES:
            raise ContractError('LOCAL_AVAILABILITY_NOT_ESTABLISHED')
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ContractError('INVENTORY_LIMIT')
    pending, entries, errors = [str(root)], [], []
    skipped, partial, visited = [], False, 0
    while pending and visited < limit:
        folder = pending.pop()
        try:
            with os.scandir(folder) as scan:
                for item in scan:
                    if visited >= limit:
                        pending.append(folder)
                        partial = True
                        break
                    identifier = 'c' + uuid.uuid4().hex
                    visited += 1
                    try:
                        info = item.stat(follow_symlinks=False)
                        attrs = getattr(info, 'st_file_attributes', 0)
                        unsafe = bool(attrs & UNSAFE_ATTRIBUTES) or item.is_symlink()
                        kind = 'DIRECTORY' if stat.S_ISDIR(info.st_mode) else 'FILE'
                        entries.append({'candidate_id':identifier,'path':item.path,
                            'kind':kind,'extension':Path(item.name).suffix.lower(),
                            'bytes':info.st_size,'mtime_ns':info.st_mtime_ns,
                            'identity':[info.st_dev,info.st_ino], 'attributes':attrs,
                            'availability':'RESERVED' if unsafe else 'LOCAL_METADATA_ONLY',
                            'hash_status':'HASH_NOT_COMPUTED_AUTHORIZATION_PENDING',
                            'sha256':None,'admission':'PENDING_REVIEW',
                            'reading_level':'METADATA_ONLY','rights':'UNKNOWN'})
                        if unsafe:
                            skipped.append(identifier)
                        elif kind == 'DIRECTORY':
                            pending.append(item.path)
                    except OSError:
                        errors.append({'candidate_id':identifier,'state':'METADATA_UNAVAILABLE'})
        except OSError:
            errors.append({'directory':folder,'state':'DIRECTORY_UNAVAILABLE'})
    complete = not pending and not errors and not skipped and not partial
    return {'inventory_version':'DOC_INVENTORY_V1','source_root':str(root),
            'entries':entries,'errors':errors,'reserved_ids':skipped,
            'resume_directories':pending,'resume_note':'Reconcile existing paths/IDs before any further traversal; no automatic restart.',
            'coverage':'COMPLETE_SCOPED' if complete else 'PARTIAL',
            'summary':{'entries':len(entries),'files':sum(x['kind']=='FILE' for x in entries),
                       'directories':sum(x['kind']=='DIRECTORY' for x in entries),
                       'pdf':sum(x['kind']=='FILE' and x['extension']=='.pdf' for x in entries),
                       'reserved':len(skipped),'errors':len(errors)}}


def operator_html(data):
    rows = ''.join('<tr>'+''.join('<td>'+html.escape(str(e[k]))+'</td>' for k in
                   ('candidate_id','path','extension','bytes','availability','hash_status'))+'</tr>'
                   for e in data['entries'])
    return ('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Inventaire opérateur ARKS</title>'
            '<style>body{font:15px system-ui;margin:2em}td,th{padding:.4em;border:1px solid #ccc}table{border-collapse:collapse}</style>'
            '<h1>Inventaire local — métadonnées seulement</h1><p>Aucune admission, exposition au modèle ou licence déduite. '
            'Choisir les IDs du pilote et déclarer les opérations permises. Les noms restent dans ce fichier local.</p>'
            '<table><tr><th>ID</th><th>Chemin opérateur</th><th>Extension</th><th>Octets</th><th>Disponibilité</th><th>Hash</th></tr>'+rows+'</table>')
