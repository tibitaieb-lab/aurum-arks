"""Verified machine relocation; historical store identity and seals stay intact."""
import hashlib
import json
from pathlib import Path
from .paths import confined, reject_links
from .provenance import require
from .serialization import fingerprint

ARKS = Path(__file__).resolve().parents[2]
POINTER = ARKS / 'runtime/documentary_v1/STORE_RELOCATION.json'

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def receipt():
    pointer = json.loads(POINTER.read_bytes())
    require(set(pointer) == {'schema', 'receipt', 'sha256'} and
            pointer['schema'] == 'ARKS_STORE_RELOCATION_POINTER_V1', 'STORE_RELOCATION_POINTER')
    path = confined(POINTER.parent, pointer['receipt'])
    require(sha(path) == pointer['sha256'], 'STORE_RELOCATION_RECEIPT_CHANGED')
    result = json.loads(path.read_bytes())
    require(result['schema'] == 'ARKS_VERIFIED_STORE_RELOCATION_V1' and
            result['status'] == 'PASS', 'STORE_RELOCATION_NOT_QUALIFIED')
    return result

def resolve_reference(value):
    path = Path(value)
    if not POINTER.is_file():
        return path
    binding = receipt()['reference_bindings'].get(str(path))
    if binding is None:
        return path
    target = Path(binding['path'])
    reject_links(target)
    require(target.resolve().is_relative_to(ARKS.resolve()) and target.is_file()
            and sha(target) == binding['sha256'], 'STORE_RELOCATION_REFERENCE_CHANGED')
    return target

def relocated_reference(value):
    """P3-401 (P3-7b) : reference absente sous l'ancienne racine ARKS (derivee du recu verifie) -> meme chemin relatif sous ARKS
    (confined). Pointeur absent, recu invalide, hors ancienne racine, chemin refuse, fichier absent : chemin inchange."""
    path = Path(value)
    if path.exists() or not POINTER.is_file():
        return path
    try:
        proof = receipt(); suffix = Path(proof['relocated_store_root']).relative_to(ARKS)
        original = Path(proof['original_store_root']); old_root = original.parents[len(suffix.parts) - 1]
        if not suffix.parts or old_root / suffix != original:
            return path
        target = confined(ARKS, path.relative_to(old_root).as_posix())
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return path
    return target if target.is_file() else path

def verified_store_root(manifest, store, index_root):
    declared = Path(manifest['input_snapshot']['store_identity']['root']).resolve()
    if declared == store.root.resolve():
        return declared
    proof = receipt()
    require(Path(proof['original_store_root']).resolve() == declared
            and Path(proof['relocated_store_root']).resolve() == store.root.resolve()
            and store.root.resolve() == (ARKS / 'data/documentary_v1').resolve()
            and Path(index_root).resolve() == (ARKS / 'data/rag_v1').resolve(), 'INDEX_STORE_IDENTITY')
    rag = Path(index_root)
    active = json.loads((rag / 'ACTIVE.json').read_bytes())
    require(active == proof['historical_active']
            and sha(rag / active['generation_id'] / 'MANIFEST.json') == active['manifest_sha256']
            and sha(rag / active['release_seal']) == active['release_sha256']
            and fingerprint(manifest['input_snapshot']) == proof['input_snapshot_sha256']
            and manifest['index_sha256'] == proof['index_sha256'], 'STORE_RELOCATION_INDEX_BINDING')
    require(sha(store.config_path) == proof['policy_sha256']
            and sha(store.root / 'catalogue.sqlite3') == proof['catalogue_sha256'], 'STORE_RELOCATION_CATALOGUE_CHANGED')
    for name, expected in proof['store_files'].items():
        path = confined(store.root, name)
        require(path.is_file() and sha(path) == expected, 'STORE_RELOCATION_CONTENT_CHANGED')
    return store.root.resolve()
