"""Public synthetic corpus, exact lexical retrieval, no private installation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from aurum_arks.documentary import DocumentaryStore
from aurum_arks.doc_service import make_server


def open_demo(work=None):
    work = Path(work or ROOT / 'data/public_demo').resolve()
    work.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'examples/observatoire.txt'
    raw = source.read_bytes()
    policy = {
        'version': 'DOC_POLICY_V1', 'enabled': True,
        'source_root': str(source.parent),
        'acquisitions': {'demo-luma': {
            'approved': True, 'decision_reference': 'PUBLIC_SYNTHETIC_DEMO',
            'candidate_id': 'demo-observatoire', 'relative_path': source.name,
            'expected_sha256': hashlib.sha256(raw).hexdigest(), 'expected_bytes': len(raw),
            'classification': 'EXTERNAL_PUBLICATION', 'synthetic': True,
            'media_type': 'text/plain', 'encoding': 'UTF-8', 'parents': [],
            'derivation_authorized': False, 'rights_basis': 'Fiction written for this demo',
            'rights': {'hash_local': True, 'storage': True, 'consultation': True,
                       'indexation': True, 'provider_submission': False, 'redistribution': False}
        }}
    }
    config = work / 'POLICY.json'
    config.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding='utf-8')
    store = DocumentaryStore(work / 'vault', ROOT / 'schemas/v0.1', config)
    try:
        store.admit('demo-luma')
        store.extract('demo-luma')
        return store
    except BaseException:
        store.close()
        raise


def main():
    parser = argparse.ArgumentParser(description='ARKS — démonstration publique fictive (recherche lexicale)')
    parser.add_argument('command', choices=['serve', 'search', 'status'], nargs='?', default='serve')
    parser.add_argument('query', nargs='?', default='luminosité')
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    store = open_demo()
    try:
        if args.command == 'serve':
            server, code = make_server(store, args.port)
            print(f'Adresse locale : http://127.0.0.1:{server.server_port}', flush=True)
            print(f'Code de session : {code}', flush=True)
            print('Exemple fictif · recherche lexicale · arrêt : Ctrl+C', flush=True)
            try:
                server.serve_forever(poll_interval=.3)
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        else:
            result = store.search(args.query) if args.command == 'search' else store.status()
            print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        store.close()


if __name__ == '__main__':
    main()
