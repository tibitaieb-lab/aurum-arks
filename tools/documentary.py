"""Operator entrypoint. No implicit corpus scan or admission on startup."""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode=True
ARKS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ARKS/'src'))
from aurum_arks.documentary import DocumentaryStore
from aurum_arks.doc_service import make_server
from aurum_arks.serialization import ContractError


def main():
    parser=argparse.ArgumentParser(description='ARKS documentaire local — TXT/PDF ; serve : recherche hybride (lexicale + dense ONNX locale, traduction FR→EN locale) ; search : recherche lexicale ; aucune génération IA')
    parser.add_argument('--data',type=Path,default=ARKS/'data/documentary_v1')
    parser.add_argument('--config',type=Path,default=ARKS/'runtime/documentary_v1/POLICY.json')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('status'); sub.add_parser('catalogue')
    for name in ('admit','extract'):
        cmd=sub.add_parser(name); cmd.add_argument('source_id')
    cmd=sub.add_parser('search'); cmd.add_argument('query'); cmd.add_argument('--as-of')
    cmd=sub.add_parser('resolve'); cmd.add_argument('evidence_id')
    cmd=sub.add_parser('render'); cmd.add_argument('source_id'); cmd.add_argument('physical_page',type=int); cmd.add_argument('--work-dir',type=Path)
    cmd=sub.add_parser('serve'); cmd.add_argument('--port',type=int,default=0); cmd.add_argument('--render-root',type=Path); cmd.add_argument('--hybrid',action='store_true',help='Exige des modèles et un index locaux configurés')
    cmd=sub.add_parser('backup'); cmd.add_argument('destination',type=Path)
    args=parser.parse_args()
    store=None
    try:
        store=DocumentaryStore(args.data,ARKS/'schemas/v0.1',args.config)
        if args.command=='serve':
            retrieval=queue=None
            if args.hybrid:
                from aurum_arks.rag_index import HybridRetrieval,DEFAULT_ROOT
                from aurum_arks.rag_ingestion import UploadQueue
                production=args.data.resolve()==(ARKS/'data/documentary_v1').resolve()
                rag_root=DEFAULT_ROOT if production else args.data.parent/(args.data.name+'_rag')
                retrieval=HybridRetrieval(store,rag_root)
                queue=UploadQueue(args.data,args.config,rag_root,model=retrieval.model,marker=None if production else rag_root/'WRITER.json');queue.start()
            server,code=make_server(store,args.port,args.render_root,retrieval=retrieval,upload_queue=queue)
            print(f'Adresse locale : http://127.0.0.1:{server.server_port}',flush=True)
            print(f'Code de session (local, à ne pas partager) : {code}',flush=True)
            print('Arrêt : Ctrl+C. Aucun appel fournisseur.',flush=True)
            try: server.serve_forever(poll_interval=.3)
            except KeyboardInterrupt: pass
            finally:
                server.server_close()
                if queue: queue.stop()
                if retrieval: retrieval.close()
            return 0
        if args.command=='status':
            result=store.status()
        elif args.command=='catalogue': result=store.catalogue()
        elif args.command=='admit':
            source=store.admit(args.source_id); result={'source_id':source['source_id'],'state':'ACTIVE'}
        elif args.command=='extract': result=store.extract(args.source_id)
        elif args.command=='search': result=store.pack(args.query,args.as_of)
        elif args.command=='resolve': result=store.resolve(args.evidence_id)
        elif args.command=='render': result=store.render(args.source_id,args.physical_page,work_dir=args.work_dir)
        else: result=store.backup(args.destination)
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except (ContractError,OSError):
        print(json.dumps({'state':'REFUSED','detail':'Voir politique, disponibilité et couverture TXT/PDF. Aucun contenu affiché.'})); return 2
    finally:
        if store: store.close()


if __name__=='__main__': raise SystemExit(main())
