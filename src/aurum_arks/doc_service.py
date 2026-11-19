"""Single-operator loopback UI with authenticated, bounded documentary uploads."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import html
import json
import secrets
import uuid
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, urlencode

from .serialization import ContractError
from .paths import reject_links
from . import doc_pdf
from . import ui_catalogue
from .catalogue_cache import CatalogueCache
from .result_titles import TitleProjection

def mode_label(value):
    if 'FACSIMILE' in value:return 'Fac-similé et légendes vérifiées ; recherche textuelle limitée'
    if 'UNINTERPRETED_GLYPH' in value:return 'Texte et glyphes conservés graphiquement'
    if 'OPAQUE' in value:return 'Texte natif ; objets joints non indexés'
    if 'COMPONENT' in value:return 'Texte avec éléments graphiques conservés'
    if 'NATIVE' in value or 'COMPLETE_PDF_TEXT' in value:return 'Texte du PDF ; mise en page non certifiée'
    return value


def make_server(store,port=0,render_root=None,*,retrieval=None,upload_queue=None):
    render_root=Path(render_root) if render_root is not None else doc_pdf.ARKS/'reports'
    reject_links(render_root)
    if not render_root.absolute().is_relative_to(doc_pdf.ARKS/'reports'):raise ContractError('PDF_WORK_DIRECTORY_SCOPE')
    render_root.mkdir(parents=True,exist_ok=True)
    login_secret=secrets.token_urlsafe(32)
    session=secrets.token_urlsafe(32)
    catalogue=CatalogueCache(store)

    class Handler(BaseHTTPRequestHandler):
        server_version='ARKSLocal/1'

        def log_message(self,*args):
            pass  # Queries, paths, tokens and source contents must not enter logs.

        def send(self,status,body,kind='text/html; charset=utf-8',cookie=None,download=None):
            data=body.encode('utf-8') if isinstance(body,str) else body
            self.send_response(status)
            self.send_header('Content-Type',kind)
            self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            # Preserve the origin on same-origin form POSTs; cross-origin
            # navigation still receives no referer. Null origins stay refused.
            self.send_header('Referrer-Policy','same-origin')
            self.send_header('Content-Security-Policy',"default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            if cookie: self.send_header('Set-Cookie',cookie)
            if download:self.send_header('Content-Disposition','attachment; filename="'+download+'"')
            self.end_headers(); self.wfile.write(data)

        def host_ok(self):
            return self.headers.get('Host')==f'127.0.0.1:{self.server.server_port}'

        def authenticated(self):
            cookies=dict(part.strip().split('=',1) for part in self.headers.get('Cookie','').split(';') if '=' in part)
            value=cookies.get('arks_session','')
            return secrets.compare_digest(value,session)

        def do_POST(self):
            origin=self.headers.get('Origin')
            expected=f'http://127.0.0.1:{self.server.server_port}'
            if not self.host_ok() or origin not in (None,expected):
                self.send(403,'Accès refusé'); return
            if self.path=='/documents/upload' and upload_queue is not None:
                if not self.authenticated() or origin!=expected:self.send(403,'Accès refusé');return
                try:
                    from email.parser import BytesParser
                    from email.policy import default
                    size=int(self.headers.get('Content-Length','0'))
                    if not 0<size<=100*1024**2+65536:self.send(413,'Lot trop volumineux');return
                    kind=self.headers.get('Content-Type','')
                    if not kind.startswith('multipart/form-data;'):raise ContractError('UPLOAD_MULTIPART_REQUIRED')
                    raw=self.rfile.read(size)
                    if len(raw)!=size:raise ContractError('UPLOAD_TRUNCATED')
                    message=BytesParser(policy=default).parsebytes(('Content-Type: '+kind+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+raw)
                    parts=list(message.iter_parts());files=[p for p in parts if p.get_filename() is not None]
                    token=next((p.get_payload(decode=True).decode() for p in parts if p.get_param('name',header='content-disposition')=='csrf'),'')
                    if not secrets.compare_digest(token,session) or not 1<=len(files)<=10:raise ContractError('UPLOAD_CSRF_OR_BATCH_LIMIT')
                    results=[]
                    for part in files:
                        try:results.append(upload_queue.submit(part.get_filename(),part.get_payload(decode=True)))
                        except (ContractError,ValueError,OSError):results.append({'state':'ÉCHEC LOCAL','detail':'Fichier refusé : nom, signature ou taille invalide.'})
                    body='<p><a href="/documents">Suivre les documents</a></p>'+''.join('<p>'+html.escape(r['state'])+'</p>' for r in results)
                    self.send(200,self.page(body));return
                except (ContractError,ValueError,OSError,UnicodeError):self.send(400,'Ajout refusé : fichier ou requête invalide.');return
            if self.path!='/login': self.send(405,'Action non disponible'); return
            try: size=int(self.headers.get('Content-Length','0'))
            except ValueError: self.send(400,'Requête invalide'); return
            if not 0<size<=1024: self.send(413,'Requête trop grande'); return
            values=parse_qs(self.rfile.read(size).decode('utf-8',errors='replace'),max_num_fields=3)
            if not secrets.compare_digest(values.get('code',[''])[0],login_secret):
                self.send(403,'Code de session incorrect'); return
            self.send(200,self.page('<p>Session ouverte. <a href="/">Accéder au catalogue</a></p>'),
                      cookie=f'arks_session={session}; HttpOnly; SameSite=Strict; Path=/')

        def page(self,body):
            return ui_catalogue.page(body)

        def do_GET(self):
            if not self.host_ok(): self.send(403,'Accès refusé'); return
            if len(self.path)>2048: self.send(414,'Requête trop longue'); return
            if not self.authenticated():
                self.send(401,self.page('<h2>Session opérateur</h2><form method="post" action="/login">'
                    '<label>Code affiché dans le terminal <input name="code" type="password" autocomplete="off"></label>'
                    '<button>Ouvrir la session</button></form>')); return
            try:
                parts=urlsplit(self.path); args=parse_qs(parts.query,max_num_fields=8)
                if parts.path.startswith('/ui/'):
                    name=parts.path[4:]
                    if name not in ui_catalogue.ASSET_TYPES:self.send(404,'Ressource absente');return
                    self.send(200,(ui_catalogue.ASSETS/name).read_bytes(),ui_catalogue.ASSET_TYPES[name])
                elif parts.path=='/':
                    rows=ui_catalogue.metadata_view(store,catalogue.get())
                    self.send(200,self.page(ui_catalogue.catalogue_html(rows,upload_queue is not None,args.get('state',[''])[0],hybrid=retrieval is not None)))
                elif parts.path=='/documents' and upload_queue is not None:
                    body='<p><a href="/">Catalogue et recherche</a></p><h2>Ajouter des documents</h2><p>Les PDF restent locaux. Chaque ajout est contrôlé avant de devenir disponible.</p>'
                    for multiple,label in [(False,'Ajouter un PDF'),(True,'Ajouter plusieurs PDF')]:
                        body+='<form method="post" action="/documents/upload" enctype="multipart/form-data"><input type="hidden" name="csrf" value="'+session+'"><label>'+label+' <input aria-label="'+label+'" type="file" name="pdf" accept=".pdf,application/pdf" '+('multiple ' if multiple else '')+'required></label><button>'+label+'</button></form>'
                    body+='<h2>Suivi des ajouts</h2><p><a href="/documents">Actualiser le suivi</a></p><table><tr><th>Nom</th><th>Statut</th><th>Source</th><th>Information</th></tr>'
                    for job in upload_queue.status():
                        link='<a href="/source?'+urlencode({'id':job['source_id']})+'">'+html.escape(job['source_id'])+'</a>' if job['source_id'] and job['state'] in ('PRÊT','DOUBLON EXACT') else html.escape(job['source_id'] or ('Non attribué' if job['state']=='ÉCHEC LOCAL' else 'En cours'))
                        body+='<tr><td>'+html.escape(job['name'])+'</td><td>'+html.escape(job['state'])+'</td><td>'+link+'</td><td>'+html.escape(job['detail'])+'</td></tr>'
                    self.send(200,self.page(body+'</table>'))
                elif parts.path=='/documents/status.json' and upload_queue is not None:
                    self.send(200,json.dumps(upload_queue.status(),ensure_ascii=False),'application/json; charset=utf-8')
                elif parts.path=='/retrieval.json' and retrieval is not None:
                    allowed={'q','limit','source_id','category','document_type','language','derivation_method'}
                    if set(args)-allowed:raise ContractError('UNSUPPORTED_FILTER')
                    found=retrieval.query(args.get('q',[''])[0],{k:v[0] for k,v in args.items() if k not in ('q','limit')},int(args.get('limit',['10'])[0]))
                    self.send(200,json.dumps(found,ensure_ascii=False),'application/json; charset=utf-8')
                elif parts.path=='/candidates':
                    rows=[]
                    for item in store.candidate_inventory():
                        rows.append('<tr>'+''.join('<td>'+html.escape(str(item.get(k,'')))+'</td>' for k in
                            ('candidate_id','path','bytes','availability','hash_status','admission'))+'</tr>')
                    self.send(200,self.page('<p><a href="/">Catalogue admis</a></p><h2>Candidats — aucune admission implicite</h2>'
                        '<p>Noms réservés à cette consultation opérateur locale. Aucun classement sémantique réalisé.</p>'
                        '<table><tr><th>ID</th><th>Chemin local</th><th>Octets</th><th>Disponibilité</th><th>Hash</th><th>Admission</th></tr>'+''.join(rows)+'</table>'))
                elif parts.path in ('/search','/search.json'):
                    if retrieval is not None and (retrieval.root/'ACTIVE.json').exists() and parts.path=='/search':
                        if set(args)-{'q','source_id','category','document_type','language','derivation_method'}:raise ContractError('UNSUPPORTED_FILTER')
                        found=retrieval.query(args.get('q',[''])[0],{k:v[0] for k,v in args.items() if k!='q'})
                        titles=TitleProjection(store.config(),retrieval.sources)
                        body='<p><a href="/">Catalogue</a> · <a href="/documents">Ajouter des PDF</a></p><h2>Résultats</h2><p>'+html.escape(found['query'])+'</p><p>Passages candidats : le rang indique un voisinage documentaire, pas un support suffisant ni une validation scientifique.</p>'
                        if not found['results']:body+='<p>Aucun passage disponible pour cette recherche.</p>'
                        for hit in found['results']:
                            hit=titles.for_result(hit)
                            if hit['page_refs']:
                                page=hit['page_refs'][0]['physical_page'];location='page '+str(page)
                                target={'id':hit['source_id'],'page':page}
                            elif hit.get('text_refs'):
                                ref=hit['text_refs'][0];location='lignes '+str(ref['start_line'])+'–'+str(ref['end_line'])+' · octets '+str(ref['start'])+'–'+str(ref['end'])
                                target={'id':hit['source_id']}
                            else:raise ContractError('RESULT_LOCATION_REQUIRED')
                            qualification=hit.get('content_qualification',{})
                            warning='<p role="note">'+html.escape(qualification['message'])+'</p>' if qualification.get('message') else ''
                            body+=warning
                            body+='<article><h3 class="result-title">'+html.escape(hit['display_title'])+'</h3><p>'+html.escape(hit['source_id'])+' · '+html.escape(location)+'</p><pre>'+html.escape(hit['exact_text'])+'</pre><p>Mode documentaire : '+html.escape(mode_label(hit['derivation_method']))+'</p><a href="'+html.escape('/source?'+urlencode(target),quote=True)+'">Vérifier dans la source</a><p>SHA source : '+hit['source_sha256']+'</p></article>'
                        self.send(200,self.page(body));return
                    if set(args)-{'q','limit','as_of'}:raise ContractError('UNSUPPORTED_SEARCH_FILTER')
                    found=store.search(args.get('q',[''])[0],limit=int(args.get('limit',['8'])[0]),as_of=args.get('as_of',[None])[0])
                    if parts.path=='/search.json':
                        self.send(200,json.dumps(found,ensure_ascii=False),'application/json; charset=utf-8');return
                    body='<p><a href="/">Catalogue</a></p><h2>'+html.escape(found['query'])+'</h2><p>'+html.escape(found['state'])+'</p>'
                    if found['issues']:body+='<p>Des sources restent indisponibles ou non courantes. Aucun passage de substitution.</p>'
                    for hit in found['results']:
                        ev=hit['evidence'];pdf=ev.get('physical_page') is not None
                        location=('page physique '+str(ev['physical_page'])+' · caractères ' if pdf else 'octets ')+str(ev['range'])
                        link='/source?'+urlencode({'id':ev['source_id'],**({'page':ev['physical_page']} if pdf else {})})
                        body+='<article><p>'+html.escape(ev['source_id']+' · '+ev['document_version']+' · '+location)+'</p>'
                        body+='<pre>'+html.escape(ev['content_exact'])+'</pre><p>Preuve '+html.escape(ev['evidence_id'])+' · SHA '+html.escape(ev['excerpt_sha256'])+'</p>'
                        body+='<a href="'+html.escape(link,quote=True)+'">Vérifier dans la source</a></article>'
                    self.send(200,self.page(body))
                elif parts.path=='/source':
                    key=args.get('id',[''])[0];source=store.source(key)
                    if source['declared_media_type']!='application/pdf':
                        self.send(200,store.original(key),'text/plain; charset=utf-8');return
                    item=next(x for x in catalogue.get() if x['source_id']==key)
                    body='<p><a href="/">Catalogue</a></p><h2>'+html.escape(key)+'</h2><p>SHA-256 '+html.escape(source['raw_sha256'])+'</p><p>'+html.escape(item['coverage'])+'</p>'
                    if retrieval is not None:
                        status=retrieval.source_status(key)
                        if 'mode' in status:status['mode']=mode_label(status['mode'])
                        labels={'name':'Nom','pages':'Pages','evidence':'Evidence','chunks':'Chunks','mode':'Mode documentaire','lexical_index':'Index lexical','vector_index':'Index vectoriel','status':'Statut'}
                        body+='<table>'+''.join('<tr><th>'+label+'</th><td>'+html.escape(str(status.get(field,'En attente')))+'</td></tr>' for field,label in labels.items())+'</table>'
                    if item['consultation']:
                        page=int(args.get('page',['1'])[0]);total=item['total_physical_pages']
                        if not 1<=page<=total:raise ContractError('PDF_RENDER_PAGE_SCOPE')
                        body+='<form action="/source"><input type="hidden" name="id" value="'+html.escape(key,quote=True)+'">'
                        body+='<label>Page physique <input type="number" name="page" min="1" max="'+str(total)+'" value="'+str(page)+'"></label><button>Afficher</button></form>'
                        body+='<p>Page '+str(page)+' sur '+str(total)+'. Rendu passif ; aucune action PDF exécutée. Image affichée ne signifie pas texte indexé.</p>'
                        body+='<img alt="Rendu passif de la page" src="'+html.escape('/render?'+urlencode({'id':key,'page':page}),quote=True)+'">'
                    else:body+='<p>Original conservé ; passages non consultables tant que la qualification technique n’a pas réussi.</p>'
                    body+='<p><a href="'+html.escape('/download?'+urlencode({'id':key}),quote=True)+'">Obtenir volontairement la copie binaire locale</a> — aucun lecteur externe n’est lancé automatiquement.</p>'
                    self.send(200,self.page(body))
                elif parts.path=='/render':
                    result=store.render(args.get('id',[''])[0],int(args.get('page',['0'])[0]),work_dir=render_root/('HTTP_RENDER_'+uuid.uuid4().hex))
                    self.send(200,Path(result['png_path']).read_bytes(),'image/png')
                elif parts.path=='/download':
                    key=args.get('id',[''])[0];source=store.source(key)
                    self.send(200,store.original(key),'application/octet-stream',download=key+('.pdf' if source['declared_media_type']=='application/pdf' else '.txt'))
                elif parts.path=='/evidence':
                    self.send(200,json.dumps(store.resolve(args.get('id',[''])[0]),ensure_ascii=False),'application/json; charset=utf-8')
                elif parts.path=='/catalogue.json':
                    self.send(200,json.dumps(store.catalogue()),'application/json')
                elif parts.path=='/status':
                    self.send(200,json.dumps(store.status()),'application/json')
                else: self.send(404,'Ressource absente')
            except (ContractError,ValueError,KeyError,OSError):
                self.send(403,'Opération refusée ou source indisponible')

    server=HTTPServer(('127.0.0.1',port),Handler)
    server.timeout=1
    # Limits a slow local client; this service is not a multi-user deployment.
    old_get=server.get_request
    def get_request():
        connection,address=old_get(); connection.settimeout(5); return connection,address
    server.get_request=get_request
    return server,login_secret
