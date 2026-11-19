"""Bounded local identification; output is evidence, never operational authority."""
import json,os,sys,io,math
from pathlib import Path
p=Path(sys.argv[1]); gate=json.loads((p/'GATE.json').read_bytes())
with (p/'READY.tmp').open('x') as f: json.dump(dict(gate,pid=os.getpid()),f); f.flush();os.fsync(f.fileno())
os.replace(p/'READY.tmp',p/'READY.json')
(p/('READY_COMMITTED.'+gate['nonce'])).write_bytes(b'')
if sys.stdin.buffer.readline(8)!=b'RUN\n':raise SystemExit(125)
import pypdf
result={'status':'FAILED','metadata':{},'page_samples':[],'frontmatter_layout':[],'identification_version':'ARKS_LOCAL_BIBLIOGRAPHIC_LAYOUT_V2','preflight':'FAIL'}
try:
    r=pypdf.PdfReader(io.BytesIO((p/'input.pdf').read_bytes()),strict=True)
    if r.is_encrypted: raise ValueError('ENCRYPTED_UNSUPPORTED')
    n=len(r.pages);result['physical_pages']=n
    result['metadata']={str(k):str(v)[:2000] for k,v in (r.metadata or {}).items()}
    root=r.root_object; names=root.get('/Names')
    result['structural_flags']=[k for k in ('/OpenAction','/AA','/AcroForm') if k in root]
    if names:result['structural_flags'] += [k for k in ('/JavaScript','/EmbeddedFiles') if k in names.get_object()]
    result['page_actions']=[i+1 for i,x in enumerate(r.pages) if '/AA' in x]
    result['preflight']='PASS' if 0<n<=2048 and not result['structural_flags'] and not result['page_actions'] else 'FAIL'
    for i in range(min(2,n)):
        try:
            spans=[]
            def visit(text,cm,tm,font,size):
                if text.strip() and len(spans)<512:
                    # Physical glyph scale includes the text and current matrices.
                    # Font size alone can be 1 for every heading in a valid PDF.
                    scale=math.hypot(tm[2]*cm[0]+tm[3]*cm[2],tm[2]*cm[1]+tm[3]*cm[3])
                    spans.append({'text':text[:2000],'font_size':float(size)*scale,'raw_font_size':float(size),'x':float(tm[4]*cm[0]+tm[5]*cm[2]+cm[4]),'y':float(tm[4]*cm[1]+tm[5]*cm[3]+cm[5])})
            result['page_samples'].append({'physical_page':i+1,'text':r.pages[i].extract_text(visitor_text=visit)[:6000]})
            result['frontmatter_layout'].append({'physical_page':i+1,'spans':spans})
        except Exception as e: result['page_samples'].append({'physical_page':i+1,'error':type(e).__name__})
    result['status']='IDENTIFIED';result['pypdf_version']=pypdf.__version__
except Exception as e:result['error']=type(e).__name__+':'+str(e)[:200]
(p/'METADATA.json').write_text(json.dumps(result,ensure_ascii=False),encoding='utf-8')
