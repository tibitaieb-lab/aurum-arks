"""Trusted gated native reader and explicit passive raster rendering; no PDF actions."""
import io
import json
import os
from pathlib import Path
import sys
import math
import struct
import zlib

sys.dont_write_bytecode = True


# Versioned semantic interpretation of two explicit source glyph names.
# Renders reviewed in CP2830; never infers a CID from font family or context.
DECLARED_SEMANTIC_NAMES_V1={'envelopeback':'\u2709','greaterorequalslant':'\u2a7e','Sigma1':'\u03a3','Phi1':'\u03a6'}
def literal_glyph_unicode(name):
    base=name.split('.',1)[0]
    digits=base[3:] if base.startswith('uni') and len(base)==7 else base[1:] if base.startswith('u') and 5<=len(base)<=7 else ''
    if not digits or any(c not in '0123456789ABCDEF' for c in digits):return None
    code=int(digits,16)
    if not 32<=code<=0x10ffff or 0x7f<=code<=0x9f or 0xd800<=code<=0xdfff or code==0xfffd:return None
    return chr(code)


def collect_passive_objects(reader,kind):
 """Inspect bounded passive data only; never initialize or execute objects."""
 import hashlib
 def need(v):
  if not v:raise RuntimeError('PDF_PASSIVE_OBJECT_NOT_QUALIFIABLE')
 def res(v):return v.get_object() if hasattr(v,'get_object') else v
 def ref(v):return {'object_id':v.idnum,'generation':v.generation} if hasattr(v,'idnum') else None
 out=[]
 if kind=='EMPTY_STATIC_ACROFORM_V1':
  form=res(reader.root_object.get('/AcroForm',{}));need(isinstance(form,dict) and '/XFA' not in form and '/AA' not in form and '/CO' not in form)
  appearance=res(form.get('/NeedAppearances',False));need(appearance is False or getattr(appearance,'value',None) is False)
  fields=res(form.get('/Fields',[]));need(isinstance(fields,list) and 1<=len(fields)<=2048)
  page_map={}
  for n,page in enumerate(reader.pages,1):
   for ann in res(page.get('/Annots',[])):
    if hasattr(ann,'idnum'):page_map[(ann.idnum,ann.generation)]=n
  leaves=[];seen=set()
  def descend(fref,parent=None,inherited_type=None,depth=0):
   need(depth<=16);reference=ref(fref);need(reference is not None);key=(reference['object_id'],reference['generation']);need(key not in seen and len(seen)<2048);seen.add(key)
   original=res(fref);need(isinstance(original,dict) and not any(k in original for k in ('/AA','/AF','/XFA')))
   if '/Parent' in original:need(ref(original.raw_get('/Parent'))==parent)
   effective_type=str(original.get('/FT',inherited_type));need(effective_type in ('/Tx','/Btn'))
   for k in ('/V','/DV'):need(original.get(k) in (None,'','/Off'))
   if '/Kids' in original:
    need('/A' not in original);kids=res(original['/Kids']);need(isinstance(kids,list) and 1<=len(kids)<=64)
    for child in kids:descend(child,reference,effective_type,depth+1)
   else:
    f=dict(original);f['/FT']=effective_type;f.pop('/Parent',None);leaves.append((fref,f,parent))
  for fref in fields:descend(fref)
  for fref,f,parent in leaves:
   need(str(f.get('/Subtype'))=='/Widget')
   for key in ('/V','/DV'):need(f.get(key) in (None,'','/Off'))
   need(f.get('/AS') in (None,'/Off'))
   action=res(f.get('/A'))
   if action is not None:need(isinstance(action,dict) and set(action)<= {'/Type','/S','/N'} and str(action.get('/S'))=='/Named' and str(action.get('/N'))=='/Print')
   r=ref(fref);need(r is not None and (r['object_id'],r['generation']) in page_map)
   rect=res(f.get('/Rect'));need(isinstance(rect,list) and len(rect)==4 and all(isinstance(v,(int,float)) and math.isfinite(float(v)) for v in rect))
   ap=res(f.get('/AP',{}));need(isinstance(ap,dict) and set(ap)<= {'/N','/D','/R'})
   appearances=[]
   for mode,entry in sorted(ap.items()):
    obj=res(entry);items=[('',entry)] if hasattr(obj,'get_data') else list(obj.items()) if isinstance(obj,dict) else []
    need(1<=len(items)<=8)
    for state,entry in items:
     stream=res(entry);need(hasattr(stream,'get_data'));data=stream.get_data();need(len(data)<=1024**2)
     appearances.append({'mode':str(mode),'state':str(state),'reference':ref(entry),'decoded_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
   out.append({'reference':r,'parent_reference':parent,'physical_page':page_map[(r['object_id'],r['generation'])],'kind':'EMPTY_STATIC_WIDGET','field_type':str(f['/FT']),'rect':[float(v).hex() for v in rect],'value':str(f.get('/V','')),'appearance_state':str(f.get('/AS','')),'appearances':appearances,'disabled_action':'PRINT' if action else None,'text_indexed':False})
 elif kind=='OPAQUE_EMBEDDED_DATA_V1':
  names=res(reader.root_object.get('/Names',{}));tree=res(names.get('/EmbeddedFiles',{}));need(isinstance(tree,dict) and set(tree)<= {'/Names'})
  entries=res(tree.get('/Names',[]));need(isinstance(entries,list) and 0<len(entries)<=64 and len(entries)%2==0)
  for name,fref in zip(entries[::2],entries[1::2]):
   f=res(fref);need(isinstance(name,str) and len(name)<=1024 and isinstance(f,dict) and set(f)<= {'/Type','/F','/UF','/EF','/Desc','/AFRelationship'} and str(f.get('/Type'))=='/Filespec')
   ef=res(f.get('/EF'));need(isinstance(ef,dict) and 1<=len(ef)<=2 and set(ef)<= {'/F','/UF'})
   streams=[]
   for key,entry in sorted(ef.items()):
    stream=res(entry);need(hasattr(stream,'get_data') and str(stream.get('/Type'))=='/EmbeddedFile');data=stream.get_data();need(0<len(data)<=8*1024**2)
    streams.append({'key':str(key),'reference':ref(entry),'decoded_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
   out.append({'reference':ref(fref),'name':str(name),'streams':streams,'execution':'NONE','text_indexed':False})
 else:need(False)
 return out


def passive_controls(reader,object_proof=None):
    """Validate inert destinations, not a blanket permission for PDF actions."""
    def reject(code):raise RuntimeError(code)
    root=reader.root_object;pages=list(reader.pages)
    refs={(p.indirect_reference.idnum,p.indirect_reference.generation) for p in pages if p.indirect_reference}
    counts={'internal_destinations':0,'named_internal_destinations':0,'inert_uri_links':0,'empty_forms':0,'pages_inspected':len(pages)}
    qualified=None;widget_refs=set()
    if object_proof is not None:
        if type(object_proof) is not dict or object_proof.get('version')!='ARKS_PASSIVE_OBJECT_PROOF_V1':reject('PDF_PASSIVE_OBJECT_PROOF')
        qualified=collect_passive_objects(reader,object_proof['kind'])
        if qualified!=object_proof['objects']:reject('PDF_PASSIVE_OBJECT_PROOF_CHANGED')
        counts['qualified_passive_objects']=object_proof
        if object_proof['kind']=='EMPTY_STATIC_ACROFORM_V1':widget_refs={(o['reference']['object_id'],o['reference']['generation']) for o in qualified}
    def pdf_boolean(value):
        # pypdf BooleanObject(False) is truthy as a Python wrapper. Its PDF value
        # is explicit; strings/numbers/unknown wrappers are not boolean consent.
        from pypdf.generic import BooleanObject
        value=value.get_object() if hasattr(value,'get_object') else value
        if isinstance(value,BooleanObject):value=value.value
        if type(value) is not bool:reject('PDF_BOOLEAN_VALUE_INVALID')
        return value
    named=None
    def destination(value,manual=False):
        nonlocal named
        value=value.get_object() if hasattr(value,'get_object') else value
        if isinstance(value,str):
            if len(value)>1024:reject('PDF_NAMED_DESTINATION_BOUND')
            if named is None:
                named=reader.named_destinations
                if len(named)>16384:reject('PDF_NAMED_DESTINATION_BOUND')
            target=named.get(value)
            if target is None:
                if manual:
                    counts['inert_unresolved_navigation_links']=counts.get('inert_unresolved_navigation_links',0)+1;return
                reject('PDF_NAMED_DESTINATION_NOT_FOUND')
            value=target.dest_array
            counts['named_internal_destinations']+=1
        if not isinstance(value,list) or len(value)<2:reject('PDF_PASSIVE_DESTINATION_UNSUPPORTED')
        first=value[0]
        if hasattr(first,'idnum'):
            if (first.idnum,first.generation) not in refs:reject('PDF_DESTINATION_OUTSIDE_DOCUMENT')
        elif not isinstance(first,int) or isinstance(first,bool) or not 0<=first<len(pages):reject('PDF_DESTINATION_OUTSIDE_DOCUMENT')
        sizes={'/Fit':2,'/FitB':2,'/FitH':3,'/FitV':3,'/FitBH':3,'/FitBV':3,'/XYZ':5,'/FitR':6}
        incomplete_view=len(value)==2 and str(value[1]) in ('/FitH','/FitV','/FitBH','/FitBV')
        if str(value[1]) not in sizes or (len(value)!=sizes[str(value[1])] and not incomplete_view):reject('PDF_DESTINATION_MODE_UNSUPPORTED')
        if incomplete_view:counts['inert_incomplete_view_destinations']=counts.get('inert_incomplete_view_destinations',0)+1
        for n in value[2:]:
            if type(n).__name__=='NullObject':continue
            if not isinstance(n,(int,float)) or isinstance(n,bool) or not math.isfinite(float(n)):reject('PDF_DESTINATION_VALUE_INVALID')
        counts['internal_destinations']+=1
    def action(value,link=False):
        value=value.get_object() if hasattr(value,'get_object') else value
        if isinstance(value,list):destination(value,manual=link);return
        if not isinstance(value,dict):reject('PDF_ACTION_UNSUPPORTED')
        if str(value.get('/S'))=='/GoTo' and set(value)<= {'/S','/D','/Type'} and '/D' in value:destination(value['/D'],manual=link);return
        if link and str(value.get('/S'))=='/Named' and set(value)<= {'/S','/N','/Type'} and str(value.get('/N')) in ('/FirstPage','/LastPage','/NextPage','/PrevPage','/GoToPage','/GoBack','/GoForward','/Find'):
            counts['inert_viewer_navigation_links']=counts.get('inert_viewer_navigation_links',0)+1;return
        # URI annotations are represented passively, never followed. Automatic URI actions remain denied.
        if link and str(value.get('/S'))=='/URI' and set(value)<= {'/S','/URI','/Type','/IsMap'}:
            # A PDF string can be an indirect object. Resolve its representation
            # before applying the same inert-link type check; never follow it.
            uri=value.get('/URI');uri=uri.get_object() if hasattr(uri,'get_object') else uri
            if isinstance(uri,str) and not pdf_boolean(value.get('/IsMap',False)):
                counts['inert_uri_links']+=1;return
        # Manual remote destinations are inert annotation data, just like URI
        # links. Never dereference the file specification or execute its action.
        # Automatic actions, chains and embedded file specifications are still
        # refused. A named destination is recorded, not resolved externally.
        if link and str(value.get('/S'))=='/GoToR' and set(value)<= {'/S','/F','/D','/Type','/NewWindow'}:
            target=value.get('/F');target=target.get_object() if hasattr(target,'get_object') else target
            if isinstance(target,dict):
                if set(target)-{'/F','/UF','/Type'} or str(target.get('/Type','/Filespec'))!='/Filespec':reject('PDF_INERT_REMOTE_FILE_SPEC_UNSUPPORTED')
                if '/UF' in target and (not isinstance(target['/UF'],str) or not 0<len(target['/UF'])<=4096 or any(ord(c)<32 for c in target['/UF'])):reject('PDF_INERT_REMOTE_FILE_SPEC_UNSUPPORTED')
                target=target.get('/F')
            dest=value.get('/D');dest=dest.get_object() if hasattr(dest,'get_object') else dest
            if (not isinstance(target,str) or not 0<len(target)<=4096 or any(ord(c)<32 for c in target)
                    or not isinstance(dest,str) or not 0<len(dest)<=1024 or any(ord(c)<32 for c in dest)
                    or str(value.get('/Type','/Action'))!='/Action' or pdf_boolean(value.get('/NewWindow',False))):
                reject('PDF_INERT_REMOTE_LINK_UNSUPPORTED')
            counts['inert_remote_links']=counts.get('inert_remote_links',0)+1;return
        reject('PDF_EXECUTABLE_OR_EXTERNAL_ACTION_UNSUPPORTED')
    if '/AA' in root:reject('PDF_AUTOMATIC_ACTION_UNSUPPORTED')
    if '/OpenAction' in root:action(root['/OpenAction'])
    if '/AcroForm' in root and not widget_refs:
        form=root['/AcroForm'].get_object()
        if not isinstance(form,dict):reject('PDF_NONEMPTY_OR_DYNAMIC_FORM_UNSUPPORTED')
        fields=form.get('/Fields',[])
        fields=fields.get_object() if hasattr(fields,'get_object') else fields
        if '/XFA' in form or not isinstance(fields,list) or fields or pdf_boolean(form.get('/NeedAppearances',False)):reject('PDF_NONEMPTY_OR_DYNAMIC_FORM_UNSUPPORTED')
        counts['empty_forms']+=1
    names=root.get('/Names')
    if names:
        names=names.get_object()
        if '/JavaScript' in names:reject('PDF_ACTIVE_OR_EMBEDDED_CONTENT_UNSUPPORTED')
        if '/EmbeddedFiles' in names and not (object_proof and object_proof['kind']=='OPAQUE_EMBEDDED_DATA_V1'):
            embedded=names['/EmbeddedFiles'].get_object()
            if not isinstance(embedded,dict) or set(embedded)-{'/Names','/Kids'}:reject('PDF_ACTIVE_OR_EMBEDDED_CONTENT_UNSUPPORTED')
            for value in embedded.values():
                value=value.get_object() if hasattr(value,'get_object') else value
                if not isinstance(value,list) or len(value):reject('PDF_ACTIVE_OR_EMBEDDED_CONTENT_UNSUPPORTED')
            counts['empty_attachment_containers']=1
    if '/AF' in root:reject('PDF_ATTACHED_FILE_UNSUPPORTED')
    for page in pages:
        if '/AA' in page:reject('PDF_PAGE_ACTION_UNSUPPORTED')
        annotations=page.get('/Annots',[])
        annotations=annotations.get_object() if hasattr(annotations,'get_object') else annotations
        if not isinstance(annotations,list) or len(annotations)>10000:reject('PDF_ANNOTATION_BOUND')
        for value in annotations:
            item=value.get_object()
            if hasattr(value,'idnum') and (value.idnum,value.generation) in widget_refs:continue
            if not isinstance(item,dict) or '/AA' in item or '/AF' in item or str(item.get('/Subtype')) in ('/Widget','/FileAttachment','/RichMedia','/Screen','/Movie','/Sound','/3D'):reject('PDF_ACTIVE_ANNOTATION_UNSUPPORTED')
            if '/A' in item:action(item['/A'],link=str(item.get('/Subtype'))=='/Link')
            if '/Dest' in item:destination(item['/Dest'],manual=str(item.get('/Subtype'))=='/Link')
    return dict(counts,status='PASS',execution='NONE',forms_initialized=False)


def passive_pdfium():
    import platform
    if sys.platform!='win32' or os.name!='nt' or sys.getwindowsversion().major<10:raise RuntimeError('PDF_PASSIVE_OS_IDENTITY')
    previous=platform.system
    try:
        platform.system=lambda:'Windows'
        import pypdfium2 as pdfium
    finally:platform.system=previous
    from pypdfium2.version import PYPDFIUM_INFO,PDFIUM_INFO
    if str(PYPDFIUM_INFO.version)!='5.13.0' or list(PDFIUM_INFO.flags):raise RuntimeError('PDF_PASSIVE_RUNTIME_IDENTITY')
    return pdfium


def names_from_cff(data):
 from pdfminer.pdffont import CFFFont
 def check(v):
  if not v:raise RuntimeError('PDF_CFF_DECLARATION_UNSUPPORTED')
 check(type(data) is bytes and 4<=len(data)<=8*1024**2)
 def take(pos,size):
  check(type(pos) is int and type(size) is int and 0<=pos<=len(data) and 0<=size<=len(data)-pos);return data[pos:pos+size]
 def index(pos):
  count=int.from_bytes(take(pos,2),'big');pos+=2;check(count<=65535)
  if count==0:return [],pos
  offsize=take(pos,1)[0];pos+=1;check(1<=offsize<=4)
  offsets=[int.from_bytes(take(pos+i*offsize,offsize),'big') for i in range(count+1)];pos+=(count+1)*offsize
  check(offsets[0]==1 and all(a<=b for a,b in zip(offsets,offsets[1:])))
  items=[take(pos+offsets[i]-1,offsets[i+1]-offsets[i]) for i in range(count)]
  return items,pos+offsets[-1]-1
 check(data[0]==1 and 4<=data[2]<=len(data));pos=data[2]
 fontnames,pos=index(pos);top,pos=index(pos);strings,pos=index(pos);subrs,pos=index(pos);check(len(fontnames)==len(top)==1)
 d={};stack=[];src=top[0];i=0
 while i<len(src):
  b=src[i];i+=1
  if b<=21:
   if b==12:
    check(i<len(src));op=(12,src[i]);i+=1
   else:op=b
   check(op not in d);d[op]=stack;stack=[]
  elif 32<=b<=246:stack.append(b-139)
  elif 247<=b<=254:
   check(i<len(src));v=src[i];i+=1;stack.append((b-247)*256+v+108 if b<=250 else -(b-251)*256-v-108)
  elif b in (28,29):
   n=2 if b==28 else 4;check(i+n<=len(src));stack.append(int.from_bytes(src[i:i+n],'big',signed=True));i+=n
  elif b==30:
   # Real-valued metadata may occur in FontMatrix; offsets must still be integers.
   done=False;start=i
   while not done:
    check(i<len(src) and i-start<=64);v=src[i];i+=1;done=(v>>4)==15 or (v&15)==15
   stack.append(None)
  else:check(False)
  check(len(stack)<=48 and len(d)<=512)
 check(not stack and (12,30) not in d)
 def scalar(op,default):
  value=d.get(op,[default]);check(type(value) is list and len(value)==1 and type(value[0]) is int);return value[0]
 charset=scalar(15,0);encoding=scalar(16,0);charstrings=scalar(17,0)
 glyphs,_=index(charstrings);check(1<=len(glyphs)<=256)
 def name(sid):
  check(type(sid) is int and 0<=sid<len(CFFFont.STANDARD_STRINGS)+len(strings))
  value=CFFFont.STANDARD_STRINGS[sid] if sid<len(CFFFont.STANDARD_STRINGS) else strings[sid-len(CFFFont.STANDARD_STRINGS)].decode('ascii','strict')
  check(type(value) is str and 1<=len(value)<=128);return value
 # This narrow profile supports custom encodings/charsets, not guessed defaults.
 check(charset>2 and encoding>1);pos=charset;fmt=take(pos,1)[0];pos+=1;names={0:'.notdef'};gid=1
 if fmt==0:
  for gid in range(1,len(glyphs)):names[gid]=name(int.from_bytes(take(pos,2),'big'));pos+=2
 elif fmt in (1,2):
  while gid<len(glyphs):
   first=int.from_bytes(take(pos,2),'big');pos+=2;size=1 if fmt==1 else 2;left=int.from_bytes(take(pos,size),'big');pos+=size;check(gid+left<len(glyphs))
   for sid in range(first,first+left+1):names[gid]=name(sid);gid+=1
 else:check(False)
 pos=encoding;tag=take(pos,1)[0];fmt=tag&127;supplement=bool(tag&128);pos+=1;check(fmt in (0,1));count=take(pos,1)[0];pos+=1;mapping={};gid=1
 if fmt==0:
  codes=take(pos,count);pos+=count
  for code in codes:
   check(code not in mapping and gid<len(glyphs));mapping[code]=names[gid];gid+=1
 else:
  for _ in range(count):
   first,left=take(pos,2);pos+=2;check(first+left<=255)
   for code in range(first,first+left+1):
    check(code not in mapping and gid<len(glyphs));mapping[code]=names[gid];gid+=1
 if supplement:
  count=take(pos,1)[0];pos+=1;seen=set()
  for _ in range(count):
   code=take(pos,1)[0];sid=int.from_bytes(take(pos+1,2),'big');pos+=3;value=name(sid)
   check(code not in seen and value in names.values() and (code not in mapping or mapping[code]==value))
   seen.add(code);mapping[code]=value
 check(mapping);return mapping


def symbolic_truetype_names(data):
 """Source cmap -> glyph index -> source post name; no Unicode inference."""
 def check(v):
  if not v:raise RuntimeError('PDF_TRUETYPE_DECLARATION_UNSUPPORTED')
 check(type(data) is bytes and 12<=len(data)<=8*1024**2 and data[:4] in (b'\0\1\0\0',b'true'))
 def take(offset,size):
  check(0<=offset<=len(data) and 0<=size<=len(data)-offset);return data[offset:offset+size]
 def u16(b,o):check(0<=o<=len(b)-2);return int.from_bytes(b[o:o+2],'big')
 tables={};count=u16(data,4);check(1<=count<=128)
 for i in range(count):
  tag,checksum,offset,size=struct.unpack('>4sIII',take(12+16*i,16));check(tag not in tables);tables[tag]=take(offset,size)
 if b'post' not in tables or b'cmap' not in tables:return {}
 post=tables[b'post'];check(len(post)>=32)
 if post[:4]!=b'\0\2\0\0':return {}
 count=u16(post,32);check(1<=count<=65535);indices=[u16(post,34+2*i) for i in range(count)]
 custom=[];pos=34+2*count
 for i in range(max(0,max(indices)-257)):
  check(pos<len(post));length=post[pos];pos+=1;check(1<=length<=128 and pos+length<=len(post));custom.append(post[pos:pos+length].decode('ascii','strict'));pos+=length
 names={gid:custom[index-258] for gid,index in enumerate(indices) if index>=258}
 cmap=tables[b'cmap'];count=u16(cmap,2);check(1<=count<=128);maps=[]
 for i in range(count):
  pos=4+8*i;check(pos+8<=len(cmap));platform,encoding,offset=struct.unpack('>HHI',cmap[pos:pos+8])
  if (platform,encoding) not in ((3,0),(1,0)):continue
  fmt=u16(cmap,offset);length=u16(cmap,offset+2);check(offset+length<=len(cmap));sub=cmap[offset:offset+length];mapping={}
  if fmt==0:
   check(len(sub)==262);mapping={i:sub[6+i] for i in range(256) if sub[6+i]}
  elif fmt==6:
   # OpenType cmap format 6: explicit contiguous character -> glyph indices.
   # No Unicode or font-family inference; post names remain the sole authority.
   first=u16(sub,6);entries=u16(sub,8)
   check(len(sub)==10+2*entries and first+entries<=65536)
   for j in range(entries):
    gid=u16(sub,10+2*j)
    if gid:check(gid<len(indices));mapping[first+j]=gid
  elif fmt==4:
   seg=u16(sub,6)//2;check(1<=seg<=8192 and u16(sub,6)==seg*2)
   for j in range(seg):
    end=u16(sub,14+2*j);start=u16(sub,16+2*seg+2*j);delta=u16(sub,16+4*seg+2*j);ro=16+6*seg+2*j;off=u16(sub,ro);check(start<=end)
    for code in range(start,end+1):
     if code==65535:continue
     gid=u16(sub,ro+off+2*(code-start)) if off else code
     if gid or not off:gid=(gid+delta)&65535
     if gid:check(code not in mapping);mapping[code]=gid
  else:raise RuntimeError('PDF_TRUETYPE_CMAP_FORMAT_UNSUPPORTED')
  resolved={}
  for cid in range(256):
   choices={mapping[c] for c in (cid,cid+0xf000) if c in mapping} if platform==3 else {mapping[cid]} if cid in mapping else set()
   check(len(choices)<=1)
   if choices:
    gid=next(iter(choices));check(gid<len(indices))
    if gid in names:resolved[cid]=names[gid]
  maps.append(resolved)
 result={}
 for mapping in maps:
  for cid,name in mapping.items():check(cid not in result or result[cid]==name);result[cid]=name
 return result


def deterministic_layout_grouping(original):
 """Keep native geometry; replace only process-address tie breaks."""
 import types
 def grouped(self,laparams,boxes):
  identities={}
  def stable_id(obj):
   if obj not in identities:
    if len(identities)>=65536:raise RuntimeError('PDF_LAYOUT_GROUP_BOUND')
    identities[obj]=len(identities)
   return identities[obj]
  for box in boxes:stable_id(box)
  namespace=dict(original.__globals__);namespace['id']=stable_id
  return types.FunctionType(original.__code__,namespace,original.__name__,original.__defaults__,original.__closure__)(self,laparams,boxes)
 return grouped


def source_font_reference(objid,spec):
 """Fingerprint a source-scoped font dictionary, retaining indirect references."""
 from pdfminer.pdftypes import PDFObjRef,PDFStream
 from pdfminer.psparser import PSLiteral
 def encode(v,depth=0):
  if depth>16:raise RuntimeError('PDF_FONT_REFERENCE_DEPTH')
  if isinstance(v,PDFObjRef):return {'source_object_id':v.objid}
  if isinstance(v,PSLiteral):return {'pdf_name':v.name}
  if isinstance(v,PDFStream):
   raw=v.get_data()
   if len(raw)>8*1024**2:raise RuntimeError('PDF_FONT_REFERENCE_STREAM_BOUND')
   import hashlib
   return {'dictionary':encode(v.attrs,depth+1),'decoded_stream_sha256':hashlib.sha256(raw).hexdigest()}
  if isinstance(v,dict):
   if len(v)>1024:raise RuntimeError('PDF_FONT_REFERENCE_BOUND')
   return {k:encode(val,depth+1) for k,val in sorted(v.items())}
  if isinstance(v,(list,tuple)):
   if len(v)>65536:raise RuntimeError('PDF_FONT_REFERENCE_BOUND')
   return [encode(a,depth+1) for a in v]
  if isinstance(v,bytes):return {'bytes_hex':v.hex()}
  if type(v) is float:
   if not math.isfinite(v):raise RuntimeError('PDF_FONT_REFERENCE_NUMBER')
   return {'float_hex':v.hex()}
  if v is None or type(v) in (int,str,bool):return v
  raise RuntimeError('PDF_FONT_REFERENCE_TYPE')
 value={'contract':'SOURCE_SCOPED_FONT_DICTIONARY_V1','object_id':objid,'dictionary':encode(spec)}
 raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 if len(raw)>1024**2:raise RuntimeError('PDF_FONT_REFERENCE_BOUND')
 import hashlib
 return hashlib.sha256(raw).hexdigest(),value


def passive_pdfminer(raw,total,report,declared_mapping=False,reviewed_pages=None):
    """Bounded native character interpretation; undefined glyphs stay explicit."""
    import logging,hashlib
    events=[]
    class TechnicalLogs(logging.Handler):
        def emit(self,record):
            if record.levelno>=logging.WARNING:
                if len(events)>=1000:raise RuntimeError('PDF_NATIVE_WARNING_LIMIT')
                events.append({'logger':record.name,'module':record.module,'function':record.funcName,'line':record.lineno,
                    'type':'LoggingWarning','message_sha256':hashlib.sha256(record.getMessage().encode()).hexdigest()})
    logger=logging.getLogger('pdfminer');logger.addHandler(TechnicalLogs());logger.propagate=False
    import pdfminer
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfinterp import PDFResourceManager,PDFPageInterpreter
    from pdfminer.converter import PDFPageAggregator
    from pdfminer.layout import LAParams,LTChar,LTAnno,LTContainer
    from pdfminer.layout import LTLayoutContainer
    if pdfminer.__version__!='20260107' or not Path(pdfminer.__file__).is_relative_to(Path(sys.prefix)):
        raise RuntimeError('PDF_NATIVE_RUNTIME_IDENTITY')
    document=PDFDocument(PDFParser(io.BytesIO(raw)))
    if not document.is_extractable:raise RuntimeError('PDF_NATIVE_EXTRACTION_PERMISSION')
    pages=list(PDFPage.create_pages(document))
    if len(pages)!=total:raise RuntimeError('PDF_NATIVE_PAGE_COUNT')
    report['native_document_warnings']=list(events);events.clear()
    if report['native_document_warnings']:raise RuntimeError('PDF_NATIVE_DOCUMENT_WARNING')
    from pdfminer.pdftypes import resolve1,PDFStream
    from pdfminer.pdffont import Type1FontHeaderParser,PDFUnicodeNotDefined
    from pdfminer.psparser import PSEOF
    from pdfminer.encodingdb import name2unicode
    from pypdf._codecs.adobe_glyphs import adobe_glyphs
    class DeclaredManager(PDFResourceManager):
        def get_font(self,objid,spec):
            font=super().get_font(objid,spec)
            if hasattr(font,'_arks_declared'):return font
            names={};encoding=resolve1(spec.get('Encoding'))
            def record(cid,name,origin):
                if type(cid) is not int or not 0<=cid<=255 or type(name) is not str or len(name)>128:
                    raise RuntimeError('PDF_DECLARED_GLYPH_CONTRACT')
                if cid in names and names[cid][0]!=name:raise RuntimeError('PDF_CONFLICTING_GLYPH_DECLARATION')
                names[cid]=(name,origin)
            if isinstance(encoding,dict):
                cursor=None;difference=resolve1(encoding.get('Differences',[]))
                if not isinstance(difference,list) or len(difference)>1024:raise RuntimeError('PDF_GLYPH_DIFFERENCES_BOUND')
                for item in difference:
                    if type(item) is int:cursor=item
                    elif hasattr(item,'name') and cursor is not None:
                        record(cursor,item.name,'PDF_ENCODING_DIFFERENCES');cursor+=1
                    else:raise RuntimeError('PDF_DECLARED_GLYPH_CONTRACT')
            elif 'Encoding' not in spec:
                stream=resolve1(resolve1(font.descriptor).get('FontFile'))
                if isinstance(stream,PDFStream):
                    data=stream.get_data();length=stream.attrs.get('Length1')
                    if len(data)>8*1024**2 or type(length) is not int or not 0<=length<=len(data):raise RuntimeError('PDF_GLYPH_PROGRAM_BOUND')
                    header=data[:length]
                    # The passive pdfminer token reader does not execute `for`.
                    # It reports the loop's literal 1 /.notdef as a CID1 put.
                    # Recognize only this exact static Encoding initialization;
                    # genuine duplicate glyph assignments still reach record().
                    import re
                    initializer_puts={header.index(b'put',m.start(),m.end()) for m in re.finditer(
                        rb'/Encoding\s+256\s+array\s+0\s+1\s+255\s*\{\s*1\s+index\s+exch\s*/\.notdef\s+put\s*\}\s*for\b',header)}
                    class ExplicitEncodingParser(Type1FontHeaderParser):
                        def do_keyword(self,pos,token):
                            if token is self.KEYWORD_PUT and pos in initializer_puts:
                                self.pop(2) # Same passive stack consumption, no fictitious CID.
                                return
                            return super().do_keyword(pos,token)
                    parser=ExplicitEncodingParser(io.BytesIO(header))
                    # Same passive token parser as pdfminer, before name-to-Unicode loss.
                    # It interprets no PostScript operators or document commands.
                    for _ in range(1025):
                        try:cid,name=parser.nextobject()
                        except PSEOF:break
                        record(cid,name,'EMBEDDED_TYPE1_CLEAR_HEADER')
                    else:raise RuntimeError('PDF_GLYPH_DECLARATIONS_BOUND')
                else:
                    cff=resolve1(resolve1(font.descriptor).get('FontFile3'))
                    if isinstance(cff,PDFStream) and getattr(resolve1(cff.attrs.get('Subtype')),'name',None)=='Type1C':
                        for cid,name in names_from_cff(cff.get_data()).items():
                            record(cid,name,'EMBEDDED_CFF_ENCODING_CHARSET')

            if ('Encoding' not in spec and getattr(spec.get('Subtype'),'name',None)=='TrueType'
                    and type(resolve1(font.descriptor).get('Flags')) is int and resolve1(font.descriptor)['Flags']&4):
                ttf=resolve1(resolve1(font.descriptor).get('FontFile2'))
                if isinstance(ttf,PDFStream):
                    for cid,name in symbolic_truetype_names(ttf.get_data()).items():record(cid,name,'EMBEDDED_TRUETYPE_SYMBOL_CMAP_POST')
            font._arks_declared=names
            font._arks_source_font_reference=source_font_reference(objid,spec)
            if reviewed_pages:
                font._arks_program_hashes=[]
                for field in ('FontFile','FontFile2','FontFile3'):
                    stream=resolve1(resolve1(font.descriptor).get(field))
                    if isinstance(stream,PDFStream):
                        data=stream.get_data()
                        if len(data)>8*1024**2:raise RuntimeError('PDF_GLYPH_PROGRAM_BOUND')
                        font._arks_program_hashes.append(hashlib.sha256(data).hexdigest())
                if not font._arks_program_hashes:font._arks_program_hashes=[font._arks_source_font_reference[0]]
            return font
    class TracedAggregator(PDFPageAggregator):
        def render_image(self,name,stream):
            ordinal=self.image_ordinal;self.image_ordinal+=1
            review=getattr(self,'page_review',None)
            if review and review['method']=='SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2' and any(m['image_ordinal']==ordinal for m in review['content']['image_connectors']):
                width=stream.get('Width',stream.get('W'));height=stream.get('Height',stream.get('H'));bits=stream.get('BitsPerComponent',stream.get('BPC',1));mask=stream.get('ImageMask',stream.get('IM',False));decode=stream.get('Decode',stream.get('D'))
                if not (type(width) is int and type(height) is int and width==height==1 and type(bits) is int and bits==1 and mask is True and decode in (None,[0,1])):raise RuntimeError('PDF_REVIEW_MASK_PROFILE_CHANGED')
                data=stream.get_data()
                if data!=b'\x00':raise RuntimeError('PDF_REVIEW_MASK_PAINT_CHANGED')
                self.image_connectors.append({'image_ordinal':ordinal,'following_glyph_ordinal':self.source_ordinal,'width':width,'height':height,'bits_per_component':bits,'image_mask':mask,'decode':decode,'decoded_sha256':hashlib.sha256(data).hexdigest(),'figure_matrix':[float(v).hex() for v in self.cur_item.matrix],'bbox':[float(v).hex() for v in self.cur_item.bbox]})
            return super().render_image(name,stream)
        def render_char(self,matrix,font,fontsize,scaling,rise,cid,ncs,graphicstate):
            source_ordinal=self.source_ordinal;self.source_ordinal+=1
            original=font.to_unichr
            try:baseline=original(cid)
            except PDFUnicodeNotDefined:baseline='(cid:%d)'%cid
            graphic=None
            review=getattr(self,'page_review',None)
            grouped=bool(review and review['method'] in ('SOURCE_DECLARED_COMPONENT_GROUPS_V1','SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2'))
            uninterpreted=bool(review and review['method']=='SOURCE_UNINTERPRETED_GLYPH_OBJECTS_V1')
            if review and review['method'] in ('SOURCE_GLYPH_DIAGRAM_OBJECTS_V1','SOURCE_DECLARED_COMPONENT_GROUPS_V1','SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2','SOURCE_UNINTERPRETED_GLYPH_OBJECTS_V1'):
                for resource in review['content']['resources']:
                    if resource['program_sha256'] in getattr(font,'_arks_program_hashes',[]) and cid in resource['cids']:
                        if uninterpreted and not any(c['source_ordinal']==source_ordinal and c['cid']==cid and c['program_sha256']==resource['program_sha256'] for c in review['content']['components']):continue
                        if graphic is not None:raise RuntimeError('PDF_GRAPHIC_RESOURCE_AMBIGUOUS')
                        graphic=resource
            declaration=getattr(font,'_arks_declared',{}).get(cid);target=None;explicit=False
            unresolved_before=self.unresolved
            if font.unicode_map:
                try:font.unicode_map.get_unichr(cid);explicit=True
                except KeyError:pass
            replacement_repair=explicit and (baseline=='\ufffd' or any(ord(c)<32 and c not in '\t\n\r' for c in baseline))
            if declaration is not None and (not explicit or replacement_repair):
                name,origin=declaration;target=adobe_glyphs.get('/'+name)
                try:native_name=name2unicode(name)
                except KeyError:native_name=None
                if target is None:target=native_name
                if target is None and not replacement_repair and name in DECLARED_SEMANTIC_NAMES_V1:
                    target=DECLARED_SEMANTIC_NAMES_V1[name];origin+='_ARKS_EXPLICIT_SEMANTIC_NAME_V1'
                if replacement_repair:
                    # A declared glyph name is independent of a broken
                    # ToUnicode entry. A missing naming-table entry is not a
                    # conflicting entry; any actual conflict remains closed.
                    # Valid ToUnicode always wins.
                    independent=adobe_glyphs.get('/'+name.split('.',1)[0])
                    if independent is None:
                        independent=literal_glyph_unicode(name)
                        if independent is not None:origin+='_SOURCE_LITERAL_UNICODE_NAME'
                    if (independent is None or target!=independent
                            or (native_name is not None and native_name!=independent)
                            or any(c=='\ufffd' or ord(c)<32 for c in target)):
                        target=None
                    else:origin+='_REPLACES_UNICODE_REPLACEMENT_CHARACTER'

                if target is None or (native_name is not None and target!=native_name):
                    self.unresolved+=1;target=None
                    def unknown(_):raise PDFUnicodeNotDefined(None,cid)
                    font.to_unichr=unknown
                elif target!=baseline:
                    if declared_mapping:
                        font.to_unichr=lambda _:target
                        key=(cid,name,origin,baseline,target)
                        self.declarations[key]=self.declarations.get(key,0)+1
                        if len(self.declarations)>1024:raise RuntimeError('PDF_GLYPH_MAPPING_BOUND')
                    else:
                        self.unresolved+=1
                        def unknown(_):raise PDFUnicodeNotDefined(None,cid)
                        font.to_unichr=unknown
            if graphic is not None:
                try:
                    try:review_baseline=font.to_unichr(cid)
                    except PDFUnicodeNotDefined:review_baseline='(cid:%d)'%cid
                    if (not grouped and not uninterpreted and len(review_baseline)!=1) or not 1<=len(review_baseline)<=32:raise RuntimeError('PDF_GRAPHIC_RAW_CHARACTER_CONTRACT')
                    if uninterpreted:
                        invalid=(review_baseline=='(cid:%d)'%cid or '\ufffd' in review_baseline or any(ord(c)<32 and c not in '\t\r\n' for c in review_baseline))
                        if not invalid:raise RuntimeError('PDF_UNINTERPRETED_VALID_TEXT_REFUSED')
                        if graphic['program_sha256']==font._arks_source_font_reference[0]:
                            if graphic.get('resource_kind')!='SOURCE_FONT_DICTIONARY' or graphic.get('font_dictionary')!=font._arks_source_font_reference[1]:raise RuntimeError('PDF_FONT_REFERENCE_DEFINITION_CHANGED')
                    if grouped or uninterpreted:self.unresolved=unresolved_before
                    font.to_unichr=lambda _:'\ufffc'
                    advance=super().render_char(matrix,font,fontsize,scaling,rise,cid,ncs,graphicstate)
                    item=self.cur_item._objs[-1];item._arks_raw_text=baseline
                    color=getattr(graphicstate,'ncolor',None)
                    color=list(color) if isinstance(color,(tuple,list)) else [color]
                    if not all(type(v) in (int,float) for v in color):raise RuntimeError('PDF_GRAPHIC_COLOR_UNSUPPORTED')
                    item._arks_graphic={'cid':cid,'program_sha256':graphic['program_sha256'],'raw_text':review_baseline,
                        'matrix':[float(v).hex() for v in matrix],'bbox':[float(v).hex() for v in item.bbox],
                        'font_size':float(fontsize).hex(),'horizontal_scaling':float(scaling).hex(),'rise':float(rise).hex(),
                        'nonstroking_color':[float(v).hex() for v in color],'color_space':getattr(ncs,'name',None),
                        'representation':'SOURCE_GLYPH_REFERENCE_NON_TEXT_DIAGRAM'}
                    if grouped:
                        if declaration is None:raise RuntimeError('PDF_GROUP_DECLARATION_MISSING')
                        item._arks_graphic.update(source_ordinal=source_ordinal,glyph_name=declaration[0],representation='SOURCE_DECLARED_COMPONENT_GROUP_NOT_UNICODE')
                    if uninterpreted:item._arks_graphic.update(source_ordinal=source_ordinal,representation='SOURCE_GLYPH_SHAPE_UNICODE_UNKNOWN')
                    if uninterpreted and graphic.get('resource_kind')=='SOURCE_FONT_DICTIONARY':item._arks_graphic.update(resource_kind='SOURCE_FONT_DICTIONARY',source_font_dictionary=graphic['font_dictionary'])
                    return advance
                finally:font.to_unichr=original
            try:
                advance=super().render_char(matrix,font,fontsize,scaling,rise,cid,ncs,graphicstate)
                self.cur_item._objs[-1]._arks_raw_text=baseline
                return advance
            finally:font.to_unichr=original
        def handle_undefined_char(self,font,cid):
            self.undefined+=1
            return super().handle_undefined_char(font,cid)
    manager=DeclaredManager(caching=True);device=TracedAggregator(manager,laparams=LAParams());interpreter=PDFPageInterpreter(manager,device)
    def extract(number,limit):
        events.clear();device.undefined=0;device.unresolved=0;device.source_ordinal=0;device.image_ordinal=0;device.image_connectors=[];device.declarations={};device.page_review=(reviewed_pages or {}).get(number)
        grouping=LTLayoutContainer.group_textboxes;LTLayoutContainer.group_textboxes=deterministic_layout_grouping(grouping)
        try:interpreter.process_page(pages[number-1])
        finally:LTLayoutContainer.group_textboxes=grouping
        layout=device.get_result();parts=[];raw_parts=[];review_parts=[];graphics=[];size=0;review_size=0;empty=0;native=0;images=0
        def visit(item,depth=0):
            nonlocal size,review_size,empty,native,images
            if depth>100:raise RuntimeError('PDF_NATIVE_LAYOUT_DEPTH')
            if isinstance(item,LTContainer):
                for child in item:visit(child,depth+1)
            elif isinstance(item,(LTChar,LTAnno)):
                value=item.get_text();offset=size;size+=len(value)
                if size>limit:raise RuntimeError('PDF_EXTRACTED_TEXT_LIMIT')
                parts.append(value)
                raw_parts.append(getattr(item,'_arks_raw_text',value))
                graphic=getattr(item,'_arks_graphic',None)
                review_value=graphic['raw_text'] if graphic else value;review_parts.append(review_value)
                if graphic:
                    entry=dict(graphic,offset=offset)
                    if 'source_ordinal' in graphic:entry.update(raw_start=review_size,raw_end=review_size+len(review_value))
                    graphics.append(entry)
                review_size+=len(review_value)
                if isinstance(item,LTChar):empty+=not bool(value);native+=len(value)
            elif type(item).__name__=='LTImage':images+=1
        visit(layout)
        raw_text=''.join(raw_parts)
        if len(raw_text)>limit:raise RuntimeError('PDF_RAW_NATIVE_TEXT_LIMIT')
        metadata={'native_character_count':native,'native_undefined_glyphs':device.undefined,'native_empty_glyphs':empty,
            'native_warning_count':len(events),'native_warning_events':list(events),'native_image_count':images,
            'native_unresolved_declarations':device.unresolved}
        if declared_mapping:
            declarations=[{'cid':cid,'glyph_name_sha256':hashlib.sha256(name.encode()).hexdigest(),'origin':origin,
                'before_sha256':hashlib.sha256(before.encode()).hexdigest(),'after_codepoints':[ord(c) for c in after],'occurrences':count}
                for (cid,name,origin,before,after),count in device.declarations.items()]
            metadata.update(raw_native_glyph_text=raw_text,raw_native_glyph_sha256=hashlib.sha256(raw_text.encode()).hexdigest(),
                raw_native_layout_contract='ORIGINAL_UNICODE_PER_GLYPH_WITH_QUALIFIED_LAYOUT_ANNOTATIONS',
                declared_mapping_count=sum(device.declarations.values()),declared_mappings=declarations,
                declared_mapping_contract='SOURCE_ENCODING_NAMES_V3_LITERAL_UNICODE_AND_EXPLICIT_SEMANTIC_NAMES')
        if device.page_review:
            metadata.update(review_input_text=''.join(review_parts),graphic_components=graphics)
            if device.page_review['method']=='SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2':metadata['review_image_connectors']=list(device.image_connectors)
        return ''.join(parts),metadata
    return extract


def main():
    folder = Path(sys.argv[1]).absolute()
    arks = Path(__file__).resolve().parents[2]
    if not folder.is_relative_to(arks/'reports'): return 125
    gate=json.loads((folder/'GATE.json').read_bytes())
    if (type(gate) is not dict or set(gate)!={'version','nonce'}
        or gate['version']!='ARKS_PDF_READY_V2' or type(gate['nonce']) is not str
        or len(gate['nonce'])!=32 or any(c not in '0123456789abcdef' for c in gate['nonce'])): return 125
    with (folder/'READY.tmp').open('x',encoding='utf-8') as stream:
        json.dump(dict(gate,pid=os.getpid()),stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(folder/'READY.tmp',folder/'READY.json')
    # Existence of READY alone is not publication completion on Windows.
    # No read of this marker is needed: READY's rename has already returned.
    with (folder/('READY_COMMITTED.'+gate['nonce'])).open('xb'): pass
    # Parent assigns both venv redirector and this interpreter before this gate.
    if sys.stdin.buffer.readline(8) != b'RUN\n': return 125
    sys.path.insert(0,str(arks/'src'))
    from aurum_arks.serialization import fingerprint, sha256, strict_loads
    from aurum_arks.paths import reject_links
    from aurum_arks.doc_pdf_warnings import ScopedWarnings
    reject_links(folder)
    if not folder.is_relative_to(arks/'reports'): return 125
    request_raw = (folder/'REQUEST.json').read_bytes()
    if len(request_raw)>131072: return 125
    request = strict_loads(request_raw); cfg = request['extractor']; params = cfg['parameters']
    passive=cfg.get('adapter')=='ARKS_PDF_TEXT_SELECTED_V2'
    render_page=params.get('render_page')
    if render_page is not None and (not passive or params.get('structural_only') is not True
                                   or type(render_page) is not int):return 125
    read_roots = (Path(sys.prefix),Path(sys.base_prefix),arks/'src',folder)
    forbidden_events = []

    def audit(event, args):
        if event.startswith(('socket.','subprocess.')) or event in ('os.system','os.startfile','os.startfile/2','os.exec','os.spawn'):
            forbidden_events.append(event); raise RuntimeError('PDF_FORBIDDEN_OPERATION')
        if event=='open' and isinstance(args[0],(str,bytes,os.PathLike)):
            path = Path(os.fsdecode(args[0])).absolute(); flags = args[2]
            writing = bool(flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            write_paths=(folder/'worker-result.tmp',folder/'worker-result.json',folder/'FATAL_TECHNICAL.json')
            if render_page is not None:write_paths+=(folder/'render.png',)
            if writing and path not in write_paths:
                forbidden_events.append('WRITE_OUTSIDE_RESULT'); raise RuntimeError('PDF_WRITE_REFUSED')
            if not writing and not any(path.is_relative_to(root) for root in read_roots):
                forbidden_events.append('READ_OUTSIDE_RUNTIME'); raise RuntimeError('PDF_READ_REFUSED')
    sys.addaudithook(audit)

    counter = ScopedWarnings(Path(sys.prefix)/'Lib/site-packages/pypdf')
    counter.install()
    report = {'format':'ARKS_PDF_EXTRACTION_V1_1','source_id':request['source_id'],
              'source_sha256':request['source_sha256'],'source_bytes':request['source_bytes'],
              'extractor':cfg,'status':'FAILED','code':None,'total_physical_pages':None,
              'coverage':'UNKNOWN','pages':[],'layout_semantics':'NOT_QUALIFIED',
              'audit_forbidden_events':forbidden_events,
              'document_warnings':counter.document_warnings,'document_warning_count':0,
              'document_warning_review_status':'NOT_ASSESSED','document_warning_impact_status':'INDETERMINATE'}
    alt=None;pdfium=None;miner_extract=None;reviews={}
    if passive:report['execution_counts']={'pypdf_text_calls':0,'pdfium_text_calls':0,'renders':0,'pypdf_openings':0,'pdfium_openings':0}
    try:
        with counter.scope('document_scope'):
            import pypdf
            if pypdf.__version__!='6.19.0' or not Path(pypdf.__file__).is_relative_to(Path(sys.prefix)/'Lib/site-packages/pypdf'):
                raise RuntimeError('PDF_RUNTIME_IDENTITY')
            raw = (folder/'input.pdf').read_bytes()
            if not 0<len(raw)<=100*1024**2 or len(raw)!=request['source_bytes'] or sha256(raw)!=request['source_sha256']:
                raise RuntimeError('PDF_SOURCE_VERSION_MISMATCH')
            reader = pypdf.PdfReader(io.BytesIO(raw),strict=True)
            if passive:report['execution_counts']['pypdf_openings']+=1
            if reader.is_encrypted:
                raise RuntimeError('PDF_ENCRYPTED_UNSUPPORTED')
            root = reader.root_object
            if not passive and any(key in root for key in ('/OpenAction','/AA','/AcroForm')):
                raise RuntimeError('PDF_ACTIVE_OR_FORM_CONTENT_UNSUPPORTED')
            names = root.get('/Names')
            if not passive and names and any(key in names.get_object() for key in ('/JavaScript','/EmbeddedFiles')):
                raise RuntimeError('PDF_ACTIVE_OR_EMBEDDED_CONTENT_UNSUPPORTED')
            declared = root['/Pages'].get('/Count')
            if not isinstance(declared,int) or not 1<=declared<=(2048 if passive else 300):
                raise RuntimeError('PDF_DECLARED_PAGE_COUNT_UNSUPPORTED')
            total = len(reader.pages)
            if not 1<=total<=(2048 if passive else 300) or total!=declared:
                raise RuntimeError('PDF_PAGE_TREE_COUNT_MISMATCH')
            report['total_physical_pages']=total
            selection=params.get('selection')
            excluded={}
            if selection is not None:
                from aurum_arks.doc_pdf_scope import validate_scope
                validate_scope(selection,request['source_id'],request['source_sha256'])
                if selection['total_physical_pages']!=total:
                    raise RuntimeError('PDF_SCOPE_PAGE_COUNT_MISMATCH')
                excluded={p['physical_page']:p for p in selection['excluded_pages']}
            if passive:
                object_proof=None
                if selection.get('passive_object_proof_sha256'):
                    proof_path=folder/'PASSIVE_OBJECT_PROOF.private.json'
                    if not 0<proof_path.stat().st_size<=4*1024**2:raise RuntimeError('PDF_PASSIVE_OBJECT_PROOF_SIZE')
                    object_proof=strict_loads(proof_path.read_bytes())
                    if fingerprint(object_proof)!=selection['passive_object_proof_sha256'] or object_proof.get('source_id')!=request['source_id'] or object_proof.get('source_sha256')!=request['source_sha256']:raise RuntimeError('PDF_PASSIVE_OBJECT_PROOF_IDENTITY')
                report['passive_controls']=passive_controls(reader,object_proof)
                pdfium=passive_pdfium();alt=pdfium.PdfDocument(raw)
                report['execution_counts']['pdfium_openings']+=1
                if len(alt)!=total:raise RuntimeError('PDF_INDEPENDENT_PAGE_COUNT_MISMATCH')
                report['pdfium_build_flags']=[]
                if cfg['native_reader'] in ('PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
                    report['native_document_warnings']=[]
                    if cfg['native_reader'] in ('PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
                        table=Path(sys.prefix)/'Lib/site-packages/pypdf/_codecs/adobe_glyphs.py'
                        if sha256(table.read_bytes())!=cfg.get('declared_glyph_table_sha256'):raise RuntimeError('PDF_GLYPH_TABLE_IDENTITY')
                    if not params.get('structural_only'):
                        if cfg['native_reader']=='PDFMINER_REVIEWED_PAGES_V5':
                            from aurum_arks import doc_pdf_review
                            if sha256(Path(doc_pdf_review.__file__).read_bytes())!=cfg['review_adapter_sha256']:raise RuntimeError('PDF_REVIEW_ADAPTER_IDENTITY')
                            review_path=folder/'REVIEWED_PAGES.private.json'
                            if not 0<review_path.stat().st_size<=12*1024**2:raise RuntimeError('PDF_REVIEW_BUNDLE_SIZE')
                            bundle=strict_loads(review_path.read_bytes())
                            if fingerprint(bundle)!=cfg['review_bundle_fingerprint']:raise RuntimeError('PDF_REVIEW_BUNDLE_IDENTITY')
                            reviews=doc_pdf_review.validate_bundle(bundle,selection)
                        miner_extract=passive_pdfminer(raw,total,report,cfg['native_reader'] in ('PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'),reviews)
                        report['execution_counts'].update(pdfminer_openings=1,pdfminer_text_calls=0)
        text_total=0
        structural_only=passive and params.get('structural_only') is True
        if render_page is not None:
            if not 1<=render_page<=total:raise RuntimeError('PDF_RENDER_PAGE_SCOPE')
            ap=alt[render_page-1]
            try:
                width,height=ap.get_size();scale=min(1.5,2400/max(width,height))
                if not 0<width<=4000 or not 0<height<=4000 or width*height*scale**2>8000000:
                    raise RuntimeError('PDF_RENDER_BOUND')
                bitmap=ap.render(scale=scale,may_draw_forms=False,draw_annots=True,
                                force_bitmap_format=pdfium.raw.FPDFBitmap_BGR,rev_byteorder=True)
                try:
                    if bitmap.n_channels!=3 or bitmap.mode!='RGB':raise RuntimeError('PDF_RENDER_FORMAT')
                    w,h=bitmap.width,bitmap.height;buffer=bytes(bitmap.buffer)
                    rows=[buffer[y*bitmap.stride:y*bitmap.stride+w*3] for y in range(h)]
                    pixels=b''.join(rows)
                    def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
                    png=(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,2,0,0,0))
                         +chunk(b'IDAT',zlib.compress(b''.join(b'\0'+r for r in rows),6))+chunk(b'IEND',b''))
                    if len(png)>8*1024**2:raise RuntimeError('PDF_RENDER_SIZE')
                    (folder/'render.png').write_bytes(png)
                    report['render']={'physical_page':render_page,'width':w,'height':h,'scale_ratio':list(scale.as_integer_ratio()),
                        'png_sha256':sha256(png),'pixel_sha256':sha256(pixels),'all_rgb_white':all(x==255 for x in pixels),
                        'forms_initialized':False,'document_actions_executed':0,'text_extraction_calls':0}
                    report['execution_counts']['renders']+=1
                finally:bitmap.close()
            finally:ap.close()
        for number in ([] if structural_only else range(1,total+1)):
            item={'physical_page':number,'status':'NOT_PROCESSED','text':None,'text_sha256':None,
                  'code':None,'warning_count':0,'page_warning_count':0,
                  'page_warnings':counter.page_events(number),'printed_page_label':'NOT_READ'}
            report['pages'].append(item)
            if number in excluded:
                item.update(status='OPERATOR_EXCLUDED',code=excluded[number]['code'],
                            locator_status='PDF_PAGE_NOT_EXTRACTED',
                            exclusion_decision_reference=excluded[number]['decision_reference'])
                continue  # No page access or extraction for an operator-excluded page.
            if number>params['max_pages']:
                item.update(status='NOT_PROCESSED_LIMIT',code='PDF_PAGE_LIMIT'); continue
            try:
                with counter.scope('page_scope',number):
                    page=reader.pages[number-1]
                    if '/AA' in page:
                        raise RuntimeError('PDF_PAGE_ACTION_UNSUPPORTED')
                    contents=page.get_contents()
                    if contents is not None and len(contents.get_data())>params['max_content_bytes']:
                        raise RuntimeError('PDF_PAGE_CONTENT_LIMIT')
                    effective_reader=selection.get('native_fallback_pages',{}).get(str(number),cfg.get('native_reader')) if passive else None
                    if passive and 'native_fallback_pages' in selection:item['native_reader']=effective_reader
                    if passive and effective_reader in ('PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
                        text,metrics=miner_extract(number,params['max_page_characters']);item.update(metrics)
                        report['execution_counts']['pdfminer_text_calls']+=1
                    elif passive and effective_reader=='PDFIUM_PASSIVE_V2':
                        ap=alt[number-1]
                        try:
                            tp=ap.get_textpage()
                            try:
                                count=tp.count_chars()
                                if count>params['max_page_characters']:raise RuntimeError('PDF_EXTRACTED_TEXT_LIMIT')
                                text=tp.get_text_range(0,count,errors='strict')
                                report['execution_counts']['pdfium_text_calls']+=1
                                item['native_character_count']=count
                                item['unicode_mapping_errors']=sum(pdfium.raw.FPDFText_HasUnicodeMapError(tp,i)!=0 for i in range(count))
                                excluded=[];nonbmp=0;invalid_native=0
                                for i in range(count):
                                    codepoint=pdfium.raw.FPDFText_GetUnicode(tp,i)
                                    generated=pdfium.raw.FPDFText_IsGenerated(tp,i)==1
                                    nonbmp+=codepoint>65535
                                    invalid_native+=not generated and (codepoint==0 or codepoint==65533 or (codepoint<32 and codepoint not in (9,10,13)))
                                    if pdfium.raw.FPDFText_GetTextIndexFromCharIndex(tp,i)==-1 and not generated and not chr(codepoint).isspace():excluded.append((i,codepoint))
                                item['native_excluded_nonwhitespace_count']=len(excluded)
                                item['native_excluded_positions_sha256']=sha256(json.dumps(excluded).encode())
                                item['native_nonbmp_count']=nonbmp
                                item['native_invalid_codepoint_count']=invalid_native
                            finally:tp.close()
                        finally:ap.close()
                    else:
                        text=page.extract_text(orientations=(0,90,180,270),extraction_mode='plain')
                        if passive:report['execution_counts']['pypdf_text_calls']+=1
                    if number in reviews:
                        review=reviews[number]
                        if sha256(item['review_input_text'].encode())!=review['native_text_sha256']:raise RuntimeError('PDF_REVIEW_NATIVE_CHANGED')
                        ap=alt[number-1]
                        try:
                            if review['method']==doc_pdf_review.FACSIMILE:
                                measured,png=doc_pdf_review.render_facsimile(pdfium,ap);item['facsimile_png_sha256']=sha256(png)
                                if item['facsimile_png_sha256']!=review['content']['png_sha256']:raise RuntimeError('PDF_FACSIMILE_RENDER_CHANGED')
                                item['source_page_images']=doc_pdf_review.source_page_images(page);text=doc_pdf_review.facsimile_text(review['content'])
                            else:measured=doc_pdf_review.render_identity(pdfium,ap)
                            report['execution_counts']['renders']+=1
                            if measured!=review['render']:raise RuntimeError('PDF_REVIEW_RENDER_CHANGED')
                            if review['method']==doc_pdf_review.OCR:
                                if text!='':raise RuntimeError('PDF_REVIEW_NATIVE_TEXT_PRESENT')
                                tp=ap.get_textpage()
                                try:item['review_second_native_characters']=len(tp.get_text_range());report['execution_counts']['pdfium_text_calls']+=1
                                finally:tp.close()
                                item['review_pypdf_characters']=len(page.extract_text(orientations=(0,90,180,270),extraction_mode='plain'));report['execution_counts']['pypdf_text_calls']+=1
                                if item['review_second_native_characters'] or item['review_pypdf_characters']:raise RuntimeError('PDF_REVIEW_OTHER_NATIVE_TEXT_PRESENT')
                                text=review['content']['text']
                        finally:ap.close()
                        item.update(reviewed_page=review,review_render=measured,text=text)
                        doc_pdf_review.verify_page(item,review)
                item['warning_count']=item['page_warning_count']=len(item['page_warnings'])
                if not isinstance(text,str): raise RuntimeError('PDF_INVALID_TEXT_RESULT')
                if len(text)>params['max_page_characters'] or text_total+len(text)>params['max_document_characters']:
                    raise RuntimeError('PDF_EXTRACTED_TEXT_LIMIT')
                text.encode('utf-8',errors='strict')
                text_total+=len(text)
                if not text.strip():
                    if passive and len(text)==0:
                        native=page.extract_text(orientations=(0,90,180,270),extraction_mode='plain')
                        report['execution_counts']['pypdf_text_calls']+=1
                        ap=alt[number-1]
                        try:
                            tp=ap.get_textpage()
                            try:
                                alternate=tp.get_text_range();report['execution_counts']['pdfium_text_calls']+=1
                            finally:tp.close()
                            width,height=ap.get_size()
                            if not 0<width*height<=16000000 or width>4000 or height>4000:raise RuntimeError('PDF_RENDER_BOUND')
                            bitmap=ap.render(scale=1,may_draw_forms=False,draw_annots=True,force_bitmap_format=pdfium.raw.FPDFBitmap_BGR,rev_byteorder=True)
                            report['execution_counts']['renders']+=1
                            try:
                                pixels=b''.join(bytes(bitmap.buffer)[y*bitmap.stride:y*bitmap.stride+bitmap.width*3] for y in range(bitmap.height))
                                white=all(v==255 for v in pixels)
                            finally:bitmap.close()
                        finally:ap.close()
                        item['blank_verification']={'pypdf_characters':len(native),'pdfium_characters':len(alternate),'all_rgb_white':white,'pixel_sha256':sha256(pixels)}
                        if len(native)==len(alternate)==0 and white:
                            item.update(status='BLANK_VERIFIED',code=None);continue
                    item.update(status='NO_EXTRACTABLE_TEXT',code='PDF_NO_TEXT_NO_OCR')
                    continue
                if (item['warning_count'] or any(item.get(k,0) for k in ('unicode_mapping_errors','native_excluded_nonwhitespace_count','native_nonbmp_count','native_invalid_codepoint_count','native_undefined_glyphs','native_empty_glyphs','native_warning_count','native_unresolved_declarations'))
                        or '\ufffd' in text or any(ord(c)<32 and c not in '\r\n\t' for c in text)):
                    item.update(status='EXTRACTION_UNCERTAIN',code='PDF_WARNINGS_OR_INVALID_GLYPHS')
                    if passive:item['raw_text_rejected']=text
                    continue
                item.update(status='TEXT_EXTRACTED_UNREVIEWED',text=text,text_sha256=sha256(text.encode('utf-8')))
            except MemoryError:
                item.update(status='PAGE_ERROR',code='PDF_MEMORY_LIMIT')
            except Exception as error:
                code=str(error) if isinstance(error,RuntimeError) and str(error).startswith('PDF_') else 'PDF_PAGE_EXTRACTION_ERROR'
                item.update(status='PAGE_ERROR',code=code,error_category=type(error).__name__)
            finally:
                item['warning_count']=item['page_warning_count']=len(item['page_warnings'])
        successful=sum(p['status']=='TEXT_EXTRACTED_UNREVIEWED' for p in report['pages'])
        blank=sum(p['status']=='BLANK_VERIFIED' for p in report['pages']) if passive else 0
        report['coverage']={'pages_total':total,'pages_text_extracted':successful,'pages_not_text_covered':total-successful}
        report['status']='TEXT_EXTRACTED_UNREVIEWED' if successful+blank==total else 'PARTIAL_EXTRACTION' if successful else 'INSUFFICIENT_EXTRACTION'
        report['code']=None if successful+blank==total else 'PDF_PAGES_NOT_TEXT_COVERED'
        if structural_only:report.update(status='PASSIVE_STRUCTURE_VERIFIED',code=None,coverage='NOT_EXTRACTED_STRUCTURAL_ONLY')
        if render_page is not None:report.update(status='PASSIVE_RENDER_VERIFIED',code=None,coverage='NOT_TEXT_EXTRACTED_RENDER_ONLY')
    except MemoryError:
        report.update(status='FAILED',code='PDF_MEMORY_LIMIT')
    except Exception as error:
        code=str(error) if isinstance(error,RuntimeError) and str(error).startswith('PDF_') else 'PDF_PARSE_ERROR'
        report.update(status='FAILED',code=code,error_category=type(error).__name__)
    finally:
        if alt is not None:alt.close()
    if forbidden_events:
        report.update(status='FAILED',code='PDF_FORBIDDEN_OPERATION',pages=[],coverage='UNKNOWN')
    report['document_warning_count']=len(report['document_warnings'])
    report['document_warning_review_status']='REQUIRED' if report['document_warning_count'] else 'NONE'
    report['document_warning_impact_status']='INDETERMINATE' if report['document_warning_count'] else 'NOT_APPLICABLE'
    report['extraction_id']=fingerprint(report)
    encoded=json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2).encode('utf-8')
    if len(encoded)>(64 if passive else 8)*1024**2: return 126
    with (folder/'worker-result.tmp').open('xb') as stream:
        stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    os.replace(folder/'worker-result.tmp',folder/'worker-result.json')
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as error:
        # Technical frames only. Preserve nonzero exit and any partial payload.
        frames=[];tb=error.__traceback__
        while tb is not None:
            frames.append({'module':Path(tb.tb_frame.f_code.co_filename).name,
                           'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno})
            tb=tb.tb_next
        folder=Path(sys.argv[1]).absolute() if len(sys.argv)==2 else None
        if folder is not None and folder.is_relative_to(Path(__file__).resolve().parents[2]/'reports'):
            with (folder/'FATAL_TECHNICAL.json').open('x',encoding='utf8') as out:
                json.dump({'exception_type':type(error).__name__,'frames':frames,'document_text_included':False},out)
        raise SystemExit(125)
