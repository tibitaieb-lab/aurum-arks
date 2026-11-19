"""Trusted, version-bound reviewed page derivatives; never PDF-supplied authority.

Raw OCR is not a publication permission. A reviewed whole-page transcription or
explicit non-text diagram representation is bound to source, native output and
passive render. This contract does not infer mathematical meaning from shapes.
"""
from copy import deepcopy
import difflib
import re
from .serialization import ContractError,fingerprint,sha256,strict_loads,business_bytes
from .paths import confined
from .doc_inventory import local_regular

READER='PDFMINER_REVIEWED_PAGES_V5'
VERSION='ARKS_REVIEWED_PAGE_V1'
OCR='OCR_ASSISTED_VISUAL_TRANSCRIPTION_V1'
GRAPHIC='SOURCE_GLYPH_DIAGRAM_OBJECTS_V1'
GROUP='SOURCE_DECLARED_COMPONENT_GROUPS_V1'
MASK_GROUP='SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2'
UNINTERPRETED='SOURCE_UNINTERPRETED_GLYPH_OBJECTS_V1'
FACSIMILE='SOURCE_PAGE_FACSIMILE_V1'
MAX_ARTIFACT=2*1024**2
def require(condition,code):
 if not condition:raise ContractError(code)
def is_hash(value):return type(value) is str and re.fullmatch('[a-f0-9]{64}',value) is not None
def references(scope):
 refs=scope.get('reviewed_pages')
 require(type(refs) is list and 1<=len(refs)<=128,'PDF_REVIEW_REFERENCE_COUNT')
 pages=[]
 for ref in refs:
  require(type(ref) is dict and set(ref)=={'physical_page','artifact_sha256'} and type(ref['physical_page']) is int and ref['physical_page'] in scope['included_pages'] and is_hash(ref['artifact_sha256']),'PDF_REVIEW_REFERENCE')
  pages.append(ref['physical_page'])
 require(pages==sorted(set(pages)),'PDF_REVIEW_PAGE_PARTITION');return refs
def validate(artifact,scope,ref):
 require(type(artifact) is dict and len(business_bytes(artifact))<=MAX_ARTIFACT and fingerprint(artifact)==ref['artifact_sha256'],'PDF_REVIEW_ARTIFACT_IDENTITY')
 base={'version','source_id','source_sha256','physical_page','method','native_text_sha256','render','review','visual_regions','content'}
 require(set(artifact)==base and artifact['version']==VERSION and artifact['source_id']==scope['source_id'] and artifact['source_sha256']==scope['source_sha256'] and artifact['physical_page']==ref['physical_page'],'PDF_REVIEW_SOURCE_VERSION')
 require(is_hash(artifact['native_text_sha256']) and artifact['method'] in (OCR,GRAPHIC,GROUP,MASK_GROUP,UNINTERPRETED,FACSIMILE),'PDF_REVIEW_METHOD')
 render=artifact['render'];require(type(render) is dict and set(render)=={'pixel_sha256','width','height','scale_ratio'} and is_hash(render['pixel_sha256']) and all(type(render[k]) is int and 1<=render[k]<=6000 for k in ('width','height')) and type(render['scale_ratio']) is list and len(render['scale_ratio'])==2 and all(type(v) is int and v>0 for v in render['scale_ratio']),'PDF_REVIEW_RENDER')
 review=artifact['review'];require(type(review) is dict and set(review)=={'author','authority','proof_reference','status','semantic_scope'} and all(type(v) is str and bool(v) for v in review.values()) and review['status']=='WHOLE_TARGET_VERIFIED' and review['semantic_scope']=='NO_GENERAL_SCIENTIFIC_OR_FORMULA_CERTIFICATION','PDF_REVIEW_AUTHORITY')
 require(type(artifact['visual_regions']) is list and len(artifact['visual_regions'])<=32,'PDF_REVIEW_VISUAL_REGIONS')
 content=artifact['content'];require(type(content) is dict,'PDF_REVIEW_CONTENT')
 if artifact['method']==OCR:
  require(set(content)=={'raw_ocr','text','text_sha256','corrections','segments'},'PDF_REVIEW_OCR_FIELDS')
  raw=content['raw_ocr'];text=content['text'];require(type(raw) is dict and type(raw.get('text')) is str and raw.get('engine')=='Windows.Media.Ocr' and raw.get('language')=='fr-FR' and raw.get('qualified') is False and is_hash(raw.get('artifact_sha256')),'PDF_REVIEW_OCR_RAW')
  require(type(text) is str and 0<len(text)<=200000 and text.strip() and sha256(text.encode())==content['text_sha256'] and '\ufffd' not in text and '\ufffc' not in text and not any(ord(c)<32 and c not in '\r\n\t' for c in text),'PDF_REVIEW_OCR_TEXT')
  require(content['corrections']==corrections(raw['text'],text),'PDF_REVIEW_OCR_CORRECTIONS')
  segments=content['segments'];require(type(segments) is list and bool(segments),'PDF_REVIEW_OCR_SEGMENTS');position=0
  for s in segments:
   require(set(s)=={'start','end','box','status'} and s['status']=='VISUALLY_VERIFIED' and s['start']==position and type(s['end']) is int and position<s['end']<=len(text),'PDF_REVIEW_OCR_SEGMENT_SEQUENCE')
   box=s['box'];require(type(box) is list and len(box)==4 and all(type(v) is int for v in box) and 0<=box[0]<box[2]<=render['width'] and 0<=box[1]<box[3]<=render['height'],'PDF_REVIEW_OCR_SEGMENT_BOUNDS');position=s['end']
  require(position==len(text),'PDF_REVIEW_OCR_TEXT_COVERAGE')
  require(artifact['native_text_sha256']==sha256(b''),'PDF_REVIEW_OCR_NATIVE_TEXT_EXISTS')
 elif artifact['method']==FACSIMILE:
  require(set(content)=={'native_text','caption','caption_regions','source_images','png_sha256'} and type(content['native_text']) is str and sha256(content['native_text'].encode())==artifact['native_text_sha256'] and is_hash(content['png_sha256']),'PDF_FACSIMILE_CONTENT')
  require(type(content['caption']) is str and len(content['caption'])<=4096 and type(content['caption_regions']) is list and len(content['caption_regions'])<=16,'PDF_FACSIMILE_CAPTION')
  require(content['caption']=='\n'.join(c['text'] for c in content['caption_regions']),'PDF_FACSIMILE_CAPTION_IDENTITY')
  for c in content['caption_regions']:
   require(set(c)=={'text','box'} and type(c['text']) is str and bool(c['text'].strip()) and type(c['box']) is list and len(c['box'])==4 and all(type(n) is int for n in c['box']) and 0<=c['box'][0]<c['box'][2]<=render['width'] and 0<=c['box'][1]<c['box'][3]<=render['height'],'PDF_FACSIMILE_CAPTION_REGION')
  require(type(content['source_images']) is list and 1<=len(content['source_images'])<=1024,'PDF_FACSIMILE_SOURCE_IMAGES')
  for im in content['source_images']:require(set(im)=={'resource_path','object_id','generation','width','height','encoded_stream_sha256'} and type(im['resource_path']) is str and is_hash(im['encoded_stream_sha256']) and all(type(im[k]) is int and im[k]>=0 for k in ('object_id','generation','width','height')) and im['width']*im['height']>0,'PDF_FACSIMILE_IMAGE_PROVENANCE')
 elif artifact['method']==UNINTERPRETED:
  require(set(content)=={'resources','components','classification'} and content['classification']=='SOURCE_GLYPH_SHAPES_PRESERVED_UNICODE_UNKNOWN','PDF_UNINTERPRETED_CLASSIFICATION')
  resources=content['resources'];components=content['components']
  require(type(resources) is list and 1<=len(resources)<=16 and type(components) is list and 1<=len(components)<=2048,'PDF_UNINTERPRETED_BOUND')
  for r in resources:
   require(set(r) in ({'program_sha256','cids'},{'program_sha256','cids','resource_kind','font_dictionary'}) and is_hash(r['program_sha256']) and type(r['cids']) is list and r['cids']==sorted(set(r['cids'])) and 1<=len(r['cids'])<=1024 and all(type(n) is int and 0<=n<=65535 for n in r['cids']),'PDF_UNINTERPRETED_RESOURCE')
   if 'resource_kind' in r:
    import json
    raw=json.dumps(r['font_dictionary'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    require(r['resource_kind']=='SOURCE_FONT_DICTIONARY' and r['font_dictionary'].get('contract')=='SOURCE_SCOPED_FONT_DICTIONARY_V1' and sha256(raw)==r['program_sha256'],'PDF_FONT_DICTIONARY_REFERENCE_HASH')
  ordinals=[]
  for c in components:
   require(set(c)=={'source_ordinal','cid','program_sha256','matrix','bbox','raw_text'} and type(c['source_ordinal']) is int and c['source_ordinal']>=0 and any(c['program_sha256']==r['program_sha256'] and c['cid'] in r['cids'] for r in resources) and hex_vector(c['matrix'],6) and hex_vector(c['bbox'],4) and type(c['raw_text']) is str and 1<=len(c['raw_text'])<=32,'PDF_UNINTERPRETED_COMPONENT')
   ordinals.append(c['source_ordinal'])
  require(ordinals==sorted(set(ordinals)),'PDF_UNINTERPRETED_ORDER')
 elif artifact['method']==GRAPHIC:
  require(set(content)=={'resources','expected_occurrences','outline_proof_sha256','classification'} and content['classification']=='NON_TEXT_DIAGRAM_STROKES' and is_hash(content['outline_proof_sha256']),'PDF_REVIEW_GRAPHIC_CLASSIFICATION')
  resources=content['resources'];require(type(resources) is list and 1<=len(resources)<=4 and type(content['expected_occurrences']) is int and 1<=content['expected_occurrences']<=512,'PDF_REVIEW_GRAPHIC_BOUND')
  for resource in resources:
   require(set(resource)=={'program_sha256','cids'} and is_hash(resource['program_sha256']) and type(resource['cids']) is list and resource['cids']==sorted(set(resource['cids'])) and resource['cids'] and all(type(v) is int and 0<=v<=255 for v in resource['cids']),'PDF_REVIEW_GRAPHIC_RESOURCE')
 else:
  masked=artifact['method']==MASK_GROUP
  expected_fields={'resources','expected_occurrences','outline_proof_sha256','classification','components','groups'}
  if masked:expected_fields.add('image_connectors')
  require(set(content)==expected_fields and content['classification']==('CONNECTED_SOURCE_GRAPHIC_GROUPS_WITH_MASKS_NOT_SEMANTIC_FORMULA' if masked else 'CONNECTED_SOURCE_GRAPHIC_GROUPS_NOT_SEMANTIC_FORMULA') and is_hash(content['outline_proof_sha256']),'PDF_REVIEW_GROUP_CLASSIFICATION')
  resources=content['resources'];require(type(resources) is list and 1<=len(resources)<=4,'PDF_REVIEW_GROUP_RESOURCES')
  for r in resources:require(set(r)=={'program_sha256','cids'} and is_hash(r['program_sha256']) and type(r['cids']) is list and r['cids']==sorted(set(r['cids'])) and r['cids'] and all(type(n) is int and 0<=n<=255 for n in r['cids']),'PDF_REVIEW_GROUP_RESOURCE')
  components=content['components'];require(type(components) is list and 1<=len(components)<=512 and content['expected_occurrences']==len(components),'PDF_REVIEW_GROUP_COMPONENT_COUNT');ordinals=[]
  for c in components:
   require(set(c)=={'source_ordinal','cid','program_sha256','matrix','glyph_name'} and c['glyph_name'] in ('radicaltp','radicalvertex','radicalbt','bracehtipupleft','bracehtipdownright','bracehtipdownleft','bracehtipupright') and type(c['source_ordinal']) is int and c['source_ordinal']>=0 and any(c['program_sha256']==r['program_sha256'] and c['cid'] in r['cids'] for r in resources) and hex_vector(c['matrix'],6),'PDF_REVIEW_GROUP_COMPONENT');ordinals.append(c['source_ordinal'])
  require(ordinals==sorted(set(ordinals)),'PDF_REVIEW_GROUP_SOURCE_ORDER');groups=content['groups'];require(type(groups) is list and 1<=len(groups)<=128,'PDF_REVIEW_GROUP_COUNT');covered=[];rule_ids=[]
  image_ids=[]
  if masked:
   masks=content['image_connectors'];require(type(masks) is list and 2<=len(masks)<=256,'PDF_REVIEW_MASK_COUNT')
   for mask in masks:validate_mask(mask)
   require([m['image_ordinal'] for m in masks]==sorted({m['image_ordinal'] for m in masks}),'PDF_REVIEW_MASK_ORDER')
  for g in groups:
   group_fields={'kind','component_ordinals','rule_ordinals','ink_bbox','geometric_region','neighbor_glyph_ordinals','relation','unicode_inferred','semantic_formula_indexing'}
   if masked:group_fields.add('image_ordinals')
   require(set(g)==group_fields and g['kind'] in (('DECLARED_HORIZONTAL_BRACE_COMPONENT_RUN',) if masked else ('DECLARED_RADICAL_COMPONENT_RUN','DECLARED_HORIZONTAL_BRACE_COMPONENT_RUN')) and g['relation']=='GEOMETRIC_ENVELOPE_NOT_SEMANTIC_OPERAND' and g['unicode_inferred'] is False and g['semantic_formula_indexing'] is False,'PDF_REVIEW_GROUP_SCOPE')
   for name in ('component_ordinals','rule_ordinals','neighbor_glyph_ordinals'):require(type(g[name]) is list and g[name]==sorted(set(g[name])) and all(type(n) is int and n>=0 for n in g[name]),'PDF_REVIEW_GROUP_RELATION')
   if masked:
    require(g['rule_ordinals']==[] and type(g['image_ordinals']) is list and len(g['image_ordinals'])==2 and g['image_ordinals']==sorted(set(g['image_ordinals'])) and all(type(n) is int and n>=0 for n in g['image_ordinals']),'PDF_REVIEW_MASK_GROUP_GEOMETRY');image_ids+=g['image_ordinals']
   require(len(g['component_ordinals'])>=3 and (masked or bool(g['rule_ordinals'])) and hex_vector(g['ink_bbox'],4) and hex_vector(g['geometric_region'],4),'PDF_REVIEW_GROUP_GEOMETRY');covered+=g['component_ordinals'];rule_ids+=g['rule_ordinals']
   names=[next(c['glyph_name'] for c in components if c['source_ordinal']==n) for n in g['component_ordinals'] if n in ordinals]
   require(len(names)==len(g['component_ordinals']) and (names==['bracehtipupleft','bracehtipdownright','bracehtipdownleft','bracehtipupright'] if g['kind']=='DECLARED_HORIZONTAL_BRACE_COMPONENT_RUN' else names[0]=='radicaltp' and names[-1]=='radicalbt' and all(n=='radicalvertex' for n in names[1:-1])),'PDF_REVIEW_GROUP_DECLARED_SEQUENCE')
  require(sorted(covered)==ordinals and len(covered)==len(set(covered)) and len(rule_ids)==len(set(rule_ids)),'PDF_REVIEW_GROUP_PARTITION')
  if masked:require(sorted(image_ids)==[m['image_ordinal'] for m in masks] and len(image_ids)==len(set(image_ids)),'PDF_REVIEW_MASK_PARTITION')
 return deepcopy(artifact)

def validate_mask(mask):
 require(type(mask) is dict and set(mask)=={'image_ordinal','following_glyph_ordinal','width','height','bits_per_component','image_mask','decode','decoded_sha256','figure_matrix','bbox'},'PDF_REVIEW_MASK_FIELDS')
 require(all(type(mask[k]) is int and mask[k]>=0 for k in ('image_ordinal','following_glyph_ordinal')) and all(type(mask[k]) is int and mask[k]==1 for k in ('width','height','bits_per_component')) and mask['image_mask'] is True,'PDF_REVIEW_MASK_PROFILE')
 require(mask['decode'] in (None,[0,1]) and mask['decoded_sha256']==sha256(b'\x00') and hex_vector(mask['figure_matrix'],6) and hex_vector(mask['bbox'],4),'PDF_REVIEW_MASK_PAINT')
 m=[float.fromhex(x) for x in mask['figure_matrix']];b=[float.fromhex(x) for x in mask['bbox']]
 require(m[1]==m[2]==0 and m[0]!=0 and m[3]!=0 and b==[min(m[4],m[4]+m[0]),min(m[5],m[5]+m[3]),max(m[4],m[4]+m[0]),max(m[5],m[5]+m[3])],'PDF_REVIEW_MASK_TRANSFORM')
 return True

def hex_vector(value,n):
 return type(value) is list and len(value)==n and all(type(v) is str and re.fullmatch(r'-?0x[0-9a-f.]+p[+-][0-9]+',v) for v in value)
def corrections(before,after):
 return [{'operation':op,'raw_range':[i,j],'derived_range':[a,b],'before_sha256':sha256(before[i:j].encode()),'after_sha256':sha256(after[a:b].encode())} for op,i,j,a,b in difflib.SequenceMatcher(None,before,after,autojunk=False).get_opcodes() if op!='equal']
def load_bundle(root,scope):
 result=[]
 for ref in references(scope):
  path=confined(root,'extractions/reviewed/'+ref['artifact_sha256']+'.json');require(0<local_regular(path).st_size<=MAX_ARTIFACT,'PDF_REVIEW_FILE_SIZE');raw=path.read_bytes();require(sha256(raw)==ref['artifact_sha256'],'PDF_REVIEW_FILE_HASH');artifact=strict_loads(raw);validate(artifact,scope,ref);result.append(artifact)
 return result
def validate_bundle(bundle,scope):
 refs=references(scope);require(type(bundle) is list and len(bundle)==len(refs),'PDF_REVIEW_BUNDLE_COUNT')
 return {r['physical_page']:validate(a,scope,r) for a,r in zip(bundle,refs)}
def render_identity(pdfium,page):
 width,height=page.get_size();scale=min(1.5,2400/max(width,height))
 require(0<width<=4000 and 0<height<=4000 and width*height*scale**2<=8000000,'PDF_REVIEW_RENDER_BOUND')
 bitmap=page.render(scale=scale,may_draw_forms=False,draw_annots=True,force_bitmap_format=pdfium.raw.FPDFBitmap_BGR,rev_byteorder=True)
 try:
  require(bitmap.n_channels==3 and bitmap.mode=='RGB','PDF_REVIEW_RENDER_FORMAT');data=bytes(bitmap.buffer);pixels=b''.join(data[y*bitmap.stride:y*bitmap.stride+bitmap.width*3] for y in range(bitmap.height));return {'pixel_sha256':sha256(pixels),'width':bitmap.width,'height':bitmap.height,'scale_ratio':list(scale.as_integer_ratio())}
 finally:bitmap.close()
def facsimile_text(content):
 return content['native_text']+'\n'+(content['caption']+'\n' if content['caption'] else '')+'\ufffc'

def source_page_images(page):
 result=[];seen=set()
 def walk(resources,prefix='',depth=0):
  require(depth<=16,'PDF_FACSIMILE_RESOURCE_DEPTH');resources=resources.get_object() if hasattr(resources,'get_object') else resources
  objects=resources.get('/XObject',{});objects=objects.get_object() if hasattr(objects,'get_object') else objects
  for name,reference in sorted(objects.items()):
   require(len(result)<=1024,'PDF_FACSIMILE_IMAGE_BOUND');obj=reference.get_object();path=prefix+str(name)
   if str(obj.get('/Subtype'))=='/Image':
    encoded=obj._data;require(type(encoded) is bytes and len(encoded)<=32*1024**2,'PDF_FACSIMILE_STREAM_BOUND')
    result.append({'resource_path':path,'object_id':reference.idnum,'generation':reference.generation,'width':int(obj['/Width']),'height':int(obj['/Height']),'encoded_stream_sha256':sha256(encoded)})
   elif str(obj.get('/Subtype'))=='/Form':
    key=(reference.idnum,reference.generation);require(key not in seen,'PDF_FACSIMILE_RESOURCE_CYCLE');seen.add(key);walk(obj.get('/Resources',{}),path+'/',depth+1);seen.remove(key)
 walk(page.get('/Resources',{}));return result

def render_facsimile(pdfium,page):
 import struct,zlib
 width,height=page.get_size();scale=min(1.5,2400/max(width,height));require(0<width<=4000 and 0<height<=4000 and width*height*scale**2<=8000000,'PDF_REVIEW_RENDER_BOUND')
 bitmap=page.render(scale=scale,may_draw_forms=False,draw_annots=True,force_bitmap_format=pdfium.raw.FPDFBitmap_BGR,rev_byteorder=True)
 try:
  require(bitmap.n_channels==3 and bitmap.mode=='RGB','PDF_REVIEW_RENDER_FORMAT');data=bytes(bitmap.buffer);pixels=b''.join(data[y*bitmap.stride:y*bitmap.stride+bitmap.width*3] for y in range(bitmap.height))
  render={'pixel_sha256':sha256(pixels),'width':bitmap.width,'height':bitmap.height,'scale_ratio':list(scale.as_integer_ratio())}
  def chunk(t,b):return struct.pack('>I',len(b))+t+b+struct.pack('>I',zlib.crc32(t+b)&0xffffffff)
  packed=b''.join(b'\0'+pixels[y*bitmap.width*3:(y+1)*bitmap.width*3] for y in range(bitmap.height));png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',bitmap.width,bitmap.height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(packed))+chunk(b'IEND',b'');return render,png
 finally:bitmap.close()

def verify_page(page,artifact):
 require(page.get('reviewed_page')==artifact and page.get('review_render')==artifact['render'],'PDF_REVIEW_PAGE_PROVENANCE')
 raw=page.get('review_input_text');require(type(raw) is str and sha256(raw.encode())==artifact['native_text_sha256'],'PDF_REVIEW_NATIVE_IDENTITY')
 if artifact['method']==FACSIMILE:
  content=artifact['content'];require(page.get('source_page_images')==content['source_images'] and page.get('facsimile_png_sha256')==content['png_sha256'] and page.get('native_image_count',0)>0,'PDF_FACSIMILE_PAGE_PROVENANCE')
  require(page.get('text')==facsimile_text(content) and raw==content['native_text'],'PDF_FACSIMILE_TEXT_IDENTITY')
 elif artifact['method']==OCR:
  require(raw=='' and page.get('review_second_native_characters')==page.get('review_pypdf_characters')==0 and page.get('text')==artifact['content']['text'],'PDF_REVIEW_OCR_QUALIFICATION')
 elif artifact['method'] in (GROUP,MASK_GROUP,UNINTERPRETED):
  if artifact['method']==MASK_GROUP:require(page.get('review_image_connectors')==artifact['content']['image_connectors'],'PDF_REVIEW_MASK_SOURCE_CHANGED')
  glyphs=page.get('graphic_components');expected=artifact['content']['components'];require(type(glyphs) is list and len(glyphs)==len(expected),'PDF_REVIEW_GROUP_COMPLETENESS')
  fields=('source_ordinal','cid','program_sha256','matrix','bbox','raw_text') if artifact['method']==UNINTERPRETED else ('source_ordinal','cid','program_sha256','matrix','glyph_name')
  actual=sorted(({k:g[k] for k in fields} for g in glyphs),key=lambda g:g['source_ordinal']);require(actual==expected,'PDF_REVIEW_GROUP_SOURCE_CHANGED')
  rebuilt=[];raw_end=0;derived_end=0
  for g in glyphs:
   start,end,offset=g['raw_start'],g['raw_end'],g['offset'];require(all(type(n) is int for n in (start,end,offset)) and raw_end<=start<end<=len(raw) and raw[start:end]==g['raw_text'] and hex_vector(g['bbox'],4),'PDF_REVIEW_GROUP_RAW_RANGE')
   prefix=raw[raw_end:start];require(offset==derived_end+len(prefix),'PDF_REVIEW_GROUP_DERIVED_OFFSET');rebuilt.extend((prefix,'\ufffc'));derived_end=offset+1;raw_end=end
  rebuilt.append(raw[raw_end:]);require(page.get('text')==''.join(rebuilt),'PDF_REVIEW_GROUP_LOSS_OR_SUBSTITUTION')
 else:
  glyphs=page.get('graphic_components');require(type(glyphs) is list and len(glyphs)==artifact['content']['expected_occurrences'],'PDF_REVIEW_GRAPHIC_COMPLETENESS')
  resources=artifact['content']['resources'];previous=-1;rebuilt=list(raw)
  for item in glyphs:
   offset=item['offset'];require(type(offset) is int and previous<offset<len(raw) and len(item['raw_text'])==1 and raw[offset]==item['raw_text'],'PDF_REVIEW_GRAPHIC_OFFSET');previous=offset
   require(any(item['program_sha256']==r['program_sha256'] and item['cid'] in r['cids'] for r in resources),'PDF_REVIEW_GRAPHIC_UNAUTHORIZED_RESOURCE')
   require(type(item['matrix']) is list and len(item['matrix'])==6 and type(item['bbox']) is list and len(item['bbox'])==4 and all(type(v) is str and re.fullmatch(r'-?0x[0-9a-f.]+p[+-][0-9]+',v) for v in item['matrix']+item['bbox']),'PDF_REVIEW_GRAPHIC_GEOMETRY')
   rebuilt[offset]='\ufffc'
  require(page.get('text')==''.join(rebuilt),'PDF_REVIEW_GRAPHIC_LOSS_OR_SUBSTITUTION')
 return True
