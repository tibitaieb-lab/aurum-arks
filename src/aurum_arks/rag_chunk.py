"""Evidence-preserving, page-local deterministic chunking."""
import re,unicodedata
from .serialization import fingerprint,sha256
from .provenance import require
VERSION='ARKS_PAGE_BOUNDARIES_V1'
TXT_VERSION='ARKS_RAW_UTF8_METHOD_BOUNDARIES_V1'
TEXT_VERSION='ARKS_RETRIEVAL_NFKC_SPACE_V1'
PARAMETERS={'chunker_version':VERSION,'target_tokens':320,'max_tokens':480,'overlap':32,'boundary_policy':'EVIDENCE_THEN_PARAGRAPH_SENTENCE_LINE_WORD; PAGE_LOCAL; NO_MERGE','tokenizer':'intfloat/multilingual-e5-small/tokenizer.json','retrieval_text_version':TEXT_VERSION}

def retrieval_text(text):
    # Object replacement characters designate nontext, never inferred Unicode.
    return ' '.join(unicodedata.normalize('NFKC',text.replace('\ufffc',' ')).split())

def ranges(text,model):
    if model.count('passage: '+retrieval_text(text))<=PARAMETERS['max_tokens']:return [(0,len(text))]
    boundaries=[m.end() for m in re.finditer(r'\n\s*\n|(?<=[.!?;])\s+|\n',text)]
    words=[m.end() for m in re.finditer(r'\s+',text)]+[len(text)];out=[];start=0
    while start<len(text):
        remaining=text[start:]
        if model.count('passage: '+retrieval_text(remaining))<=PARAMETERS['max_tokens']:end=len(text)
        else:
            low=start+1;high=len(text)
            while low<high:
                mid=(low+high+1)//2
                if model.count('passage: '+retrieval_text(text[start:mid]))<=PARAMETERS['target_tokens']:low=mid
                else:high=mid-1
            candidates=[n for n in boundaries if start<n<=low and n-start>max(32,(low-start)//2)]
            end=max(candidates) if candidates else max((n for n in words if start<n<=low),default=low)
        require(end>start,'CHUNK_BOUNDARY_PROGRESS');out.append((start,end))
        if end==len(text):break
        overlap=[]
        for n in reversed(words):
            if not start<n<end:continue
            if model.count(retrieval_text(text[n:end]))>PARAMETERS['overlap']:break
            overlap.append(n)
        start=min(overlap) if overlap else end
    return out

def chunk_evidence(e,source,metadata,model):
    if e['locator'].get('kind')=='RAW_UTF8_BYTE_RANGE':
        return _text_chunks(e,source,metadata,model)
    from .math_finance import selected,records_for_evidence,chunk_binding,PROFILE
    scientific=selected(metadata)
    text=e['content_exact'];ref=e['locator']['reference'];page=ref['physical_page'];coverage=source['coverage']
    scientific_ranges=records_for_evidence(e,metadata,model) if scientific else None
    method=next((p['method'] for p in coverage.get('reviewed_page_methods',[]) if p['physical_page']==page),'NATIVE_PDF_TEXT')
    cleaned=retrieval_text(text)
    if not cleaned:return [],'NON_TEXT_ACCOUNTED' if '\ufffc' in text else 'EMPTY_ACCOUNTED'
    if method=='SOURCE_PAGE_FACSIMILE_V1' and not metadata.get('verified_caption_pages',{}).get(str(page)):
        return [],'NON_TEXT_ACCOUNTED'
    chunks=[]
    for position,(start,end) in enumerate([(s,t) for s,t,_ in scientific_ranges] if scientific else ranges(text,model)):
        exact=text[start:end];rt=retrieval_text(exact)
        if not rt:continue
        span={'evidence_id':e['evidence_id'],'start':start,'end':end,'evidence_excerpt_sha256':e['excerpt_sha256']}
        identity={'chunker_version':VERSION,'parameters':PARAMETERS,'source_id':source['source_id'],'source_sha256':source['source_sha256'],'spans':[span],'exact_text_sha256':sha256(exact.encode())}
        if scientific:identity.update(chunker_version=PROFILE,scientific_object=chunk_binding(scientific_ranges[position][2],metadata))
        chunks.append({'chunk_id':'chk_'+fingerprint(identity),'chunker_version':VERSION,'source_id':source['source_id'],'source_sha256':source['source_sha256'],'document_version':source['document_version'],'evidence_spans':[span],'page_refs':[{'physical_page':page,'evidence_id':e['evidence_id'],'start':ref['start']+start,'end':ref['start']+end}],'exact_text':exact,'exact_text_sha256':identity['exact_text_sha256'],'retrieval_text':rt,'retrieval_text_sha256':sha256(rt.encode()),'retrieval_text_version':TEXT_VERSION,'position':{'physical_page':page,'evidence_start':ref['start'],'chunk':position},'language_if_known':metadata.get('language','UNKNOWN'),'derivation_method':method,'metadata':metadata})
        if scientific:chunks[-1].update(chunker_version=PROFILE,scientific_object=identity['scientific_object'])
    return chunks,'INDEXED_TEXT' if chunks else 'EMPTY_ACCOUNTED'

def verify_chunk(chunk,evidence):
    if chunk.get('chunker_version')==TXT_VERSION:
        return _verify_text_chunk(chunk,evidence)
    parts=[];pages=[]
    for span in chunk['evidence_spans']:
        e=evidence[span['evidence_id']];require(e['source_id']==chunk['source_id'] and e['excerpt_sha256']==span['evidence_excerpt_sha256'],'CHUNK_EVIDENCE_IDENTITY')
        require(0<=span['start']<span['end']<=len(e['content_exact']),'CHUNK_SPAN_BOUNDS');parts.append(e['content_exact'][span['start']:span['end']])
        ref=e['locator']['reference'];require(ref['source_sha256']==chunk['source_sha256'] and e['document_version']==chunk['document_version'],'CHUNK_SOURCE_VERSION')
        pages.append({'physical_page':ref['physical_page'],'evidence_id':e['evidence_id'],'start':ref['start']+span['start'],'end':ref['start']+span['end']})
    require(''.join(parts)==chunk['exact_text'] and sha256(chunk['exact_text'].encode())==chunk['exact_text_sha256'],'CHUNK_EXACT_MISMATCH')
    require(retrieval_text(chunk['exact_text'])==chunk['retrieval_text'] and sha256(chunk['retrieval_text'].encode())==chunk['retrieval_text_sha256'],'CHUNK_RETRIEVAL_MISMATCH')
    require(pages==chunk['page_refs'],'CHUNK_PAGE_PROVENANCE')
    identity={'chunker_version':VERSION,'parameters':PARAMETERS,'source_id':chunk['source_id'],'source_sha256':chunk['source_sha256'],'spans':chunk['evidence_spans'],'exact_text_sha256':chunk['exact_text_sha256']}
    from .math_finance import selected,validate_chunk,PROFILE
    if selected(chunk['metadata']):
        validate_chunk(chunk,evidence);identity.update(chunker_version=PROFILE,scientific_object=chunk['scientific_object'])
    else:require(chunk['chunker_version']==VERSION and 'scientific_object' not in chunk,'CHUNK_PROFILE_MISMATCH')
    expected='chk_'+fingerprint(identity)
    require(chunk['chunk_id']==expected,'CHUNK_IDENTITY')

def _text_identity(c):
    return {'chunker_version':TXT_VERSION,'parameters':PARAMETERS,'source_id':c['source_id'],
            'source_sha256':c['source_sha256'],'spans':c['evidence_spans'],'exact_text_sha256':c['exact_text_sha256']}

def _text_ref(e,start,end):
    text=e['content_exact'];ref=e['locator']
    return {'evidence_id':e['evidence_id'],'reference_frame':'RAW_BYTES',
            'start':ref['start']+len(text[:start].encode('utf8')),
            'end':ref['start']+len(text[:end].encode('utf8')),
            'start_line':ref['start_line']+text[:start].count('\n'),
            'end_line':ref['start_line']+text[:end-1].count('\n')}

def _text_chunks(e,source,metadata,model):
    require(metadata.get('internal_method_reference') is True and
            source['source']['declared_media_type']=='text/plain','TXT_METHOD_PROFILE_REQUIRED')
    chunks=[];text=e['content_exact']
    if not retrieval_text(text):return [],'EMPTY_ACCOUNTED'
    for position,(start,end) in enumerate(ranges(text,model)):
        exact=text[start:end];rt=retrieval_text(exact)
        if not rt:continue
        c={'chunker_version':TXT_VERSION,'source_id':source['source_id'],'source_sha256':source['source_sha256'],
           'document_version':source['document_version'],
           'evidence_spans':[{'evidence_id':e['evidence_id'],'start':start,'end':end,'evidence_excerpt_sha256':e['excerpt_sha256']}],
           'page_refs':[],'text_refs':[_text_ref(e,start,end)],'exact_text':exact,'exact_text_sha256':sha256(exact.encode()),
           'retrieval_text':rt,'retrieval_text_sha256':sha256(rt.encode()),'retrieval_text_version':TEXT_VERSION,
           'position':{'physical_page':None,'evidence_start':e['locator']['start'],'chunk':position},
           'language_if_known':metadata.get('language','UNKNOWN'),'derivation_method':'TXT_RAW_LINES_V1','metadata':metadata}
        c['chunk_id']='chk_'+fingerprint(_text_identity(c));chunks.append(c)
    return chunks,'INDEXED_TEXT' if chunks else 'EMPTY_ACCOUNTED'

def _verify_text_chunk(c,evidence):
    require(c['metadata'].get('internal_method_reference') is True and not c['page_refs']
            and 'scientific_object' not in c,'TXT_METHOD_PROFILE_REQUIRED')
    parts=[];refs=[]
    for span in c['evidence_spans']:
        e=evidence[span['evidence_id']];ref=e['locator'];start,end=span['start'],span['end']
        require(ref.get('kind')=='RAW_UTF8_BYTE_RANGE' and ref.get('reference_frame')=='RAW_BYTES','TXT_LOCATOR_REQUIRED')
        require(e['source_id']==c['source_id'] and e['document_version']==c['document_version']=='v'+c['source_sha256'],'CHUNK_SOURCE_VERSION')
        require(sha256(e['content_exact'].encode())==e['excerpt_sha256']==span['evidence_excerpt_sha256'],'CHUNK_EVIDENCE_IDENTITY')
        require(0<=start<end<=len(e['content_exact']) and len(e['content_exact'].encode())==ref['end']-ref['start'],'CHUNK_SPAN_BOUNDS')
        parts.append(e['content_exact'][start:end]);refs.append(_text_ref(e,start,end))
    require(''.join(parts)==c['exact_text'] and sha256(c['exact_text'].encode())==c['exact_text_sha256'],'CHUNK_EXACT_MISMATCH')
    require(retrieval_text(c['exact_text'])==c['retrieval_text'] and sha256(c['retrieval_text'].encode())==c['retrieval_text_sha256'],'CHUNK_RETRIEVAL_MISMATCH')
    require(refs==c['text_refs'],'CHUNK_BYTE_PROVENANCE')
    require(c['chunk_id']=='chk_'+fingerprint(_text_identity(c)),'CHUNK_IDENTITY')
