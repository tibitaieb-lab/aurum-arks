"""Trusted, version-bound PDF page selection; never inferred from PDF content."""
from copy import deepcopy
import re

from .serialization import ContractError, fingerprint

VERSION = 'ARKS_PDF_SCOPE_V1'


def require(condition, code):
    if not condition: raise ContractError(code)


def validate_scope(scope, source_id, source_sha256):
    passive=type(scope) is dict and scope.get('version')=='ARKS_PDF_SCOPE_V2'
    keys={'version','source_id','source_sha256',
        'total_physical_pages','included_pages','excluded_pages','decision_reference',
        'expected_document_warnings','expected_page_sha256'}
    if passive:keys|={'native_reader','blank_page_policy','qualification_reference'}
    if passive and 'native_fallback_pages' in scope:keys.add('native_fallback_pages')
    reviewed=passive and scope.get('native_reader')=='PDFMINER_REVIEWED_PAGES_V5'
    if reviewed:keys.add('reviewed_pages')
    if passive and 'passive_object_proof_sha256' in scope:
        keys.add('passive_object_proof_sha256')
        require(type(scope['passive_object_proof_sha256']) is str and re.fullmatch('[a-f0-9]{64}',scope['passive_object_proof_sha256']),'PDF_PASSIVE_OBJECT_PROOF_HASH')
    require(type(scope) is dict and set(scope)==keys,'PDF_SCOPE_CONTRACT')
    require(scope['version'] in (VERSION,'ARKS_PDF_SCOPE_V2') and scope['source_id']==source_id
            and scope['source_sha256']==source_sha256, 'PDF_SCOPE_SOURCE_VERSION')
    if passive:
        require(scope['native_reader'] in ('PYPDF_PASSIVE_V2','PDFIUM_PASSIVE_V2','PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5') and scope['blank_page_policy']=='TWO_NATIVE_ZERO_AND_WHITE_RENDER'
                and type(scope['qualification_reference']) is str and bool(scope['qualification_reference']),'PDF_PASSIVE_SCOPE_CONTRACT')
    total=scope['total_physical_pages']; included=scope['included_pages']; excluded=scope['excluded_pages']
    require(type(total) is int and 1<=total<=(2048 if passive else 300), 'PDF_SCOPE_PAGE_COUNT')
    require(type(scope['decision_reference']) is str and bool(scope['decision_reference']), 'PDF_SCOPE_AUTHORITY_REQUIRED')
    require(type(included) is list and included and all(type(n) is int and 1<=n<=total for n in included)
            and included==sorted(set(included)), 'PDF_SCOPE_INCLUDED_PAGES')
    require(type(excluded) is list, 'PDF_SCOPE_EXCLUDED_PAGES')
    numbers=[]
    for item in excluded:
        require(type(item) is dict and set(item)=={'physical_page','code','decision_reference'}, 'PDF_SCOPE_EXCLUSION_CONTRACT')
        n=item['physical_page']
        require(type(n) is int and 1<=n<=total and type(item['decision_reference']) is str
                and bool(item['decision_reference']), 'PDF_SCOPE_EXCLUSION_AUTHORITY')
        require(item['code'] in (('PDF_NO_TEXT_NO_OCR','PDF_WARNINGS_OR_INVALID_GLYPHS','PDF_OPERATOR_DECLARED_NONCONTENT') if passive else ('PDF_NO_TEXT_NO_OCR','PDF_WARNINGS_OR_INVALID_GLYPHS')), 'PDF_SCOPE_EXCLUSION_CODE')
        numbers.append(n)
    require(numbers==sorted(set(numbers)) and not set(numbers)&set(included)
            and sorted(numbers+included)==list(range(1,total+1)), 'PDF_SCOPE_PARTITION')
    if 'native_fallback_pages' in scope:
        fallback=scope['native_fallback_pages']
        require(scope['native_reader']=='PDFMINER_DECLARED_GLYPHS_V4' and type(fallback) is dict
                and 1<=len(fallback)<=16 and not excluded
                and all(type(k) is str and k in {str(n) for n in included} and v=='PDFIUM_PASSIVE_V2' for k,v in fallback.items()),
                'PDF_NATIVE_FALLBACK_SCOPE')
    warnings=scope['expected_document_warnings']
    require(type(warnings) is list and len(warnings)<=16, 'PDF_SCOPE_WARNING_LIMIT')
    for item in warnings:
        require(type(item) is dict and set(item)=={'warning_code','warning_message_sha256','warning_type','module','function'}, 'PDF_SCOPE_WARNING_CONTRACT')
        require(all(type(v) is str and bool(v) for v in item.values())
                and re.fullmatch('[a-f0-9]{64}',item['warning_message_sha256']), 'PDF_SCOPE_WARNING_IDENTITY')
    hashes=scope['expected_page_sha256']
    require(type(hashes) is dict and all(k in [str(n) for n in included]
            and type(v) is str and re.fullmatch('[a-f0-9]{64}',v) for k,v in hashes.items()), 'PDF_SCOPE_PAGE_HASHES')
    require(not hashes or set(hashes)=={str(n) for n in included}, 'PDF_SCOPE_PAGE_HASH_COVERAGE')
    if reviewed:
        from .doc_pdf_review import references
        references(scope)
    return deepcopy(scope)


def check_coverage(report, scope):
    """Unknown pages/errors/warnings always block publication of the batch."""
    from .doc_pdf import TEXT_STATE, _validated_body
    from .serialization import sha256
    _validated_body(report)
    scope=validate_scope(scope,report['source_id'],report['source_sha256'])
    passive=scope['version']=='ARKS_PDF_SCOPE_V2'
    total=scope['total_physical_pages']
    require(report['total_physical_pages']==total and [p['physical_page'] for p in report['pages']]==list(range(1,total+1)), 'PDF_COVERAGE_PAGE_SEQUENCE')
    require(report.get('audit_forbidden_events')==[], 'PDF_COVERAGE_FORBIDDEN_OPERATION')
    require(report['extractor']['parameters'].get('selection')==scope, 'PDF_COVERAGE_SELECTION_MISMATCH')
    require(report['extractor']['library_version']=='6.19.0'
            and report['extractor']['parameters']['normalization']=='NONE', 'PDF_COVERAGE_PROFILE')
    if passive:
        require(report['extractor'].get('adapter')=='ARKS_PDF_TEXT_SELECTED_V2' and report['extractor'].get('native_reader')==scope['native_reader']
                and report.get('passive_controls',{}).get('status')=='PASS' and report.get('pdfium_build_flags')==[], 'PDF_PASSIVE_PROFILE_PROOF')
        if scope['native_reader'] in ('PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
            require(report['extractor'].get('pdfminer_version')=='20260107' and report.get('native_document_warnings')==[],'PDF_NATIVE_DOCUMENT_WARNING')
    observed=[]
    for w in report['document_warnings']:
        require(w['warning_scope']=='document_scope' and w['page_number'] is None, 'PDF_COVERAGE_WARNING_SCOPE')
        origin=w.get('warning_origin',{})
        observed.append({k:w[k] for k in ('warning_code','warning_message_sha256','warning_type')} |
                        {'module':origin.get('module'),'function':origin.get('function')})
    require(report['document_warning_count']==len(observed)
            and sorted(map(fingerprint,observed))==sorted(map(fingerprint,scope['expected_document_warnings'])), 'PDF_UNREVIEWED_DOCUMENT_WARNING')
    exclusions={p['physical_page']:p for p in scope['excluded_pages']}
    blank=[]
    for p in report['pages']:
        n=p['physical_page']
        effective_reader=scope.get('native_fallback_pages',{}).get(str(n),scope.get('native_reader'))
        if 'native_fallback_pages' in scope:
            require(p.get('native_reader')==effective_reader,'PDF_NATIVE_FALLBACK_PROVENANCE')
        require(p['warning_count']==p['page_warning_count']==0 and p['page_warnings']==[], 'PDF_PAGE_WARNING_NOT_ACCEPTED')
        if n in exclusions:
            require(p['status']=='OPERATOR_EXCLUDED' and p['text'] is None and p['text_sha256'] is None
                    and p['code']==exclusions[n]['code'] and p.get('locator_status')=='PDF_PAGE_NOT_EXTRACTED', 'PDF_EXCLUSION_NOT_PRESERVED')
        elif passive and p['status']=='BLANK_VERIFIED':
            proof=p.get('blank_verification',{})
            require(p['text'] is None and p['text_sha256'] is None and proof.get('pypdf_characters')==proof.get('pdfium_characters')==0
                    and proof.get('all_rgb_white') is True and type(proof.get('pixel_sha256')) is str and re.fullmatch('[a-f0-9]{64}',proof['pixel_sha256']), 'PDF_BLANK_NOT_PROVEN')
            blank.append(n)
        else:
            text=p.get('text')
            require(p['status']==TEXT_STATE and type(text) is str and bool(text.strip()), 'PDF_NEW_PAGE_FAILURE')
            if passive and effective_reader=='PDFIUM_PASSIVE_V2':
                require(all(type(p.get(k)) is int and p[k]==0 for k in ('unicode_mapping_errors','native_excluded_nonwhitespace_count','native_nonbmp_count','native_invalid_codepoint_count')), 'PDF_NATIVE_CHARACTER_COVERAGE')
            if passive and effective_reader in ('PDFMINER_PASSIVE_V3','PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
                require(all(type(p.get(k)) is int and p[k]==0 for k in ('native_undefined_glyphs','native_empty_glyphs','native_warning_count')) and p.get('native_warning_events')==[], 'PDF_NATIVE_CHARACTER_COVERAGE')
                require(p.get('native_unresolved_declarations',0)==0,'PDF_UNRESOLVED_GLYPH_DECLARATION')
                if effective_reader in ('PDFMINER_DECLARED_GLYPHS_V4','PDFMINER_REVIEWED_PAGES_V5'):
                    raw=p.get('raw_native_glyph_text');mappings=p.get('declared_mappings')
                    require(type(raw) is str and sha256(raw.encode())==p.get('raw_native_glyph_sha256')
                            and type(mappings) is list and type(p.get('declared_mapping_count')) is int
                            and sum(m['occurrences'] for m in mappings)==p['declared_mapping_count']
                            and p.get('declared_mapping_contract') in ('SOURCE_ENCODING_NAMES_PYPDF_TABLE_V1_NO_TOUNICODE_OVERRIDE','SOURCE_ENCODING_NAMES_V2_UFFFD_ONLY_SOURCE_DECLARED_REPAIR','SOURCE_ENCODING_NAMES_V3_LITERAL_UNICODE_AND_EXPLICIT_SEMANTIC_NAMES'), 'PDF_DECLARED_MAPPING_PROVENANCE')
            require('\ufffd' not in text and not any(ord(c)<32 and c not in '\r\n\t' for c in text), 'PDF_NEW_INVALID_GLYPH')
            require(sha256(text.encode('utf-8'))==p['text_sha256'], 'PDF_PAGE_TEXT_HASH_MISMATCH')
            if scope['expected_page_sha256']:
                require(p['text_sha256']==scope['expected_page_sha256'][str(n)], 'PDF_PREVIOUS_PAGE_HASH_MISMATCH')
    if passive and scope['native_reader']=='PDFMINER_REVIEWED_PAGES_V5':
        from .doc_pdf_review import references,validate,verify_page
        expected={r['physical_page']:r for r in references(scope)}
        for p in report['pages']:
            if p['physical_page'] in expected:
                artifact=validate(p.get('reviewed_page'),scope,expected[p['physical_page']]);verify_page(p,artifact)
            else:require('reviewed_page' not in p and not p.get('graphic_components'),'PDF_UNAUTHORIZED_PAGE_REPRESENTATION')
    require(report['coverage']=={'pages_total':total,'pages_text_extracted':len(scope['included_pages'])-len(blank),
            'pages_not_text_covered':len(exclusions)+len(blank)}, 'PDF_COVERAGE_COUNTS')
    require(report['status']==('PARTIAL_EXTRACTION' if exclusions else TEXT_STATE), 'PDF_COVERAGE_STATE')
    result={'coverage':'PARTIAL_ACCEPTED_BY_OPERATOR' if exclusions else 'COMPLETE_PDF_TEXT_UNREVIEWED',
            'total_physical_pages':total,'extracted_pages':len(scope['included_pages'])-len(blank),
            'excluded_pages':sorted(exclusions),'scope_sha256':fingerprint(scope),
            'document_warning_count':len(observed),'xref_warning_impact':'INDETERMINATE' if observed else 'NOT_APPLICABLE',
            'semantic_layout':'NOT_QUALIFIED'}
    if passive:result.update(verified_blank_pages=blank,physical_pages_accounted=total,native_reader=scope['native_reader'])
    if scope.get('passive_object_proof_sha256'):
        proof=report.get('passive_controls',{}).get('qualified_passive_objects')
        require(type(proof) is dict and fingerprint(proof)==scope['passive_object_proof_sha256'] and proof.get('source_id')==scope['source_id'] and proof.get('source_sha256')==scope['source_sha256'],'PDF_PASSIVE_OBJECT_PROOF_IDENTITY')
        result.update(coverage='COMPLETE_PHYSICAL_PAGES_WITH_OPAQUE_SOURCE_OBJECTS',passive_objects={'kind':proof['kind'],'count':len(proof['objects']),'artifact_sha256':scope['passive_object_proof_sha256'],'indexing':'PAGE_BODY_TEXT_ONLY_OBJECTS_PRESERVED_IN_ORIGINAL'})
    if passive and scope['native_reader']=='PDFMINER_REVIEWED_PAGES_V5':
        result['reviewed_page_methods']=[{'physical_page':p['physical_page'],'method':p['reviewed_page']['method'],'artifact_sha256':fingerprint(p['reviewed_page'])} for p in report['pages'] if 'reviewed_page' in p]
        result['nontext_visual_semantics']='NOT_INDEXED_OR_SCIENTIFICALLY_INTERPRETED'
        if any(p.get('reviewed_page',{}).get('method')=='SOURCE_UNINTERPRETED_GLYPH_OBJECTS_V1' for p in report['pages']):
            result['coverage']='COMPLETE_PHYSICAL_PAGES_WITH_UNINTERPRETED_GLYPHS'
            result['unicode_text_coverage']='INCOMPLETE_EXPLICIT_GLYPH_REFERENCES'
        if any(p.get('reviewed_page',{}).get('method')=='SOURCE_PAGE_FACSIMILE_V1' for p in report['pages']):
            result['coverage']='COMPLETE_PHYSICAL_PAGES_WITH_SOURCE_FACSIMILES'
            result['unicode_text_coverage']='NATIVE_TEXT_AND_VERIFIED_CAPTIONS_ONLY_NO_FULL_TEXT_OCR'
    return result
