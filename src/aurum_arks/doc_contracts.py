"""Explicit SourceManifest extension; historical J0A contracts stay unchanged."""
from copy import deepcopy

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from .provenance import require, validate_txt_bounds
from .serialization import ContractError, check_json, sha256
from .validation import Contracts


class DocumentaryContracts:
    VERSION = 'DOC_SOURCE_V1'
    PDF_SOURCE_VERSION = 'DOC_PDF_SOURCE_V1'
    PDF_EVIDENCE_VERSION = 'DOC_PDF_EVIDENCE_V1'
    PDF_LONG_EVIDENCE_VERSION = 'DOC_PDF_EVIDENCE_V2'

    def __init__(self, schema_root):
        self.base = Contracts(schema_root)
        source = deepcopy(self.base.schemas['SourceManifest'])
        source['$id'] = 'urn:aurum-arks:doc:1:SourceManifest'
        source['properties']['schema_version'] = {'const': self.VERSION}
        source['properties']['admission_status']['enum'].append('ADMITTED_LOCAL')
        source['properties']['acquisition']['properties']['method']['enum'].append('MANUAL_LOCAL_COPY')
        # The initial TXT profile deliberately keeps the inherited 64 KiB limit.
        self.source_validator = Draft202012Validator(source, registry=self.base.registry,
                                                     format_checker=self.base.checker)
        pdf_source=deepcopy(source)
        pdf_source['$id']='urn:aurum-arks:doc:pdf1:SourceManifest'
        pdf_source['properties']['schema_version']={'const':self.PDF_SOURCE_VERSION}
        pdf_source['properties']['byte_length']={'type':'integer','minimum':1,'maximum':100*1024**2}
        pdf_source['properties']['declared_media_type']={'const':'application/pdf'}
        pdf_source['properties']['encoding']={'const':'NOT_APPLICABLE'}
        self.pdf_source_validator=Draft202012Validator(pdf_source,registry=self.base.registry,format_checker=self.base.checker)
        pdf_ev=deepcopy(self.base.schemas['EvidenceUnit'])
        pdf_ev['$id']='urn:aurum-arks:doc:pdf1:EvidenceUnit'
        pdf_ev['properties']['schema_version']={'const':self.PDF_EVIDENCE_VERSION}
        pdf_ev['properties']['content_type']={'const':'TEXT_UTF8'}
        ref_props={k:{'type':'string','pattern':'^[a-f0-9]{64}$'} for k in
            ('source_sha256','extraction_id','page_text_sha256','excerpt_sha256')}
        ref_props.update(source_id={'$ref':'urn:aurum-arks:j0a:0.1:common#/$defs/id'},
            physical_page={'type':'integer','minimum':1,'maximum':300},
            offset_unit={'const':'UNICODE_CODEPOINT'},start={'type':'integer','minimum':0},end={'type':'integer','minimum':1})
        pdf_ev['properties']['locator']={'type':'object','properties':{
            'kind':{'const':'PDF_EXTRACTED_CODEPOINT_RANGE'},'reference_frame':{'const':'VERSIONED_EXTRACTION'},
            'reference':{'type':'object','properties':ref_props,'required':list(ref_props),'additionalProperties':False}},
            'required':['kind','reference_frame','reference'],'additionalProperties':False}
        pdf_ev['properties']['transformation']['properties']['rule_version']={'const':'PDF_EXTRACTED_SLICE_V1'}
        pdf_ev['properties']['quality_alerts']['items']['enum']+=['PDF_LAYOUT_NOT_QUALIFIED','PARTIAL_COVERAGE','DOCUMENT_WARNING_UNREVIEWED']
        pdf_ev['properties']['quality_alerts']['items']['enum']+=['OCR_VISUALLY_REVIEWED_DERIVATIVE','NON_TEXT_GRAPHIC_OBJECTS_PRESERVED']
        pdf_ev['properties']['quality_alerts']['items']['enum']+=['UNINTERPRETED_SOURCE_GLYPHS_UNICODE_INCOMPLETE']
        pdf_ev['properties']['quality_alerts']['items']['enum']+=['OPAQUE_SOURCE_OBJECTS_PRESERVED_NOT_TEXT_INDEXED']
        pdf_ev['properties']['quality_alerts']['items']['enum']+=['SOURCE_PAGE_FACSIMILE_FULL_TEXT_NOT_INDEXED']
        pdf_ev['allOf']=[]
        self.pdf_evidence_validator=Draft202012Validator(pdf_ev,registry=self.base.registry,format_checker=self.base.checker)
        # Explicit documentary extension only. Historical V1 and J0A schemas
        # retain their bounds; actual source scope is checked by the PDF store.
        long_ev=deepcopy(pdf_ev)
        long_ev['$id']='urn:aurum-arks:doc:pdf2:EvidenceUnit'
        long_ev['properties']['schema_version']={'const':self.PDF_LONG_EVIDENCE_VERSION}
        long_ev['properties']['locator']['properties']['reference']['properties']['physical_page']['maximum']=2048
        self.pdf_long_evidence_validator=Draft202012Validator(long_ev,registry=self.base.registry,format_checker=self.base.checker)

    def validate(self, obj, expected=None):
        if expected == 'SourceManifest':
            check_json(obj)
            try:
                validator=self.pdf_source_validator if obj.get('schema_version')==self.PDF_SOURCE_VERSION else self.source_validator
                validator.validate(obj)
            except ValidationError:
                raise ContractError('DOC_SOURCE_SCHEMA_INVALID') from None
            require(obj['admission_status'] == 'ADMITTED_LOCAL', 'SOURCE_NOT_ADMITTED')
            require(obj['acquisition']['method'] == 'MANUAL_LOCAL_COPY', 'ACQUISITION_METHOD')
            require(type(obj['byte_length']) is int, 'SOURCE_SIZE_REPRESENTATION')
            return obj
        if expected=='EvidenceUnit' and obj.get('schema_version') in (self.PDF_EVIDENCE_VERSION,self.PDF_LONG_EVIDENCE_VERSION):
            check_json(obj)
            validator=self.pdf_long_evidence_validator if obj['schema_version']==self.PDF_LONG_EVIDENCE_VERSION else self.pdf_evidence_validator
            try: validator.validate(obj)
            except ValidationError: raise ContractError('DOC_PDF_EVIDENCE_SCHEMA_INVALID') from None
            return obj
        return self.base.validate(obj, expected)

    def resolve_txt(self, ev, source, loader):
        validate_txt_bounds(ev)
        self.validate(source, 'SourceManifest')
        self.validate(ev, 'EvidenceUnit')
        require((ev['source_id'],ev['document_id'],ev['document_version']) ==
                (source['source_id'],source['document_id'],source['document_version']),
                'DOCUMENT_VERSION_MISMATCH')
        require(source['declared_media_type']=='text/plain' and source['encoding']=='UTF-8',
                'SOURCE_NOT_SUPPORTED_OR_ADMITTED')
        validate_txt_bounds(ev, source['byte_length'])
        raw = loader(source['source_id'])
        require(type(raw) is bytes and len(raw)==source['byte_length'] and len(raw)<=65536,
                'RAW_SIZE_MISMATCH')
        require(sha256(raw)==source['raw_sha256'], 'RAW_HASH_MISMATCH')
        start,end=ev['locator']['start'],ev['locator']['end']
        try:
            raw.decode('utf-8'); raw[:start].decode('utf-8'); raw[:end].decode('utf-8')
            text=raw[start:end].decode('utf-8')
        except UnicodeError:
            raise ContractError('UTF8_BOUNDARY_OR_ENCODING') from None
        require(text==ev['content_exact'],'EXCERPT_MISMATCH')
        require(sha256(raw[start:end])==ev['excerpt_sha256'],'EXCERPT_HASH_MISMATCH')
        for name,pos in (('start_line',start),('end_line',end-1)):
            line=ev['locator'][name]
            require(line is None or type(line) is int and line==raw[:pos].count(b'\n')+1,
                    'AUXILIARY_LINE_MISMATCH')
        return {'evidence_id':ev['evidence_id'],'source_id':source['source_id'],
                'document_id':source['document_id'],'document_version':source['document_version'],
                'range':[start,end],'content_exact':text,'source_sha256':sha256(raw),
                'excerpt_sha256':sha256(raw[start:end]),'raw_bytes':'VERIFIED','locator':'RESOLVED'}
