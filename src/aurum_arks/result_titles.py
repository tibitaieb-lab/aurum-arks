"""Auditable title projection; no writes, document parsing or inferred titles."""
from pathlib import Path, PureWindowsPath
import re

from .paths import reject_links
from .store_relocation import relocated_reference  # P3-403 (P3-7c)
from .serialization import strict_loads, sha256, fingerprint

ARKS = Path(__file__).resolve().parents[2]


def text(value):
    if not isinstance(value, str) or not value.strip() or value.strip().casefold() in ('unknown', 'not_applicable'):
        return None
    return value.strip()


def mapping(value):
    return value if isinstance(value, dict) else {}


class TitleProjection:
    def __init__(self, config, sources, curation_root=None):
        self.config, self.sources = config, sources
        self.curation = Path(curation_root) if curation_root else ARKS / 'curation'
        self.cache = {}  # Per query only; metadata bytes are reread on the next query.

    def for_source(self, key, metadata):
        if key not in self.cache:
            self.cache[key] = self._read(key, metadata)
        return self.cache[key].copy()

    def for_result(self, hit):
        # Display structure only; never mutate the retrieval response or metadata.
        return hit | self.for_source(hit['source_id'], hit['metadata']) | {
            'page': hit['page_refs'][0]['physical_page'] if hit['page_refs'] else None}

    def _read(self, key, metadata):
        item = self.sources[key]
        source = item['source']
        digest = source['raw_sha256']
        decision = self.config.get('acquisitions', {}).get(key, {})
        candidates = []
        reference = decision.get('qualification_reference')
        if isinstance(reference, str):
            candidates.append(relocated_reference(reference))  # P3-403 (P3-7c) : ancienne racine du recu -> ARKS ; controles inchanges
        if re.fullmatch(r'ARKS_SRC_\d+', key):
            candidates += sorted((self.curation / key).glob('*.json'),
                                 key=lambda p: (p.name != key + '_QUALIFICATION.json', p.name))
        names = []

        def result(title, origin, field, **audit):
            return {'display_title': title, 'title_source': origin,
                    'title_provenance': {'field': field, 'source_id': key,
                                         'source_sha256': digest, **audit}}

        for path in dict.fromkeys(candidates):
            try:
                reject_links(path)
                if not (path.resolve().is_relative_to(ARKS) or
                        path.resolve().is_relative_to(self.curation.resolve())):
                    continue
                if not path.is_file() or path.stat().st_size > 2 * 1024**2:
                    continue
                raw = path.read_bytes()
                qualification = mapping(strict_loads(raw))
                identity = mapping(qualification.get('source_identity'))
                qkey = qualification.get('source_id', qualification.get('source_id_proposed'))
                qhash = qualification.get('source_sha256', qualification.get('sha256', identity.get('sha256')))
                if qkey != key or not isinstance(qhash, str) or qhash.casefold() != digest.casefold():
                    continue
                audit = {'path': str(path), 'artifact_sha256': sha256(raw)}
                for field, value in (
                        ('title', qualification.get('title')),
                        ('document_identity.title', mapping(qualification.get('document_identity')).get('title')),
                        ('source_identity.title', identity.get('title'))):
                    if text(value):
                        return result(text(value), 'QUALIFICATION_TITLE', field, **audit)
                for field, value in (('source_original_filename', qualification.get('source_original_filename')),
                                     ('source_identity.original_filename', identity.get('original_filename'))):
                    if text(value) and text(PureWindowsPath(value).name):
                        names.append((PureWindowsPath(value).name, field, audit))
            except (OSError, ValueError, TypeError):
                continue

        title = mapping(source.get('title'))
        if title.get('state') == 'KNOWN' and isinstance(title.get('value'), str) and title['value'].strip():
            # Explicit KNOWN also distinguishes a genuine title literally named UNKNOWN.
            return result(title['value'].strip(), 'SOURCE_MANIFEST_TITLE', 'SourceManifest.title.value',
                          source_manifest_sha256=fingerprint(source), explicit_known=True)
        if text(metadata.get('title')):
            return result(text(metadata['title']), 'DOCUMENT_METADATA_TITLE', 'chunk.metadata.title')
        if names:
            name, field, audit = names[0]
            return result(name, 'CANDIDATE_NAME', field, **audit)
        for field, value in (('chunk.metadata.original_name', metadata.get('original_name')),
                             ('policy.relative_path', decision.get('relative_path'))):
            if text(value) and text(PureWindowsPath(value).name):
                return result(PureWindowsPath(value).name, 'CANDIDATE_NAME', field)
        return result(key, 'SOURCE_ID_FALLBACK', 'source_id')
