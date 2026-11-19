"""Presentation only. Project existing qualification fields; never write a store.

No retrieval, PDF loading, inference, admission or taxonomy normalization here.
"""
import html
import json
from pathlib import Path
import re
from urllib.parse import urlencode

from .paths import reject_links
from .store_relocation import relocated_reference  # P3-403 (P3-7c)

ARKS = Path(__file__).resolve().parents[2]
ASSETS = ARKS / 'ui'
ASSET_TYPES = {'aurum-themes.css': 'text/css; charset=utf-8',
               'aurum-research-lab-logo.png': 'image/png',
               'catalogue.css': 'text/css; charset=utf-8',
               'catalogue.js': 'text/javascript; charset=utf-8'}


def values(value):
    items = value if isinstance(value, list) else [value]
    # Preserve case, spelling and separators. UNKNOWN is missing metadata.
    return list(dict.fromkeys(x.strip() for x in items if isinstance(x, str)
                              and x.strip() and x.strip() not in ('UNKNOWN', 'NON CLASSÉ')))


def categories(qualification):
    classification = qualification.get('classification', {})
    if not isinstance(classification, dict): classification = {}
    candidates = [
        ('classification.primary_domain + secondary_domains',
         values(classification.get('primary_domain')) + values(classification.get('secondary_domains'))
         if classification.get('primary_domain') else []),
        ('classification.main_domain + secondary_domains',
         values(classification.get('main_domain')) + values(classification.get('secondary_domains'))),
        ('primary_domain + subdomains', values(qualification.get('primary_domain')) + values(qualification.get('subdomains'))),
        ('domains', values(qualification.get('domains'))),
        ('category', values(qualification.get('category'))),
    ]
    for field, result in candidates:
        if result: return list(dict.fromkeys(result)), field
    # Document types and roles have no demonstrated category contract here.
    return [], None


def metadata_view(store, catalogue, curation_root=None):
    curation = Path(curation_root) if curation_root else ARKS / 'curation'
    config = store.config()
    sources = {row[0]: json.loads(row[1]) for row in store.db.execute('select id,source from acquisitions')}
    result = []
    for item in catalogue:
        key = item['source_id']; source = sources.get(key, {})
        digest = source.get('raw_sha256', '').lower()
        candidates = []
        reference = config.get('acquisitions', {}).get(key, {}).get('qualification_reference')
        if isinstance(reference, str): candidates.append(relocated_reference(reference))  # P3-403 (P3-7c) : ancienne racine du recu -> ARKS ; controles inchanges
        if re.fullmatch(r'ARKS_SRC_\d+', key):
            folder = curation / key
            candidates += sorted(folder.glob('*.json'), key=lambda p: (p.name != key + '_QUALIFICATION.json', p.name))
        found, origin = [], None
        for path in dict.fromkeys(candidates):
            try:
                reject_links(path)
                # Policy paths are trusted configuration, yet stay inside the installation/test root.
                if not (path.resolve().is_relative_to(ARKS) or path.resolve().is_relative_to(curation.resolve())): continue
                if not path.is_file() or path.stat().st_size > 2 * 1024**2: continue
                qualification = json.loads(path.read_bytes())
                identity = qualification.get('source_identity', {})
                qkey = qualification.get('source_id', qualification.get('source_id_proposed'))
                qhash = qualification.get('source_sha256', qualification.get('sha256', identity.get('sha256', '')))
                if qkey != key or not digest or not isinstance(qhash, str) or qhash.lower() != digest: continue
                found, field = categories(qualification)
                if found:
                    origin = {'path': str(path), 'field': field, 'source_id': key, 'source_sha256': digest}
                    break
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        if not found and values(source.get('themes')):
            found, origin = values(source['themes']), {'field': 'SourceManifest.themes', 'source_id': key, 'source_sha256': digest}
        result.append(dict(item, arks_categories=found or ['NON CLASSÉ'], category_origin=origin,
                           original_available=bool(item.get('consultation') or item.get('original_consultation'))))
    return result


def page(body):
    return ('<!doctype html><html lang="fr" data-theme="classic-light"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>ARKS · AURUM Research</title>'
            '<link rel="stylesheet" href="/ui/aurum-themes.css"><link rel="stylesheet" href="/ui/catalogue.css">'
            '<script src="/ui/catalogue.js" defer></script></head><body>'
            '<a class="skip-link" href="#main">Aller au contenu</a><header class="brand-header">'
            '<div class="brand-lockup"><span class="logo-plate"><img class="brand-logo" src="/ui/aurum-research-lab-logo.png" '
            'alt="AURUM Research Lab" width="259" height="75"></span><div><a class="brand" href="/">ARKS</a>'
            '<p class="brand-subtitle">AURUM Research Knowledge System</p></div></div><div id="header-controls">'
            '<label class="theme-label" for="theme">Apparence<select id="theme">'
            '<option value="classic-light">Aurum Classic Light</option><option value="ivory-premium">Aurum Ivory Premium</option><option value="data-night">Aurum Data Night</option><option value="aurum-black">Aurum Black</option>'
            '</select></label></div></header><main id="main" class="workspace">' + body +
            '</main><footer>Consultation locale · Aucun agent ni génération IA. '
            'La couverture technique ne certifie pas la fidélité de toutes les formules et figures.</footer></body></html>')


def catalogue_html(rows, uploads=True, initial_state='', hybrid=True):
    esc = html.escape
    consultable = sum(bool(row['consultation']) for row in rows)
    toolbar = ('<section class="catalogue-intro"><div><p class="eyebrow">BIBLIOTHÈQUE DOCUMENTAIRE</p>'
               '<h1>Catalogue des sources</h1><p>Explorer les documents et vérifier leurs passages.</p></div>'
               '<nav class="actions" aria-label="Actions documentaires">')
    if uploads:
        toolbar += '<a class="button" href="/documents#upload-single">Ajouter un PDF</a><a class="button secondary" href="/documents#upload-multiple">Ajouter plusieurs PDF</a>'
    toolbar += '<a class="button secondary" href="/candidates">Inventaire des candidats</a></nav></section>'
    toolbar += ('<section class="search-panel" aria-label="Recherche documentaire"><form action="/search">'
                '<label for="rag-query">Recherche dans les documents</label><div class="search-controls">'
                '<input id="rag-query" aria-label="Recherche" name="q" maxlength="256" placeholder="Mots-clés ou question…" required>'
                '<button>Rechercher</button></div></form><p>Recherche ' + ('hybride' if hybrid else 'lexicale') + ' · Passages sourcés et vérifiables</p></section>')
    toolbar += ('<section id="catalogue" data-initial-state="' + esc(initial_state, quote=True) + '">'
                '<div class="catalogue-toolbar"><div><h2>Documents</h2><p id="result-count" role="status" aria-live="polite">' +
                f'{consultable} sources affichées / {consultable}</p></div><div class="view-controls">'
                '<label for="catalogue-scope">Périmètre<select id="catalogue-scope"><option value="consultable">Sources consultables (' + str(consultable) + ')</option>'
                '<option value="all">Toutes les entrées (' + str(len(rows)) + ')</option></select></label>'
                '<button class="secondary" id="reset-filters" type="button">Réinitialiser les filtres</button></div></div>'
                '<p class="filter-hint">Filtres combinables · Plusieurs choix : OU dans une colonne, ET entre colonnes. '
                'Les autres entrées restent accessibles via « Toutes les entrées ». '
                'Binaire ACTIVE : fichier conservé ; seuls les passages admis sont consultables.</p>'
                '<noscript>Activez JavaScript pour les filtres et tris locaux. Le catalogue reste consultable ci-dessous.</noscript>'
                '<div class="table-scroll" role="region" aria-label="Catalogue des sources" tabindex="0"><table id="source-table">'
                '<caption class="sr-only">Catalogue documentaire avec six filtres et tris de colonnes</caption><thead><tr>')
    labels = ['Source', 'Candidat', 'Binaire', 'Couverture', 'Catégories ARKS', 'Original']
    for number, label in enumerate(labels):
        toolbar += '<th scope="col" aria-sort="' + ('ascending' if number == 0 else 'none') + '"><button type="button" class="sort-button" data-column="' + str(number) + '" aria-label="Trier par ' + label + '">' + label + '<span aria-hidden="true" class="sort-mark">' + ('↑' if number == 0 else '↕') + '</span></button>'
        fid = ['source', 'candidate', 'binary', 'coverage', 'category', 'original'][number]
        if number < 2:
            toolbar += '<input id="filter-' + fid + '" aria-label="Filtrer ' + label + '" type="search" placeholder="Contient…">'
        elif number in (3, 4):
            # Actual values filled with DOM textContent, never HTML injection.
            toolbar += '<div class="multi-filter" id="filter-' + fid + '"><button type="button" class="filter-toggle" aria-label="Filtrer ' + label + '" aria-expanded="false" aria-controls="choices-' + fid + '">Tous</button><fieldset id="choices-' + fid + '" hidden><legend>' + label + '</legend></fieldset></div>'
        else:
            toolbar += '<select id="filter-' + fid + '" aria-label="Filtrer ' + label + '"><option value="">Tous</option></select>'
        toolbar += '</th>'
    toolbar += '</tr></thead><tbody>'
    for row in rows:
        cats = row['arks_categories']; available = row['original_available']; key = str(row['source_id'])
        original = 'DISPONIBLE' if available else 'NON DISPONIBLE'
        data = [key, str(row.get('candidate_id') or ''), str(row['state']), str(row['coverage']), ' · '.join(cats), original]
        toolbar += '<tr data-values="' + esc(json.dumps(data, ensure_ascii=False), quote=True) + '" data-categories="' + esc(json.dumps(cats, ensure_ascii=False), quote=True) + '" data-consultable="' + str(bool(row['consultation'])).lower() + '"' + ('' if row['consultation'] else ' hidden') + '>'
        toolbar += '<td class="identifier">' + esc(data[0]) + '</td><td class="identifier muted">' + esc(data[1]) + '</td><td><span class="badge">' + esc(data[2]) + '</span></td>'
        short = {'COMPLETE_PDF_TEXT_UNREVIEWED': 'Texte complet · non revu', 'PARTIAL_ACCEPTED_BY_OPERATOR': 'Couverture partielle acceptée',
                 'COMPLETE_PHYSICAL_PAGES_WITH_SOURCE_FACSIMILES': 'Pages complètes avec fac-similés'}.get(data[3], 'Couverture technique')
        toolbar += '<td><span class="coverage-label">' + short + '</span><code class="coverage-code">' + esc(data[3]) + '</code></td><td class="categories">'
        for cat in cats[:2]: toolbar += '<span class="badge category">' + esc(cat) + '</span>'
        if len(cats) > 2:
            toolbar += '<details class="more-categories"><summary>+' + str(len(cats) - 2) + ' catégories</summary>'
            toolbar += ''.join('<span class="badge category">' + esc(cat) + '</span>' for cat in cats[2:]) + '</details>'
        toolbar += '</td><td><span class="availability">' + original + '</span>'
        if available: toolbar += '<a class="source-link" href="' + esc('/source?' + urlencode({'id': key}), quote=True) + '">Voir source <span aria-hidden="true">↗</span></a>'
        toolbar += '</td></tr>'
    return toolbar + '</tbody></table></div><p id="empty-results" hidden>Aucune source ne correspond à ces filtres.</p></section>'
