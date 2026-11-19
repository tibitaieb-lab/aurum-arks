"""PDF persistence in the existing store; uncertain parses are never replayed."""
from pathlib import Path
import json
import uuid
from . import doc_pdf
from .doc_checkpoint import atomic_json
from .doc_inventory import local_regular
from .doc_pdf_scope import validate_scope, check_coverage
from .paths import confined, reject_links
from .serialization import ContractError, fingerprint, sha256, strict_loads
from .provenance import require

EXTRACTOR='DOC_PDF_EVIDENCE_V1'
BLOCK_CHARACTERS=4096
# CP2830 V2: lower bounded request for measured host headroom. The worker
# independently rechecks the quarter-available-RAM gate at every launch.
PASSIVE_WORKER_MEMORY_MIB=384

def extraction_timeout(scope):
    """Large native PDFs retain the adapter's existing 600-second hard bound."""
    return min(600,max(240,scope['total_physical_pages'])) if scope['version']=='ARKS_PDF_SCOPE_V2' else 90

def passive_memory_request():
    """Choose a bounded request; the launcher independently checks current RAM."""
    import ctypes
    class Memory(ctypes.Structure):
        _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(n,ctypes.c_ulonglong) for n in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]
    mem=Memory();mem.length=ctypes.sizeof(mem)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem)),'PDF_MEMORY_OBSERVATION_UNAVAILABLE')
    request=min(PASSIVE_WORKER_MEMORY_MIB,((mem.available//4//(1024**2)-32)//16)*16)
    require(request>=128,'PDF_AVAILABLE_MEMORY_LIMIT')
    return request
# Exact previously qualified CP422/CP796 V1 tuple. This is not a wildcard for
# stale code: existing immutable artifacts/locators remain readable after V2.
LEGACY_PROFILE={
    'adapter_sha256':'3face9d529e7c7bad89e7285e2b46ab1c27da96cef30f5b19ea7bbc96d5f6533',
    'worker_sha256':'d66404e48c85a03605b385d37011bf71007fe43bcb221b7336370620f7ff5529',
    'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
    'scope_sha256':'90e3f1df93407349deb5d153b969008b0f4ed5b4baba99c508a378f54bbd489c'}
# Exact C2 profile qualified by CP796 passive05/canonical03/recovery02 gates.
# Original artifact identities and locators stay readable; no stale-hash wildcard.
QUALIFIED_V2_PROFILES=({'adapter_sha256': '290cf400793b7bdb374e39ad7452e85d31e7f46abd00b17f88d70cc18c9add45', 'worker_sha256': '5dea0947f7e8aba00f7b8b00cb0ca0c1814af6359783be8738e588ae47e8a6b8', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': 'a4de000edaf309fe9a9dbd4eb2de1fbd2c8ce32313c959023c944133bcfd1923'},
{'adapter_sha256': '290cf400793b7bdb374e39ad7452e85d31e7f46abd00b17f88d70cc18c9add45', 'worker_sha256': '6af98834a7fd8831b47a7f2ee5864537fea26e4c41a32864bcb7f8d9d9f9b7b1', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': '7d6b84076a8eb9a7800b217b7ca25dd20196fa02ac743654ca3ff3248f67e650'},
{'adapter_sha256': '290cf400793b7bdb374e39ad7452e85d31e7f46abd00b17f88d70cc18c9add45', 'worker_sha256': 'b879bf525b571f020ffafff171ac2e3483bc4e362323b399c8162668e0ae45dc', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': 'd2b408cbf9d7ea5792d1dc96660b04954d725fdc89e2a4a8ef7d75e2913f27ce'},
    {
    'adapter_sha256':'bb4c553f2f85da79ac37a812d64216fc660829731f7885e209867b8fb4a0f4f1',
    'worker_sha256':'a7a1824d76b1650f7f262081fed99bcd54baa7e02b6a6f3750bd35a66d6f272a',
    'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
    'scope_sha256':'faf8c4ca52cfda9bbb24f2a697df167a3e259558113fb04f9aabefafdbcc6ef6'},
    # Native3/root-C3 candidate: 193 methods/181 subtests, then scoped real
    # admissions. Read compatibility only; never an authorization to re-extract.
    {'adapter_sha256':'ab5d87a55f720129374f2677940c784f0d8991465ee0b5f4702f8aaabe55bc8d',
     'worker_sha256':'efb62701271a16ff13b4275ef1462ee28859007db569fd3668b88ed37cca5810',
     'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
     'scope_sha256':'80411ee7f3d4c4d992eecfca7b69d19dc944e1ce94c4e8417c59614cf001b7a6'},
    # Declared-glyph/long-Evidence candidate, qualified before the inert-link
    # contract revision. Exact identity preserves existing text and locators.
    {'adapter_sha256':'290cf400793b7bdb374e39ad7452e85d31e7f46abd00b17f88d70cc18c9add45',
     'worker_sha256':'a617245965fb2ac053ec20d33fe16d041175697f82a705d66c212b5ed6928e94',
     'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
     'scope_sha256':'d2b408cbf9d7ea5792d1dc96660b04954d725fdc89e2a4a8ef7d75e2913f27ce'},
    # CP2830 closed candidate: exact prior profile for immutable24admissions.
    # The Type1 initialization fix creates new extraction identities only.
    {'adapter_sha256':'290cf400793b7bdb374e39ad7452e85d31e7f46abd00b17f88d70cc18c9add45',
     'worker_sha256':'8251bad1b866267f042b02de95db353f25b11f4dbaa7aa6b5aa5e3d7feb7df60',
     'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
     'scope_sha256':'d2b408cbf9d7ea5792d1dc96660b04954d725fdc89e2a4a8ef7d75e2913f27ce'},
    # CP3925 closed candidate: exact immutable read compatibility for all32.
    {'adapter_sha256':'290cf400793b7bdb374e39ad7452e85d31e7f46abd00b17f88d70cc18c9add45',
     'worker_sha256':'c880e91a86461ae0782f42822b5cfad969d60f55811127565fae8c62c83b6a93',
     'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
     'scope_sha256':'a4de000edaf309fe9a9dbd4eb2de1fbd2c8ce32313c959023c944133bcfd1923'},)

def profile(decision,key):
    require(decision.get('pdf_profile') in ('ARKS_PDF_LOCAL_V1','ARKS_PDF_PASSIVE_V2'),'PDF_READER_NOT_CONFIGURED')
    require(decision.get('encoding')=='NOT_APPLICABLE','PDF_BINARY_ENCODING_REQUIRED')
    scope=validate_scope(decision.get('pdf_scope'),key,decision['expected_sha256'])
    require((decision['pdf_profile']=='ARKS_PDF_PASSIVE_V2')==(scope['version']=='ARKS_PDF_SCOPE_V2'),'PDF_PROFILE_SCOPE_MISMATCH')
    return scope

def init_table(db):
    db.execute('''CREATE TABLE IF NOT EXISTS pdf_extractions(
        acquisition_id TEXT PRIMARY KEY REFERENCES acquisitions(id),state TEXT NOT NULL,
        decision_hash TEXT NOT NULL,job_dir TEXT NOT NULL,extraction_id TEXT,
        artifact_sha256 TEXT,coverage_json TEXT)'''); db.commit()

def artifact_path(store,extraction_id):
    require(type(extraction_id) is str and len(extraction_id)==64 and all(c in '0123456789abcdef' for c in extraction_id),'PDF_EXTRACTION_ID')
    return confined(store.root,'extractions/'+extraction_id+'.json')

# Exact C3 profile qualified before the connected-component extension.
# Read compatibility only, linked to the scoped three real admissions.
QUALIFIED_REVIEW_PROFILES=({'adapter_sha256': 'b1b7f6766c58a05c01071997f5690c04225f48170e71a3034dbdc948f2416ccf', 'review_adapter_sha256': '87485acd456217a1dcc0e6159ab0cfce2f770ca192437ab805a320c8a05ef9a7', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'worker_sha256': 'ba887a5aab73d408d2f3f0e2c812f0c573eaccceb8012048bc148bd2972d3eff'},)

# CP5564 protected37: exact previously qualified profile, read compatibility only.
QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '29c32b8cdf711b48269dca2d078e2935055c2f662910194f32c5ed5025b1e974', 'review_adapter_sha256': 'd82c47f916b3e6a9219738e692a12d80613a9f9f48834415f574502c9e59d385', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'worker_sha256': '9abca6ac10cb510daec5e12ef06aa31df6f860313ba1103fbab6a9506c1cf8bf'},)
QUALIFIED_V2_PROFILES += ({'adapter_sha256': '29c32b8cdf711b48269dca2d078e2935055c2f662910194f32c5ed5025b1e974', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'worker_sha256': '9abca6ac10cb510daec5e12ef06aa31df6f860313ba1103fbab6a9506c1cf8bf'},)

# Exact immutable profile of the 52-source baseline before Recovery87.
# This grants read compatibility only; new extractions use current code hashes.
QUALIFIED_V2_PROFILES += ({'adapter_sha256':'5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05',
 'worker_sha256':'fec4d85ed3ef2683d72bbb401280eb84cd0f64db46360427ba16b01fc0c271b4',
 'warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3',
 'scope_sha256':'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'f0ed717005974ae6091eb08a227af77e6cd1a368dfd1178f0755e5982db9d92a', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'ce44e5361f4c0ae56512434583635bd4b9bf494c4e9636b4afc48c90b22558fc', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': '061afaf1b06f2909a64f22ef5f761ee2fca6b23222659f1428b41fef8aa49f07', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'ce57b9dbfad8e00ec5973e57c2b9b180b282f021167690a73a64add6cb27cee7', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'a157a5cc641ccce897578151d34493ae0e8cdef1284673a938b6e800e239f6f7', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'fec4d85ed3ef2683d72bbb401280eb84cd0f64db46360427ba16b01fc0c271b4', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'review_adapter_sha256': '135535a6b5375d32b6d96d899df33d382789fce07362d061d0e8243d6ddb436d'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '29c32b8cdf711b48269dca2d078e2935055c2f662910194f32c5ed5025b1e974', 'worker_sha256': '9abca6ac10cb510daec5e12ef06aa31df6f860313ba1103fbab6a9506c1cf8bf', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'review_adapter_sha256': 'd82c47f916b3e6a9219738e692a12d80613a9f9f48834415f574502c9e59d385'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': 'b1b7f6766c58a05c01071997f5690c04225f48170e71a3034dbdc948f2416ccf', 'worker_sha256': 'ba887a5aab73d408d2f3f0e2c812f0c573eaccceb8012048bc148bd2972d3eff', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': 'ba6d1afd378f48593f5865ac2efb57b1e9ecc88ddc0a3d6543990ffb9e16ad53', 'review_adapter_sha256': '87485acd456217a1dcc0e6159ab0cfce2f770ca192437ab805a320c8a05ef9a7'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': '812cf55d88ac5752df3687a97c1b8406b306ff3a2cb8a617ff59eb0b14b0937e', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': '812cf55d88ac5752df3687a97c1b8406b306ff3a2cb8a617ff59eb0b14b0937e', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'review_adapter_sha256': 'f466874926efa49abcb7016dadb1f21dff5a18061210dc0f773a255556c1d58a'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'd9cde5bec0d08e70fc14ed764173d755276448d291899d72b2e8a552aec580ca', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '5341bf8d502a3144c00550f0d3f1fbfda1418b8eb6aaa97cb83e4d4c846f4b05', 'worker_sha256': 'd9cde5bec0d08e70fc14ed764173d755276448d291899d72b2e8a552aec580ca', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'review_adapter_sha256': '172bf3ec70014d9cafada301e4684190daf5cc0920aee18158e72e98b4e39b45'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '461cf2c1084c515061afdb5f87791e7839357178f3c1447485c0bb619fda3cf9', 'worker_sha256': '9b3653c9d39b6255a467ac453b0a1980cae7b18dd91828df8fbeb5e7728b551b', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '461cf2c1084c515061afdb5f87791e7839357178f3c1447485c0bb619fda3cf9', 'worker_sha256': '9b3653c9d39b6255a467ac453b0a1980cae7b18dd91828df8fbeb5e7728b551b', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'review_adapter_sha256': '172bf3ec70014d9cafada301e4684190daf5cc0920aee18158e72e98b4e39b45'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '461cf2c1084c515061afdb5f87791e7839357178f3c1447485c0bb619fda3cf9', 'worker_sha256': 'a2597230c8d42bafafc70a44202107f905248267de63fc830264b157e8b440df', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '461cf2c1084c515061afdb5f87791e7839357178f3c1447485c0bb619fda3cf9', 'worker_sha256': 'a2597230c8d42bafafc70a44202107f905248267de63fc830264b157e8b440df', 'scope_sha256': '93c347082a5194b2d8412df4a4278c84f48c0f8d0f7450631a685193f2ed3254', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'review_adapter_sha256': '172bf3ec70014d9cafada301e4684190daf5cc0920aee18158e72e98b4e39b45'},)

QUALIFIED_V2_PROFILES += ({'adapter_sha256': '3ef9ddf42296d88c1ddab77693f79da2f7ba03dc5224796a68f51f9d92e74a9a', 'worker_sha256': '761bc84c91c83975a21e06f8d392ea13bf81fe82c60dd55cde466f002c32a533', 'scope_sha256': '4be0c719985405f54ac001cc0bfd46a9f6c99ece0f2a3e2100b5151883849bf6', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'},)

QUALIFIED_REVIEW_PROFILES += ({'adapter_sha256': '3ef9ddf42296d88c1ddab77693f79da2f7ba03dc5224796a68f51f9d92e74a9a', 'worker_sha256': '761bc84c91c83975a21e06f8d392ea13bf81fe82c60dd55cde466f002c32a533', 'scope_sha256': '4be0c719985405f54ac001cc0bfd46a9f6c99ece0f2a3e2100b5151883849bf6', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'review_adapter_sha256': '172bf3ec70014d9cafada301e4684190daf5cc0920aee18158e72e98b4e39b45'},)

# Exact release profile before cmap-format-6 support. Existing extractions are
# immutable; compatibility does not authorize re-extraction or change text.
_PRE_CMAP6_PROFILE={'adapter_sha256':'3ef9ddf42296d88c1ddab77693f79da2f7ba03dc5224796a68f51f9d92e74a9a','worker_sha256':'d6153e8851db5ffc6542633f4d478613579dd11db9e45696549039f91b5e5bf2','scope_sha256':'e11d98059646cfeedcdf93563603d8544cc6505549fd5405a460491499748e6d','warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'}
QUALIFIED_V2_PROFILES += (_PRE_CMAP6_PROFILE,)
QUALIFIED_REVIEW_PROFILES += (dict(_PRE_CMAP6_PROFILE,review_adapter_sha256='46bd2ab5f5983a5d43f1d95a694359f7aa348344dcce085c36deef4e1c78c43f'),)

# Exact protected 176-source release before controlled 22/09 remediation.
# Read compatibility only; original extraction bytes and locators are unchanged.
_PRE_REMEDIATION_20260922={'adapter_sha256':'3ef9ddf42296d88c1ddab77693f79da2f7ba03dc5224796a68f51f9d92e74a9a','worker_sha256':'6768f6f42172acd874e8bb4d15fd4155eca0d1dcfdfd45dc94bc51cdb6f1980c','scope_sha256':'e11d98059646cfeedcdf93563603d8544cc6505549fd5405a460491499748e6d','warnings_sha256':'04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3'}
QUALIFIED_V2_PROFILES += (_PRE_REMEDIATION_20260922,)
QUALIFIED_REVIEW_PROFILES += (dict(_PRE_REMEDIATION_20260922,review_adapter_sha256='46bd2ab5f5983a5d43f1d95a694359f7aa348344dcce085c36deef4e1c78c43f'),)

# Exact source profile before the F: interpreter-path relocation.
# Read compatibility only: immutable source/extraction hashes stay unchanged.
_PRE_F_RELOCATION_PROFILE = {'adapter_sha256': '3ef9ddf42296d88c1ddab77693f79da2f7ba03dc5224796a68f51f9d92e74a9a', 'worker_sha256': '15581632a4ca3aa26118ce0bc4f6bcd9dd134b54495bfef0bcef606944a9a070', 'warnings_sha256': '04b62969ff0affd611beb4d2057bdefa532929e2e006626c9e0d985ee4c64ac3', 'scope_sha256': '68a937a3d48db66b8b0aa2dc4e19ec02d16df6a8929f407999dbe4627b8298fe'}
QUALIFIED_V2_PROFILES += (_PRE_F_RELOCATION_PROFILE,)

def _identity(report):
    cfg=report['extractor']
    require(cfg['adapter'] in ('ARKS_PDF_TEXT_SELECTED_V1','ARKS_PDF_TEXT_SELECTED_V2'),'PDF_EXTRACTION_VERSION')
    if cfg.get('adapter')=='ARKS_PDF_TEXT_SELECTED_V2' and cfg.get('native_reader')=='PDFMINER_REVIEWED_PAGES_V5' and any(all(cfg.get(k)==v for k,v in profile.items()) for profile in QUALIFIED_REVIEW_PROFILES):return
    if cfg.get('native_reader')=='PDFMINER_REVIEWED_PAGES_V5':
        require(cfg.get('review_adapter_sha256')==sha256(Path(__file__).with_name('doc_pdf_review.py').read_bytes()),'PDF_STALE_REVIEW_ADAPTER')
    if cfg['adapter']=='ARKS_PDF_TEXT_SELECTED_V1' and all(cfg.get(k)==v for k,v in LEGACY_PROFILE.items()):return
    if cfg['adapter']=='ARKS_PDF_TEXT_SELECTED_V2' and any(all(cfg.get(k)==v for k,v in profile.items()) for profile in QUALIFIED_V2_PROFILES):return
    for key,name in [('adapter_sha256','doc_pdf.py'),('worker_sha256','doc_pdf_worker.py'),('warnings_sha256','doc_pdf_warnings.py'),('scope_sha256','doc_pdf_scope.py')]:
        require(cfg.get(key)==sha256(Path(__file__).with_name(name).read_bytes()),'PDF_STALE_EXTRACTOR')

def load_report(store,key,*,row=None,verify_index=True):
    source=store.source(key); config=store.config(); decision=store.decision(key,'consultation',config)
    require(decision['rights'].get('indexation') is True,'INDEX_AUTHORIZATION_REQUIRED')
    scope=profile(decision,key)
    row=row if row is not None else store.db.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone()
    require(row is not None and row['state']=='ACTIVE','PDF_EXTRACTION_NOT_ACTIVE')
    require(row['decision_hash']==store.decision_hash(key,config),'STALE_EXTRACTION')
    path=artifact_path(store,row['extraction_id'])
    require(0<local_regular(path).st_size<=doc_pdf.PASSIVE_MAX_OUTPUT,'PDF_EXTRACTION_SIZE')
    raw=path.read_bytes(); require(sha256(raw)==row['artifact_sha256'],'PDF_EXTRACTION_FILE_HASH')
    report=strict_loads(raw)
    require(report['source_id']==key and report['source_sha256']==source['raw_sha256'] and report['extraction_id']==row['extraction_id'],'PDF_EXTRACTION_SOURCE_VERSION')
    _identity(report); coverage=check_coverage(report,scope)
    for page in report['pages']:
        review=page.get('reviewed_page',{})
        if review.get('method')=='SOURCE_PAGE_FACSIMILE_V1':
            digest=review['content']['png_sha256'];image_path=confined(store.root,'extractions/reviewed/images/'+digest+'.png');require(0<local_regular(image_path).st_size<=32*1024**2 and sha256(image_path.read_bytes())==digest,'PDF_FACSIMILE_IMAGE_FILE_HASH')
    require(coverage==strict_loads(row['coverage_json']),'PDF_CATALOGUE_COVERAGE_MISMATCH')
    if verify_index: _check_index(store,key,source,report,coverage)
    return report,coverage

def evidence(store,source,report,page,start,end,coverage):
    ref=doc_pdf.locator(report,page,start,end)
    text=doc_pdf.resolve_locator(report,ref,expected_source_id=source['source_id'],expected_source_sha256=source['raw_sha256'])
    return _evidence_object(store,source,report,ref,text,coverage)


def _evidence_object(store,source,report,ref,text,coverage):
    page,start,end=ref['physical_page'],ref['start'],ref['end']
    alerts=['PDF_LAYOUT_NOT_QUALIFIED']
    if source['synthetic']: alerts.append('SYNTHETIC_FIXTURE')
    if coverage['excluded_pages']: alerts.append('PARTIAL_COVERAGE')
    if coverage['document_warning_count']: alerts.append('DOCUMENT_WARNING_UNREVIEWED')
    if coverage.get('passive_objects'):alerts.append('OPAQUE_SOURCE_OBJECTS_PRESERVED_NOT_TEXT_INDEXED')
    page_record=next(p for p in report['pages'] if p['physical_page']==page)
    if 'reviewed_page' in page_record:
        method=page_record['reviewed_page']['method']
        alerts.append('SOURCE_PAGE_FACSIMILE_FULL_TEXT_NOT_INDEXED' if method=='SOURCE_PAGE_FACSIMILE_V1' else 'UNINTERPRETED_SOURCE_GLYPHS_UNICODE_INCOMPLETE' if method=='SOURCE_UNINTERPRETED_GLYPH_OBJECTS_V1' else 'OCR_VISUALLY_REVIEWED_DERIVATIVE' if method=='OCR_ASSISTED_VISUAL_TRANSCRIPTION_V1' else 'NON_TEXT_GRAPHIC_OBJECTS_PRESERVED')
    extended=report['extractor'].get('adapter')=='ARKS_PDF_TEXT_SELECTED_V2' and report['total_physical_pages']>300
    version=store.contracts.PDF_LONG_EVIDENCE_VERSION if extended else store.contracts.PDF_EVIDENCE_VERSION
    ev={'contract_type':'EvidenceUnit','schema_version':version,
        'evidence_id':'e'+fingerprint({'source':source['source_id'],'version':source['document_version'],'extraction_id':report['extraction_id'],'page':page,'start':start,'end':end,'extractor':EXTRACTOR}),
        'source_id':source['source_id'],'document_id':source['document_id'],'document_version':source['document_version'],
        'content_exact':text,'content_type':'TEXT_UTF8','excerpt_sha256':ref['excerpt_sha256'],
        'locator':{'kind':'PDF_EXTRACTED_CODEPOINT_RANGE','reference_frame':'VERSIONED_EXTRACTION','reference':ref},
        'transformation':{'transformation_id':'t'+report['extraction_id'],'rule_version':'PDF_EXTRACTED_SLICE_V1','normalization':'NONE'},'quality_alerts':alerts}
    store.contracts.validate(ev,'EvidenceUnit'); return ev


def _expected_units(store,source,report,coverage):
    """Projection of a report already validated by check_coverage.

    Avoid rehashing the entire extraction for every chunk during index checks;
    public locator resolution still uses its full independent validation.
    """
    units=[]
    for page in report['pages']:
        if page['status']!=doc_pdf.TEXT_STATE: continue
        for start in range(0,len(page['text']),BLOCK_CHARACTERS):
            end=min(start+BLOCK_CHARACTERS,len(page['text']));text=page['text'][start:end]
            ref={'source_id':report['source_id'],'source_sha256':report['source_sha256'],
                 'extraction_id':report['extraction_id'],'physical_page':page['physical_page'],
                 'offset_unit':'UNICODE_CODEPOINT','start':start,'end':end,
                 'page_text_sha256':page['text_sha256'],'excerpt_sha256':sha256(text.encode('utf-8'))}
            units.append(_evidence_object(store,source,report,ref,text,coverage))
    return units


def _check_index(store,key,source,report,coverage):
    expected={e['evidence_id']:e for e in _expected_units(store,source,report,coverage)}
    rows=store.db.execute('select * from evidence where acquisition_id=?',(key,)).fetchall()
    require(len(rows)==len(expected) and {r['id'] for r in rows}==set(expected),'PDF_INDEX_INCONSISTENT')
    dh=store.decision_hash(key,store.config())
    for row in rows:
        require(row['extractor']==EXTRACTOR and row['decision_hash']==dh
                and strict_loads(row['object'])==expected[row['id']],'PDF_INDEX_INCONSISTENT')


def _rebuild_index(store,key,source,row,report,coverage,decision_hash):
    """Explicit repair of the derived index only; never a new PDF extraction."""
    units=_expected_units(store,source,report,coverage)
    store.original(key)
    current=store.config();store.decision(key,'consultation',current)
    require(store.decision_hash(key,current)==decision_hash,'POLICY_CHANGED_DURING_EXTRACTION')
    with store.db:
        store.db.execute('BEGIN IMMEDIATE')
        present=store.db.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone()
        require(dict(present)==dict(row),'PDF_INDEX_REBUILD_CONFLICT')
        require(sha256(artifact_path(store,row['extraction_id']).read_bytes())==row['artifact_sha256'],'PDF_EXTRACTION_FILE_CHANGED')
        store.db.execute('delete from evidence where acquisition_id=?',(key,))
        store.db.executemany('insert into evidence values (?,?,?,?,?)',[(e['evidence_id'],key,EXTRACTOR,decision_hash,json.dumps(e)) for e in units])
        store._event(key,'PDF_INDEX_REBUILT')
    _check_index(store,key,source,report,coverage)
    return dict(coverage,source_id=key,evidence_count=len(units),extraction_id=row['extraction_id'],reused=True,index_rebuilt=True)

def _completed_job(folder,source,scope):
    folder=Path(folder); reject_links(folder)
    require(folder.is_relative_to(doc_pdf.ARKS/'reports'),'PDF_JOB_PATH_SCOPE')
    require((folder/'RESULT.json').is_file(),'PDF_EXTRACTION_INDETERMINATE_NO_REPLAY')
    bounds=strict_loads((folder/'RESULT.json').read_bytes())
    require(bounds['state']=='COMPLETED' and bounds['returncode']==0,'PDF_EXTRACTION_FAILED_NO_REPLAY')
    require(sha256((folder/'LAUNCH.json').read_bytes())==bounds['launch_sha256'],'PDF_JOB_LAUNCH_HASH')
    path=folder/'worker-result.json'; require(0<local_regular(path).st_size<=doc_pdf.PASSIVE_MAX_OUTPUT,'PDF_JOB_RESULT_SIZE')
    report=strict_loads(path.read_bytes()); request=strict_loads((folder/'REQUEST.json').read_bytes())
    require(report['source_id']==source['source_id'] and report['source_sha256']==source['raw_sha256'] and report['source_bytes']==source['byte_length'] and report['extractor']==request['extractor'],'PDF_JOB_PROVENANCE')
    report['bounds']=bounds; _identity(report); check_coverage(report,scope); return report

def extract(store,key,*,work_dir=None,interrupt_at=None,rebuild_index=False):
    require(type(rebuild_index) is bool,'PDF_INDEX_REBUILD_FLAG')
    config=store.config(); decision=store.decision(key,'consultation',config)
    require(decision['rights'].get('indexation') is True,'INDEX_AUTHORIZATION_REQUIRED')
    scope=profile(decision,key); source=store.source(key); raw=store.original(key); dh=store.decision_hash(key,config)
    row=store.db.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone()
    if rebuild_index: require(row is not None and row['state']=='ACTIVE','PDF_INDEX_REBUILD_REQUIRES_ACTIVE')
    if row is not None:
        require(row['decision_hash']==dh,'PDF_EXTRACTION_POLICY_CHANGED_NO_REPLAY')
        if row['state']=='ACTIVE':
            report,coverage=load_report(store,key,row=row,verify_index=not rebuild_index)
            if rebuild_index: return _rebuild_index(store,key,source,row,report,coverage,dh)
            count=store.db.execute('select count(*) from evidence where acquisition_id=?',(key,)).fetchone()[0]
            require(count>0,'PDF_INDEX_MISSING')
            return dict(coverage,source_id=key,evidence_count=count,extraction_id=row['extraction_id'],reused=True)
        require(row['state'] in ('STARTED','PREPARED'),'PDF_EXTRACTION_FAILED_NO_REPLAY')
        report=_completed_job(row['job_dir'],source,scope)
    else:
        folder=Path(work_dir).absolute() if work_dir is not None else doc_pdf.ARKS/'reports'/('PDF_STORE_JOB_'+uuid.uuid4().hex)
        reject_links(folder)
        require(folder.is_relative_to(doc_pdf.ARKS/'reports') and not folder.exists(),'PDF_JOB_NOT_NEW_OR_OUTSIDE_REPORTS')
        reviewed_pages=None
        if scope.get('native_reader')=='PDFMINER_REVIEWED_PAGES_V5':
            from .doc_pdf_review import load_bundle
            reviewed_pages=load_bundle(store.root,scope)
        store.free_space()
        with store.db:
            store.db.execute('insert into pdf_extractions values (?,?,?,?,?,?,?)',(key,'STARTED',dh,str(folder),None,None,None)); store._event(key,'PDF_EXTRACTION_STARTED')
        if interrupt_at=='PDF_STARTED': raise ContractError('TEST_INTERRUPTION_PDF_STARTED')
        passive=scope['version']=='ARKS_PDF_SCOPE_V2'
        object_proof=None
        if scope.get('passive_object_proof_sha256'):
            proof_path=confined(store.root,'extractions/reviewed/'+scope['passive_object_proof_sha256']+'.json');require(0<local_regular(proof_path).st_size<=4*1024**2,'PDF_PASSIVE_OBJECT_PROOF_SIZE');proof_raw=proof_path.read_bytes();require(sha256(proof_raw)==scope['passive_object_proof_sha256'],'PDF_PASSIVE_OBJECT_PROOF_HASH');object_proof=strict_loads(proof_raw)
        report=doc_pdf.extract_pdf(raw,source_id=key,expected_sha256=source['raw_sha256'],work_dir=folder,timeout_seconds=extraction_timeout(scope),memory_mib=passive_memory_request() if passive else min(256,passive_memory_request()),max_pages=scope['total_physical_pages'],selection=scope,reviewed_pages=reviewed_pages,passive_object_proof=object_proof)
    try:
        _identity(report); coverage=check_coverage(report,scope)
    except (ContractError,KeyError):
        with store.db:
            store.db.execute('update pdf_extractions set state=? where acquisition_id=?',('FAILED',key)); store._event(key,'PDF_EXTRACTION_FAILED')
        raise ContractError('PDF_EXTRACTION_NOT_QUALIFIED') from None
    store.free_space(); target=artifact_path(store,report['extraction_id']); target.parent.mkdir(exist_ok=True)
    if target.exists(): require(strict_loads(target.read_bytes())==report,'PDF_EXTRACTION_FILE_CONFLICT')
    else: atomic_json(target,report,exclusive=True)
    artifact_hash=sha256(target.read_bytes())
    with store.db:
        store.db.execute('update pdf_extractions set state=?,extraction_id=?,artifact_sha256=?,coverage_json=? where acquisition_id=?',('PREPARED',report['extraction_id'],artifact_hash,json.dumps(coverage),key)); store._event(key,'PDF_EXTRACTION_PREPARED')
    if interrupt_at=='PDF_PREPARED': raise ContractError('TEST_INTERRUPTION_PDF_PREPARED')
    # Coverage and extraction fingerprint have already been checked. Avoid an
    # O(pages*document_size) rehash per chunk; public resolution verifies again.
    units=_expected_units(store,source,report,coverage)
    current=store.config(); store.decision(key,'consultation',current)
    require(store.decision_hash(key,current)==dh,'POLICY_CHANGED_DURING_EXTRACTION')
    require(sha256(target.read_bytes())==artifact_hash,'PDF_EXTRACTION_FILE_CHANGED')
    with store.db:
        store.db.execute('delete from evidence where acquisition_id=?',(key,))
        store.db.executemany('insert into evidence values (?,?,?,?,?)',[(e['evidence_id'],key,EXTRACTOR,dh,json.dumps(e)) for e in units])
        store.db.execute('update pdf_extractions set state=? where acquisition_id=?',('ACTIVE',key)); store._event(key,'PDF_INDEX_COMMITTED')
    if interrupt_at=='PDF_COMMITTED': raise ContractError('TEST_INTERRUPTION_PDF_COMMITTED')
    return dict(coverage,source_id=key,evidence_count=len(units),extraction_id=report['extraction_id'],reused=False)


def authorize_revision(store,key,previous_config):
    """Archive a reconciled failed attempt under an explicit, narrow new policy.

    Never revises an ACTIVE extraction or broadens rights. The trusted operator
    configuration supplies the authority; PDF contents cannot supply it.
    """
    current=store.config();new=store.decision(key,'storage',current);old=store.decision(key,'storage',previous_config)
    old_hash=store.decision_hash(key,previous_config);new_hash=store.decision_hash(key,current)
    authorization=new.get('pdf_recovery')
    require(type(authorization) is dict and set(authorization)=={'previous_decision_hash','previous_job_result_sha256','authority_reference','reason_reference','attempt_id'},'PDF_RECOVERY_AUTHORITY_REQUIRED')
    require(all(type(v) is str and v for v in authorization.values()) and authorization['previous_decision_hash']==old_hash,'PDF_RECOVERY_PREVIOUS_DECISION')
    require({k:v for k,v in old.items() if k not in ('pdf_profile','pdf_scope','pdf_recovery')}=={k:v for k,v in new.items() if k not in ('pdf_profile','pdf_scope','pdf_recovery')},'PDF_RECOVERY_UNAUTHORIZED_POLICY_DELTA')
    require(new_hash!=old_hash and profile(new,key)['version']=='ARKS_PDF_SCOPE_V2','PDF_RECOVERY_MATERIAL_CHANGE_REQUIRED')
    row=store.db.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone()
    acq=store.db.execute('select * from acquisitions where id=?',(key,)).fetchone()
    require(row is not None and row['state']=='FAILED' and row['decision_hash']==old_hash and acq is not None and acq['state']=='ACTIVE' and acq['decision_hash']==old_hash,'PDF_RECOVERY_RECONCILED_FAILED_ONLY')
    require(store.db.execute('select count(*) from evidence where acquisition_id=?',(key,)).fetchone()[0]==0,'PDF_RECOVERY_EVIDENCE_EXISTS')
    folder=Path(row['job_dir']);reject_links(folder);require(folder.is_relative_to(doc_pdf.ARKS/'reports'),'PDF_JOB_PATH_SCOPE')
    result_raw=(folder/'RESULT.json').read_bytes();result=strict_loads(result_raw)
    require(sha256(result_raw)==authorization['previous_job_result_sha256'],'PDF_RECOVERY_JOB_NOT_RECONCILED')
    completed=result.get('state')=='COMPLETED' and result.get('returncode')==0
    failed=result.get('state') in ('WORKER_ERROR','TIMED_OUT') and type(result.get('returncode')) is int and result['returncode']!=0
    require(completed or failed,'PDF_RECOVERY_JOB_NOT_RECONCILED')
    require(result.get('launch_sha256')==sha256((folder/'LAUNCH.json').read_bytes()),'PDF_RECOVERY_LAUNCH_CHANGED')
    require(set(result.get('logs',{}))=={'stdout.log','stderr.log'},'PDF_RECOVERY_LOG_SET')
    for name,expected in result['logs'].items():
        log=folder/name;reject_links(log)
        require(local_regular(log).st_size==0 and sha256(log.read_bytes())==expected,'PDF_RECOVERY_UNREVIEWED_OUTPUT')
    require(all(result.get(k,{}).get('state') in ('EXITED','NOT_FOUND','PID_REUSED_ORIGINAL_EXITED') for k in ('after_job_close','gated_worker_after_job_close')),'PDF_RECOVERY_TERMINATION_UNKNOWN')
    source=strict_loads(acq['source']);path=confined(store.root,'originals/'+source['raw_sha256']+'.pdf')
    require(local_regular(path).st_size==source['byte_length'] and sha256(path.read_bytes())==source['raw_sha256']==new['expected_sha256'],'PDF_RECOVERY_ORIGINAL_CHANGED')
    require(store.decision_hash(key,store.config())==new_hash,'POLICY_CHANGED_DURING_RECOVERY')
    with store.db:
        store.db.execute('BEGIN IMMEDIATE')
        require(dict(store.db.execute('select * from pdf_extractions where acquisition_id=?',(key,)).fetchone())==dict(row),'PDF_RECOVERY_CONCURRENT_CHANGE')
        store.db.execute('CREATE TABLE IF NOT EXISTS pdf_extraction_history(attempt_id TEXT PRIMARY KEY, acquisition_id TEXT NOT NULL, previous_row TEXT NOT NULL, previous_policy TEXT NOT NULL, new_decision_hash TEXT NOT NULL, authority TEXT NOT NULL)')
        require(store.db.execute('select count(*) from pdf_extraction_history where attempt_id=?',(authorization['attempt_id'],)).fetchone()[0]==0,'PDF_RECOVERY_ATTEMPT_ALREADY_USED')
        store.db.execute('insert into pdf_extraction_history values (?,?,?,?,?,?)',(authorization['attempt_id'],key,json.dumps(dict(row)),json.dumps(old),new_hash,json.dumps(authorization)))
        store.db.execute('delete from pdf_extractions where acquisition_id=?',(key,))
        store.db.execute('update acquisitions set decision_hash=? where id=?',(new_hash,key))
        store._event(key,'PDF_FAILED_ATTEMPT_ARCHIVED_FOR_AUTHORIZED_REVISION')
    return {'source_id':key,'status':'REVISION_AUTHORIZED_NOT_EXTRACTED','previous_decision_hash':old_hash,'new_decision_hash':new_hash,'attempt_id':authorization['attempt_id'],'evidence_count':0}

def resolve(store,row,source):
    require(row['extractor']==EXTRACTOR,'STALE_EXTRACTION'); store.original(source['source_id'])
    report,coverage=load_report(store,source['source_id'],verify_index=False)
    ev=strict_loads(row['object']); store.contracts.validate(ev,'EvidenceUnit'); ref=ev['locator']['reference']
    expected=evidence(store,source,report,ref['physical_page'],ref['start'],ref['end'],coverage)
    require(row['id']==expected['evidence_id'] and ev==expected,'PDF_EVIDENCE_PROVENANCE_MISMATCH')
    _check_index(store,source['source_id'],source,report,coverage)
    result={'evidence_id':ev['evidence_id'],'source_id':source['source_id'],'document_id':source['document_id'],
        'document_version':source['document_version'],'physical_page':ref['physical_page'],'range':[ref['start'],ref['end']],
        'offset_unit':'UNICODE_CODEPOINT','extraction_id':report['extraction_id'],'content_exact':ev['content_exact'],
        'source_sha256':source['raw_sha256'],'excerpt_sha256':ev['excerpt_sha256'],'raw_bytes':'VERIFIED','locator':'RESOLVED',
        'coverage':coverage['coverage'],'quality_alerts':ev['quality_alerts']}
    page=next(p for p in report['pages'] if p['physical_page']==ref['physical_page'])
    if coverage.get('passive_objects'):
        proof=report['passive_controls']['qualified_passive_objects'];result['passive_source_objects']=[o for o in proof['objects'] if o.get('physical_page',ref['physical_page'])==ref['physical_page']]
    if 'reviewed_page' in page:
        review=page['reviewed_page'];result['page_derivation']={'method':review['method'],'artifact_sha256':fingerprint(review),'review':review['review'],'render':review['render'],'visual_regions':review['visual_regions'],'semantic_scope':'NO_GENERAL_SCIENTIFIC_OR_FORMULA_CERTIFICATION'}
        result['graphic_components']=[c for c in page.get('graphic_components',[]) if ref['start']<=c['offset']<ref['end']]
        if review['method']=='SOURCE_PAGE_FACSIMILE_V1':
            digest=review['content']['png_sha256'];path=confined(store.root,'extractions/reviewed/images/'+digest+'.png');require(0<local_regular(path).st_size<=32*1024**2 and sha256(path.read_bytes())==digest,'PDF_FACSIMILE_IMAGE_FILE_HASH')
            result['source_page_facsimile']={'path':str(path),'png_sha256':digest,'render':review['render'],'source_images':review['content']['source_images'],'source_sha256':source['raw_sha256'],'physical_page':ref['physical_page'],'text_status':'NATIVE_TEXT_AND_VERIFIED_CAPTIONS_ONLY_NO_FULL_TEXT_OCR'}
        if review['method'] in ('SOURCE_DECLARED_COMPONENT_GROUPS_V1','SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2'):
            ordinals={c['source_ordinal'] for c in result['graphic_components']}
            result['graphic_groups']=[g for g in review['content']['groups'] if ordinals.intersection(g['component_ordinals'])]
            if review['method']=='SOURCE_DECLARED_COMPONENT_MASK_GROUPS_V2':
                image_ids={n for g in result['graphic_groups'] for n in g['image_ordinals']}
                result['graphic_image_connectors']=[m for m in review['content']['image_connectors'] if m['image_ordinal'] in image_ids]
            result['page_derivation']['formula_semantics']='NOT_INDEXED_OR_INFERRED'
    return result
