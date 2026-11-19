"""JSON strict et convention métier J0A_JSON_V1_PROPOSED (nom historique)."""
import hashlib
import json
import math
from collections import OrderedDict
from threading import Lock

# Cache proof of JSON validity, never decoded objects or filesystem metadata.
# Every caller still reads its input. An exact immutable text match is required;
# changed bytes always run the original strict checks. At most 4M characters.
_VALID_JSON = OrderedDict()
_VALID_JSON_LOCK = Lock()
_VALID_JSON_CHARS = 0
_VALID_JSON_LIMIT = 4 * 1024 * 1024


def _known_json(text):
    if type(text) is not str or not 65536 <= len(text) <= 1024 * 1024:
        return False
    with _VALID_JSON_LOCK:
        if text not in _VALID_JSON:
            return False
        _VALID_JSON.move_to_end(text)
        return True


def _remember_json(text):
    global _VALID_JSON_CHARS
    if type(text) is not str or not 65536 <= len(text) <= 1024 * 1024:
        return
    with _VALID_JSON_LOCK:
        if text in _VALID_JSON:
            _VALID_JSON.move_to_end(text)
            return
        _VALID_JSON[text] = None
        _VALID_JSON_CHARS += len(text)
        while _VALID_JSON_CHARS > _VALID_JSON_LIMIT or len(_VALID_JSON) > 8:
            old, _ = _VALID_JSON.popitem(last=False)
            _VALID_JSON_CHARS -= len(old)


class ContractError(ValueError):
    """Code stable sans contenu documentaire dans le message."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _constant(value):
    raise ContractError("JSON_NON_FINITE")


def check_json(value, *, business=False):
    if value is None or type(value) in (bool, int):
        return
    if type(value) is str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ContractError("JSON_INVALID_UNICODE") from None
    elif type(value) is float:
        if not math.isfinite(value) or business:
            raise ContractError("JSON_NON_FINITE_OR_BUSINESS_FLOAT")
    elif type(value) is list:
        for item in value:
            check_json(item, business=business)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError("JSON_KEY_TYPE")
            check_json(key, business=business)
            check_json(item, business=business)
    else:
        raise ContractError("JSON_TYPE")


def strict_loads(data):
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="strict")
        if _known_json(data):
            # Fresh parse creates independent mutable objects. The identical
            # text already passed duplicate-key, finite and Unicode checks.
            return json.loads(data)
        obj = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        check_json(obj)
        _remember_json(data)
        return obj
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ContractError("JSON_SYNTAX") from None


def business_bytes(obj):
    """Tous les champs de l'objet métier ; métadonnées de run dans un autre objet.

    Clés triées, tableaux ordonnés, UTF-8, compact, aucune normalisation Unicode,
    aucun flottant, BOM ou LF final. Ce n'est pas une implémentation de RFC 8785.
    """
    check_json(obj, business=True)
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(obj):
    return sha256(business_bytes(obj))
