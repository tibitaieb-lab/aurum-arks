"""Autorité de harness séparée des documents ; aucun endpoint de rôle client."""
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType
from uuid import uuid4

from .serialization import ContractError

POLICY_VERSION = "J0A_POLICY_0.1_DRAFT"
GENERATOR = "HYPOTHESIS_GENERATOR"


@dataclass(frozen=True)
class AccessRecord:
    classification: str | None
    admitted: bool = False
    parents: tuple[str, ...] = ()
    derivation_authorized: bool = False
    rights: tuple[tuple[str, str], ...] = ()
    available_on: str | None = None
    availability_proof: str | None = None


class Policy:
    """Le constructeur est réservé à l'autorité du harness, jamais au corpus.

    Ce protocole Python n'est pas une frontière contre du code Python hostile.
    La classification d'un parent reste contraignante à toute profondeur.
    """

    def __init__(self, trusted_records, trusted_role, *, trusted_internal_methods=()):
        # Copie immuable de l'autorité ; aucun manifeste documentaire n'est promu.
        self._records = MappingProxyType(dict(trusted_records))
        self._role = trusted_role
        # Exact IDs supplied only by the trusted harness, never by a document.
        self._internal_methods = frozenset(trusted_internal_methods)

    def allows(self, identifier, *, operation="consultation", as_of=None):
        if self._role != GENERATOR or operation not in (
                "storage", "consultation", "provider_submission", "redistribution"):
            return False
        cutoff = None
        if as_of is not None:
            try:
                cutoff = date.fromisoformat(as_of)
                if cutoff.isoformat() != as_of:
                    return False
            except (ValueError, TypeError):
                return False

        def visit(key, ancestors):
            if key in ancestors:
                return False
            record = self._records.get(key)
            if not isinstance(record, AccessRecord):
                return False
            internal = (record.classification == "INTERNAL_REFERENCE"
                        and key in self._internal_methods
                        and operation in ("storage", "consultation"))
            if (record.classification != "EXTERNAL_PUBLICATION" and not internal) or record.admitted is not True:
                return False
            if dict(record.rights).get(operation) != "ALLOW":
                return False
            if cutoff is not None:
                try:
                    available = date.fromisoformat(record.available_on)
                    if available.isoformat() != record.available_on:
                        return False
                    if not record.availability_proof or available > cutoff:
                        return False
                except (ValueError, TypeError):
                    return False
            if record.parents and record.derivation_authorized is not True:
                return False
            return all(visit(parent, ancestors | {key}) for parent in record.parents)

        return visit(identifier, set())


class ContextBuilder:
    """Le chargeur de confiance résout une Evidence admise après décision.

    La sortie n'expose jamais un identifiant, nom ou motif détaillé refusé.
    Diagnostic optionnel réservé au harness, sans contenu ni texte d'exception.
    """

    def __init__(self, authority_policy, trusted_loader, *, trusted_diagnostic_sink=None):
        self._policy = authority_policy
        self._load = trusted_loader
        self._diagnostic = trusted_diagnostic_sink

    def _report(self, category, phase):
        if self._diagnostic is not None:
            try:
                self._diagnostic({"diagnostic_version": "J0A_DIAGNOSTIC_V1",
                                  "category": category, "phase": phase,
                                  "correlation_id": uuid4().hex})
            except Exception:
                # Aucun retry, aucun texte d'exception, statut d'échec conservé.
                pass

    def build(self, requested_ids, *, as_of=None):
        items, statuses = [], []
        for identifier in requested_ids:
            try:
                allowed = self._policy.allows(identifier, as_of=as_of)
            except Exception:
                statuses.append("INTERNAL_ERROR")
                self._report("INTERNAL_ERROR", "POLICY")
                continue
            if not allowed:
                statuses.append("ACCESS_DENIED")
                self._report("ACCESS_DENIED", "POLICY")
                continue
            phase = "LOAD"
            try:
                resolved = self._load(identifier)
                phase = "PROJECT"
                # Copie des seuls champs de sortie attendus d'un résolveur fiable.
                item = {k: resolved[k] for k in ("evidence_id", "source_id", "document_version",
                                                "content_exact", "source_sha256", "excerpt_sha256")}
                if item["evidence_id"] != identifier:
                    raise ContractError("LOADER_ID_MISMATCH")
            except ContractError as error:
                unavailable = (phase == "LOAD" and error.args
                               and type(error.args[0]) is str and error.args[0] == "SOURCE_UNAVAILABLE")
                category = "SOURCE_UNAVAILABLE" if unavailable else "INVALID_EVIDENCE"
                statuses.append(category)
                self._report(category, phase)
                continue
            except (FileNotFoundError, PermissionError):
                category = "SOURCE_UNAVAILABLE" if phase == "LOAD" else "INTERNAL_ERROR"
                statuses.append(category)
                self._report(category, phase)
                continue
            except Exception:
                statuses.append("INTERNAL_ERROR")
                self._report("INTERNAL_ERROR", phase)
                continue
            items.append(item)
            statuses.append("FOUND")
        return {"context_version": "J0A_CONTEXT_V2", "role": GENERATOR, "policy_version": POLICY_VERSION,
                "items": items, "states": statuses,
                "semantic_faithfulness": "NOT_EVALUATED"}
