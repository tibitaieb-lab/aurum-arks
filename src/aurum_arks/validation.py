"""Définition structurelle unique : les huit schémas locaux versionnés."""
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from .paths import confined
from .serialization import ContractError, check_json, strict_loads

CONTRACTS = ("SourceManifest", "EvidenceUnit", "NumericFact", "ClaimRecord",
             "EvidencePack", "ResearchProposalEnvelope", "ExperimentReference")
SCHEMAS = ("common", *CONTRACTS)
PREFIX = "urn:aurum-arks:j0a:0.1:"


def deny_reference(uri):
    raise NoSuchResource(ref=uri)


class Contracts:
    def __init__(self, schema_root):
        self.schemas = {}
        for name in SCHEMAS:
            path = confined(schema_root, name + ".schema.json")
            schema = strict_loads(path.read_bytes())
            if schema.get("$id") != PREFIX + name:
                raise ContractError("SCHEMA_ID")
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise ContractError("SCHEMA_DIALECT")
            Draft202012Validator.check_schema(schema)
            self.schemas[name] = schema
        self.registry = Registry(retrieve=deny_reference).with_resources(
            (s["$id"], Resource.from_contents(s)) for s in self.schemas.values())
        self.checker = FormatChecker(formats=["date", "date-time"])
        for schema in self.schemas.values():
            self._check_refs(schema)
        self.validators = {n: Draft202012Validator(s, registry=self.registry,
                           format_checker=self.checker) for n, s in self.schemas.items()}

    def _check_refs(self, node):
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node["$ref"]
                if ref.split("#", 1)[0] not in {s["$id"] for s in self.schemas.values()}:
                    raise ContractError("SCHEMA_REF_NOT_LOCAL")
                self.registry.resolver().lookup(ref)
            for value in node.values():
                self._check_refs(value)
        elif isinstance(node, list):
            for value in node:
                self._check_refs(value)

    def validate(self, obj, expected=None):
        check_json(obj)
        if not isinstance(obj, dict):
            raise ContractError("CONTRACT_OBJECT_REQUIRED")
        name = obj.get("contract_type")
        if name not in CONTRACTS or (expected is not None and name != expected):
            raise ContractError("CONTRACT_UNKNOWN")
        try:
            self.validators[name].validate(obj)
        except ValidationError:
            raise ContractError("SCHEMA_INVALID") from None
        return obj
