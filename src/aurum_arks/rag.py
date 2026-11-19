"""Public ARKS retrieval interface. Backends are not part of this contract."""
from .rag_index import HybridRetrieval as Retrieval
__all__=['Retrieval']
