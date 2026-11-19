"""Pinned offline embedding model. No download or remote inference at runtime."""
import json,os,threading,hashlib,gc
from pathlib import Path
from .serialization import sha256,ContractError
from .provenance import require
DEFAULT_MODEL=Path(__file__).resolve().parents[2]/'runtime/rag_v1/model'

class LocalEmbedding:
    def __init__(self,root=DEFAULT_MODEL):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        self.np=np;self.root=Path(root);self.manifest=json.loads((self.root/'MANIFEST.json').read_bytes());self.inference_lock=threading.Lock()
        for name in ('model.onnx','tokenizer.json'):
            with (self.root/name).open('rb') as stream:require(hashlib.file_digest(stream,'sha256').hexdigest()==self.manifest['files'][name]['sha256'],'MODEL_ARTIFACT_CHANGED')
        self.tokenizer=Tokenizer.from_file(str(self.root/'tokenizer.json'));self.tokenizer.no_truncation();self.tokenizer.no_padding()
        self.ort=ort;self.session=None;self.dimension=self.manifest['dimension']

    def _ensure_session(self):
        if self.session is not None:return
        opts=self.ort.SessionOptions();opts.intra_op_num_threads=min(4,os.cpu_count() or 1);opts.inter_op_num_threads=1
        # Retained sessions must sleep between requests, leaving CPU to the UI
        # and the independent documentary/provenance checks.
        opts.add_session_config_entry('session.intra_op.allow_spinning','0')
        opts.add_session_config_entry('session.inter_op.allow_spinning','0')
        # Variable-length batches must not accumulate a large retained CPU arena.
        opts.enable_cpu_mem_arena=False;opts.enable_mem_pattern=False
        self.session=self.ort.InferenceSession(str(self.root/'model.onnx'),opts,providers=['CPUExecutionProvider'])

    def release_inference(self):
        with self.inference_lock:self.session=None;gc.collect()

    def count(self,text):return len(self.tokenizer.encode(text).ids)

    def encode(self,texts,query=False):
        with self.inference_lock:return self._encode(texts,query)

    def _encode(self,texts,query=False):
        self._ensure_session()
        np=self.np;prefix='query: ' if query else 'passage: '
        encoded=self.tokenizer.encode_batch([prefix+t for t in texts]);require(all(len(e.ids)<=512 for e in encoded),'EMBEDDING_TOKEN_LIMIT')
        n=max(len(e.ids) for e in encoded);ids=np.ones((len(encoded),n),dtype=np.int64);mask=np.zeros_like(ids)
        for i,e in enumerate(encoded):ids[i,:len(e.ids)]=e.ids;mask[i,:len(e.ids)]=1
        feeds={'input_ids':ids,'attention_mask':mask}
        if any(i.name=='token_type_ids' for i in self.session.get_inputs()):feeds['token_type_ids']=np.zeros_like(ids)
        hidden=self.session.run(None,feeds)[0];vectors=(hidden*mask[:,:,None]).sum(1)/mask.sum(1)[:,None]
        vectors=vectors/np.maximum(np.linalg.norm(vectors,axis=1,keepdims=True),1e-12)
        require(vectors.shape==(len(texts),self.dimension) and np.isfinite(vectors).all(),'EMBEDDING_INVALID')
        return vectors.astype('<f4')
