"""Offline language preparation; no golden targets, source IDs, or query rules."""
import re,json,hashlib,threading
from pathlib import Path
from .provenance import require
ROOT=Path(__file__).resolve().parents[2]/'runtime/rag_v1/query_translation'
FRENCH=frozenset('le la les un une des du au aux ce ces cette cet quels quelles quel quelle pourquoi comment est sont être avec dans pour sur sous entre tandis leurs leur chaque dont puis et ou en de que qui il ils elle elles'.split())
ENGLISH=frozenset('the a an of to is are how why what which with for and or in on under between their each then'.split())

def is_french(text):
    words=set(re.findall(r'[^\W_]+',text.casefold()))
    return len(words&FRENCH)>=2 and len(words&FRENCH)>len(words&ENGLISH)

class LocalQueryTranslation:
    def __init__(self,root=ROOT):
        import numpy as np,onnxruntime as ort
        import sentencepiece as spm
        self.np=np;self.root=Path(root);self.manifest=json.loads((self.root/'MANIFEST.json').read_bytes());self.lock=threading.Lock();self.cache={}
        for name,item in self.manifest['files'].items():
            with (self.root/name).open('rb') as f:require(hashlib.file_digest(f,'sha256').hexdigest()==item['sha256'],'QUERY_TRANSLATION_ARTIFACT_CHANGED')
        self.config=json.loads((self.root/'config.json').read_bytes())
        self.source_spm=spm.SentencePieceProcessor(model_file=str(self.root/'source.spm'));self.target_spm=spm.SentencePieceProcessor(model_file=str(self.root/'target.spm'))
        self.vocab=json.loads((self.root/'vocab.json').read_bytes());self.inverse={v:k for k,v in self.vocab.items()}
        opts=ort.SessionOptions();opts.intra_op_num_threads=2;opts.inter_op_num_threads=1;opts.enable_cpu_mem_arena=False;opts.enable_mem_pattern=False
        opts.add_session_config_entry('session.intra_op.allow_spinning','0')
        opts.add_session_config_entry('session.inter_op.allow_spinning','0')
        self.encoder=ort.InferenceSession(str(self.root/'onnx/encoder_model_quantized.onnx'),opts,providers=['CPUExecutionProvider'])
        self.decoder=ort.InferenceSession(str(self.root/'onnx/decoder_model_quantized.onnx'),opts,providers=['CPUExecutionProvider'])
    def translate(self,text):
        if not is_french(text):return text
        with self.lock:
            if text in self.cache:return self.cache[text]
            np=self.np;ids=[self.vocab.get(piece,self.vocab['<unk>']) for piece in self.source_spm.encode(text,out_type=str)]+[self.config['eos_token_id']]
            require(len(ids)<=512,'QUERY_TRANSLATION_TOKEN_LIMIT')
            source=np.array([ids],dtype=np.int64);mask=np.ones_like(source)
            hidden=self.encoder.run(None,{'input_ids':source,'attention_mask':mask})[0]
            output=[self.config['decoder_start_token_id']]
            for step in range(511):
                logits=self.decoder.run(['logits'],{'input_ids':np.array([output],dtype=np.int64),'encoder_attention_mask':mask,'encoder_hidden_states':hidden})[0][0,-1].copy()
                logits[self.config['pad_token_id']]=-np.inf
                token=int(np.argmax(logits));output.append(token)
                if token==self.config['eos_token_id']:break
            else:raise ValueError('QUERY_TRANSLATION_OUTPUT_LIMIT')
            result=self.target_spm.decode([self.inverse[i] for i in output[1:-1]]).strip();require(bool(result),'QUERY_TRANSLATION_EMPTY')
            if len(self.cache)>=128:self.cache.pop(next(iter(self.cache)))
            self.cache[text]=result;return result
