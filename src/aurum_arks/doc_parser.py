"""Finite TXT parsing in a separate process; no third-party parser.

64 KiB input, 512 blocks, 10 seconds, offsets-only bounded output. No OS memory
limit is claimed. Arbitrary PDF parsing remains unavailable for that reason too.
"""
import json
import subprocess
import sys

from .provenance import require
from .serialization import ContractError

WORKER = '''import sys,json
raw=sys.stdin.buffer.read(65537)
if len(raw)>65536: sys.exit(2)
try: raw.decode('utf-8',errors='strict')
except UnicodeError: sys.exit(3)
blocks=raw.splitlines(keepends=True)
if len(blocks)>512: sys.exit(4)
ranges=[]; start=0
for block in blocks:
 end=start+len(block); ranges.append([start,end]); start=end
sys.stdout.write(json.dumps(ranges))
'''


def txt_ranges(raw):
    require(type(raw) is bytes and 0<len(raw)<=65536,'SOURCE_SIZE_LIMIT')
    try:
        result=subprocess.run([sys.executable,'-I','-B','-c',WORKER],input=raw,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except subprocess.TimeoutExpired:
        raise ContractError('TXT_PARSER_TIMEOUT') from None
    if result.returncode:
        raise ContractError({2:'SOURCE_SIZE_LIMIT',3:'UTF8_BOUNDARY_OR_ENCODING',4:'TXT_BLOCK_LIMIT'}.get(result.returncode,'TXT_PARSER_FAILED'))
    require(len(result.stdout)<=16384,'TXT_PARSER_OUTPUT_LIMIT')
    ranges=json.loads(result.stdout)
    require(type(ranges) is list and 0<len(ranges)<=512,'TXT_PARSER_INVALID_OUTPUT')
    previous=0
    for pair in ranges:
        require(type(pair) is list and len(pair)==2 and all(type(n) is int for n in pair)
                and pair[0]==previous and pair[0]<pair[1]<=len(raw),'TXT_PARSER_INVALID_OUTPUT')
        previous=pair[1]
    require(previous==len(raw),'TXT_PARSER_INCOMPLETE')
    return ranges
