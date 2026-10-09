"""Safe reproduction against original snapshot, restricted to TemporaryDirectory."""
import contextlib,importlib.util,io,json,sys,tempfile
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import ROOT,read_traces

def main():
    original=ROOT/'security/before/run.py'
    spec=importlib.util.spec_from_file_location('original_runner',original)
    core_spec=importlib.util.spec_from_file_location('original_core',ROOT/'security/before/core.py')
    before_core=importlib.util.module_from_spec(core_spec)
    sys.modules['original_core']=before_core
    core_spec.loader.exec_module(before_core)
    before_core.ROOT=ROOT
    module=importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules,{'core':before_core}):spec.loader.exec_module(module)
    with tempfile.TemporaryDirectory(prefix='schemashift-repro-') as temporary:
        temp=Path(temporary);cache=temp/'cache';cache.mkdir();out=temp/'output'
        t=read_traces(ROOT/'demo/fixtures')[0]
        data=t.model_dump();data['run_id']='../escaped';data['trial']=1
        data.pop('provider',None);data.pop('response_model',None)
        data['config'].pop('provider',None);data['config_hash']=before_core.digest(data['config'])
        (cache/'malicious.jsonl').write_text(json.dumps(data)+'\n')
        previous=sys.argv
        try:
            sys.argv=['run.py','--variant','baseline','--trials','1','--cache',str(cache),'--out',str(out)]
            with contextlib.redirect_stdout(io.StringIO()):module.main()
        finally:sys.argv=previous
        escaped=temp/'escaped.jsonl'
        result={'finding':'CWE-22 replay run_id path traversal','reproduced':escaped.is_file(),'escaped_output_directory':escaped.is_file(),'scope':'TemporaryDirectory only; no external files touched','snapshot':'security/before/run.py','payload_run_id':'../escaped','model_calls':0}
        if not escaped.is_file():raise AssertionError('Expected original replay to escape output directory')
        (ROOT/'security/evidence/reproduction.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
if __name__=='__main__':main()
