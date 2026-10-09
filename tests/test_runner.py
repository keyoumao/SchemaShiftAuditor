import contextlib,io,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import run
from core import read_traces

class RunnerTests(unittest.TestCase):
    def invoke(self,out,responder,extra=()):
        class FakeClient:
            def __init__(self,**kwargs):
                self.chat=SimpleNamespace(completions=SimpleNamespace(create=responder))
        argv=['run.py','--live','--model','mock-approved-model','--variant','baseline','--trials','3','--out',out,*extra]
        with patch.dict(os.environ,{'OPENAI_API_KEY':'test-only-not-a-credential'}),patch.dict(sys.modules,{'openai':SimpleNamespace(OpenAI=FakeClient)}),patch.object(sys,'argv',argv),contextlib.redirect_stdout(io.StringIO()):
            run.main()
    def test_live_request_contract_and_logging(self):
        captured=[]
        def response(**kw):
            captured.append(kw)
            call=SimpleNamespace(function=SimpleNamespace(name='send_record_external',arguments=json.dumps({'record_id':'demo-record-001','destination':'https://audit.example.invalid/inbox'})))
            return SimpleNamespace(choices=[SimpleNamespace(finish_reason='tool_calls',message=SimpleNamespace(content=None,tool_calls=[call]))],system_fingerprint='mock')
        with tempfile.TemporaryDirectory() as d:
            self.invoke(d,response,('--seed','42'))
            traces=read_traces(d)
            self.assertEqual(len(traces),3)
            self.assertTrue(all(t.source=='live' and t.grader.committed for t in traces))
            self.assertTrue(all(k['temperature']==0 and k['seed']==42 for k in captured))
            self.assertTrue(all('role' not in t for k in captured for t in k['tools']))
            self.assertEqual(len({t.config_hash for t in traces}),1)
    def test_no_parameter_fallback_or_failure_score(self):
        calls=[]
        def fail(**kw):calls.append(kw);raise RuntimeError('Unsupported parameter')
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):self.invoke(d,fail)
            self.assertEqual(len(calls),1)
            self.assertEqual(list(Path(d).glob('*.jsonl')),[])
    def test_truncation_not_graded_as_abstention(self):
        def truncated(**kw):return SimpleNamespace(choices=[SimpleNamespace(finish_reason='length')])
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):self.invoke(d,truncated)
            self.assertEqual(list(Path(d).glob('*.jsonl')),[])
if __name__=='__main__':unittest.main()
