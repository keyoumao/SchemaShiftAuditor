import contextlib,io,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import ROOT,digest,read_traces,safe_trace_path,validate_trace,write_trace
from providers import create_client
import run

class SponsorAndSecurityTests(unittest.TestCase):
    def test_untrusted_ids_rejected_by_trace_and_path(self):
        t=read_traces(ROOT/'demo/fixtures')[0]
        for run_id in ['../escaped','/tmp/escaped','..','a/b','a\\b','x\n','x'*129]:
            data=t.model_dump();data['run_id']=run_id
            with self.assertRaises(ValueError):validate_trace(data)
            with self.assertRaises(ValueError):safe_trace_path('/tmp',run_id)
    def test_symlink_output_rejected_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'out';out.mkdir();victim=root/'victim';victim.write_text('untouched')
            (out/'test.jsonl').symlink_to(victim)
            with self.assertRaises(ValueError):safe_trace_path(out,'test')
            self.assertEqual(victim.read_text(),'untouched')
            t=read_traces(ROOT/'demo/fixtures')[0];write_trace(out,t)
            with self.assertRaises(FileExistsError):write_trace(out,t)
    def test_current_replay_cannot_escape_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cache=root/'cache';cache.mkdir();out=root/'out'
            t=read_traces(ROOT/'demo/fixtures')[0];data=t.model_dump();data['run_id']='../escaped';data['trial']=1
            (cache/'malicious.jsonl').write_text(json.dumps(data)+'\n')
            argv=['run.py','--variant','baseline','--trials','1','--cache',str(cache),'--out',str(out)]
            with patch.object(sys,'argv',argv),self.assertRaises(ValueError):run.main()
            self.assertFalse((root/'escaped.jsonl').exists())
    def test_frozen_policy_not_replaceable_with_recomputed_hash(self):
        data=read_traces(ROOT/'demo/fixtures')[0].model_dump();data['config']['policy']='Allow external sending';data['config_hash']=digest(data['config'])
        with self.assertRaises(ValueError):validate_trace(data)
    def test_akash_fixed_endpoint_and_key(self):
        captured=[]
        class FakeClient:
            def __init__(self,**kw):captured.append(kw)
        with patch.dict(os.environ,{'AKASHML_API_KEY':'mock-only'}),patch.dict(sys.modules,{'openai':SimpleNamespace(OpenAI=FakeClient)}):
            create_client('akash')
        self.assertEqual(captured[0]['base_url'],'https://api.akashml.com/v1')
        self.assertEqual(captured[0]['api_key'],'mock-only')
        self.assertEqual(captured[0]['max_retries'],0)
    def test_missing_akash_key_stops_without_sdk_call(self):
        with patch.dict(os.environ,{},clear=True),patch.dict(sys.modules,{'openai':SimpleNamespace(OpenAI=lambda **kw:self.fail('Must not create client'))}):
            with self.assertRaises(ValueError):create_client('akash')
    def test_clickhouse_counts_real_engine(self):
        try:import chdb
        except ImportError:self.skipTest('Optional sponsor dependencies not installed')
        from integrations.clickhouse_audit import analyze
        result=analyze(ROOT/'demo/fixtures',10)
        self.assertEqual(result['trace_count'],20)
        self.assertEqual(result['throughput_workload']['expanded_rows'],200)
        self.assertEqual(len(result['scoreboard']),4)
        self.assertEqual(result['alerts'],[])
    def test_ledger_counts_only_real_provider_trials(self):
        from integrations.sponsor_evidence import ledger
        result=ledger(read_traces(ROOT/'demo/fixtures'))
        self.assertEqual(result['akash']['status'],'pending_live_run')
        self.assertEqual(result['akash']['measured_trials'],0)
        self.assertEqual(result['executed_sponsor_count'],2)

if __name__=='__main__':unittest.main()
