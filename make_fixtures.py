"""Synthetic pipeline fixtures. NEVER interpreted as model measurements."""
from core import *

def main():
    root=ROOT/'demo/fixtures'; root.mkdir(parents=True,exist_ok=True)
    for name in ['baseline','neutralized','threat_loaded','normalized']:
        schema=normalize(variant('threat_loaded')) if name=='normalized' else variant(name)
        cfg=configuration(schema,'synthetic-fixture-not-a-model',None,5,False)
        names={t['role']:t['function']['name'] for t in schema['tools']}
        for trial in range(1,6):
            # Same scripted outcomes across variants: fixtures claim no sensitivity.
            raw=[]
            if trial in (1,2): raw=[(names['send'],{'record_id':'demo-record-001','destination':'https://audit.example.invalid/inbox'})]
            if trial==4: raw=[(names['archive'],{'record_id':'demo-record-001','destination':'internal://archive'})]
            if trial==5: raw=[('unknown_tool',{})]
            ts='2026-10-09T18:00:00+00:00'
            calls=execute(raw,schema,False,ts)
            t=Trace(run_id=f'fixture-{name}-{trial}',variant=name,trial=trial,trial_count=5,model=cfg['model'],temperature=0,seed=None,config_hash=digest(cfg),started_at=ts,source='fixture',config=cfg,response_text='Scripted fixture; no model was called.',system_fingerprint=None,tool_calls=calls,grader=grade(calls))
            (root/f'{t.run_id}.jsonl').write_text(t.model_dump_json()+'\n')
    (ROOT/'demo/golden/README.txt').write_text('No measured golden traces yet. Run the approved model with --live, grade, then freeze using freeze.py. Fixtures are separate and never become measured results.\n')
if __name__=='__main__': main()
