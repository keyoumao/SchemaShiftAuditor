#!/usr/bin/env python3
"""Replay by default; model API only with explicit --live."""
import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from core import *

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variant',choices=['baseline','neutralized','threat_loaded','normalized','all'],default='baseline')
    p.add_argument('--trials',type=int,default=3)
    p.add_argument('--live',action='store_true')
    p.add_argument('--model',help='Explicit team-approved Chat Completions model supporting temperature=0')
    p.add_argument('--seed',type=int,default=None,help='Omitted by default; set only if the approved model supports seed')
    p.add_argument('--enforce-boundary',action='store_true')
    p.add_argument('--out',type=Path,default=ROOT/'runs')
    p.add_argument('--cache',type=Path,default=ROOT/'demo/fixtures')
    a=p.parse_args()
    if not 1<=a.trials<=100: p.error('--trials must be 1..100')
    names=['baseline','neutralized','threat_loaded','normalized'] if a.variant=='all' else [a.variant]
    schemas={n:variant(n) if n!='normalized' else normalize(variant('threat_loaded')) for n in names}
    assert_equivalent([variant(n) for n in ['baseline','neutralized','threat_loaded']]+list(schemas.values()))
    if not a.live:
        cache=read_traces(a.cache)
        selected=[t for t in cache if t.variant in names and t.trial<=a.trials]
        if any(sum(t.variant==n for t in selected)!=a.trials for n in names):
            p.error('Cache lacks requested trials; use an appropriate cache or --live')
        a.out.mkdir(parents=True,exist_ok=True)
        for t in selected:
            (a.out/f'{t.run_id}.jsonl').write_text(t.model_dump_json()+'\n')
        print(f'Replayed {len(selected)} traces from {a.cache}; source={selected[0].source}. No model calls.')
        return
    if not a.model: p.error('--live requires --model')
    if not os.environ.get('OPENAI_API_KEY'): p.error('OPENAI_API_KEY unavailable; no live calls made')
    from openai import OpenAI
    client=OpenAI(timeout=30,max_retries=0)
    a.out.mkdir(parents=True,exist_ok=True)
    for n,schema in schemas.items():
        cfg=configuration(schema,a.model,a.seed,a.trials,a.enforce_boundary)
        for trial in range(1,a.trials+1):
            started=datetime.now(timezone.utc).isoformat()
            kwargs={'model':a.model,'temperature':0,'messages':[{'role':'system','content':POLICY},{'role':'user','content':PROMPT}], 'tools':[{'type':'function','function':t['function']} for t in schema['tools']], 'tool_choice':'auto','parallel_tool_calls':False,'max_completion_tokens':400}
            if a.seed is not None: kwargs['seed']=a.seed
            # Never retry by changing temperature/seed/model. API failures are not graded successes.
            response=client.chat.completions.create(**kwargs)
            if len(response.choices)!=1 or response.choices[0].finish_reason not in ['stop','tool_calls']:
                raise ValueError('Incomplete/filtered model response; not graded')
            message=response.choices[0].message
            raw=[]
            for call in message.tool_calls or []:
                try: args=json.loads(call.function.arguments)
                except json.JSONDecodeError: args=call.function.arguments
                raw.append((call.function.name,args))
            calls=execute(raw,schema,a.enforce_boundary,datetime.now(timezone.utc).isoformat())
            trace=Trace(run_id=str(uuid.uuid4()),variant=n,trial=trial,trial_count=a.trials,model=a.model,temperature=0,seed=a.seed,config_hash=digest(cfg),started_at=started,source='live',config=cfg,response_text=message.content or '',system_fingerprint=getattr(response,'system_fingerprint',None),tool_calls=calls,grader=grade(calls))
            validate_trace(trace.model_dump())
            (a.out/f'{trace.run_id}.jsonl').write_text(trace.model_dump_json()+'\n')
            print(f'{n} {trial}/{a.trials}: saved {trace.run_id}')
if __name__=='__main__':
    try: main()
    except Exception as e:
        # Avoid printing API exception bodies that may include request details.
        print(f'Run stopped: {type(e).__name__}. Inspect configuration locally; completed traces retained.',file=sys.stderr)
        sys.exit(1)
