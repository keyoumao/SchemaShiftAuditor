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
from monitoring.hooks import emit

def collect_trial(client, schema, model, trials, trial, enforce_boundary, out, provider="openai", seed=None):
    """One request, no retries or fallback; validate before storing simulated outcome."""
    cfg=configuration(schema,model,seed,trials,enforce_boundary,provider)
    started=datetime.now(timezone.utc).isoformat()
    run_id=str(uuid.uuid4())
    emit(run_id,"started",digest(cfg),schema["name"])
    kwargs={'model':model,'temperature':0,'messages':[{'role':'system','content':POLICY},{'role':'user','content':PROMPT}], 'tools':[{'type':'function','function':t['function']} for t in schema['tools']], 'tool_choice':'auto','parallel_tool_calls':False,'max_completion_tokens':400}
    if seed is not None: kwargs['seed']=seed
    # Never retry by changing temperature/seed/model. API failures are not graded successes.
    try:
        response=client.chat.completions.create(**kwargs)
    except Exception:
        emit(run_id,"provider_error",digest(cfg),schema["name"])
        raise
    if len(response.choices)!=1 or response.choices[0].finish_reason not in ['stop','tool_calls']:
        emit(run_id,"provider_error",digest(cfg),schema["name"])
        raise ValueError('Incomplete/filtered model response; not graded')
    message=response.choices[0].message
    raw=[]
    for call in message.tool_calls or []:
        try: args=json.loads(call.function.arguments)
        except json.JSONDecodeError: args=call.function.arguments
        raw.append((call.function.name,args))
    calls=execute(raw,schema,enforce_boundary,datetime.now(timezone.utc).isoformat())
    trace=Trace(run_id=run_id,variant=schema['name'],trial=trial,trial_count=trials,model=model,temperature=0,seed=seed,config_hash=digest(cfg),started_at=started,source='live',provider=provider,response_model=getattr(response,'model',model),config=cfg,response_text=message.content or '',system_fingerprint=getattr(response,'system_fingerprint',None),tool_calls=calls,grader=grade(calls))
    validate_trace(trace.model_dump())
    write_trace(out,trace)
    kind = 'forbidden_commit' if trace.grader.committed else 'blocked_attempt' if trace.grader.blocked else 'execution_error' if any(c.status == 'error' for c in calls) else 'completed'
    emit(run_id,kind,digest(cfg),schema['name'],trace.grader.attempted,trace.grader.committed,trace.grader.blocked)
    return trace

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variant',choices=['baseline','neutralized','threat_loaded','normalized','all'],default='baseline')
    p.add_argument('--trials',type=int,default=3)
    p.add_argument('--live',action='store_true')
    p.add_argument('--provider',choices=['openai','akash'],default='openai',help='Fixed API provider; AkashML uses AKASHML_API_KEY')
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
            write_trace(a.out,t)
        print(f'Replayed {len(selected)} traces from {a.cache}; source={selected[0].source}. No model calls.')
        return
    if not a.model: p.error('--live requires --model')
    from providers import PROVIDERS,create_client
    key_name=PROVIDERS[a.provider][0]
    if not os.environ.get(key_name):p.error(f'{key_name} unavailable; no live calls made')
    client=create_client(a.provider)
    a.out.mkdir(parents=True,exist_ok=True)
    for n,schema in schemas.items():
        cfg=configuration(schema,a.model,a.seed,a.trials,a.enforce_boundary,a.provider)
        for trial in range(1,a.trials+1):
            trace=collect_trial(client,schema,a.model,a.trials,trial,a.enforce_boundary,a.out,a.provider,a.seed)
            print(f'{n} {trial}/{a.trials}: saved {trace.run_id}')
if __name__=='__main__':
    try: main()
    except Exception as e:
        # Avoid printing API exception bodies that may include request details.
        print(f'Run stopped: {type(e).__name__}. Inspect configuration locally; completed traces retained.',file=sys.stderr)
        sys.exit(1)
