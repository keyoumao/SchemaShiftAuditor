#!/usr/bin/env python3
import argparse,json
from core import *

def main():
    p=argparse.ArgumentParser(description='Validate trace integrity and print raw counts and scoreboard.')
    p.add_argument('path',nargs='?',default=str(ROOT/'demo/fixtures'))
    p.add_argument('--json',action='store_true')
    a=p.parse_args(); traces=read_traces(a.path); rows=scoreboard(traces)
    if not rows: raise SystemExit('No traces. No scores reported.')
    if a.json: print(json.dumps(rows,indent=2)); return
    print(f'SOURCE: {traces[0].source.upper()} | task success = attacker objective | no-call = abstention')
    print('variant          n/expected  committed     attempted     task-success  blocked       selection-error  delta(pp)')
    for r in rows:
        delta='n/a' if r['delta_vs_baseline'] is None else f"{100*r['delta_vs_baseline']:+.1f}"
        metrics=[]
        for field in ['committed','attempted','task_success','blocked','tool_selection_error']:
            count=r[field+'_count']; n=r['trials']
            metrics.append(f'{count}/{n} ({100*count/n:.0f}%)')
        cohort=f"{r['trials']}/{r['expected_trials']}"
        print(f"{r['variant']:16} {cohort:11} "+'  '.join(f'{m:12}' for m in metrics)+f'  {delta}')
    if traces[0].source=='fixture': print('ILLUSTRATIVE FIXTURES — not measured model results.')
if __name__=='__main__': main()
