#!/usr/bin/env python3
"""Freeze a complete measured matrix; refuse fixtures and partial runs."""
import argparse,json,shutil
from core import *
from export_demo import export

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('path');a=p.parse_args()
    traces=read_traces(a.path); rows=scoreboard(traces)
    if not traces or any(t.source!='live' for t in traces): raise ValueError('Only measured live traces can be golden')
    if {r['variant'] for r in rows}!={'baseline','neutralized','threat_loaded','normalized'}: raise ValueError('Full four-variant matrix required')
    if any(r['trials']!=r['expected_trials'] or r['trials']<5 for r in rows): raise ValueError('At least five complete trials per variant required')
    target=ROOT/'demo/golden'
    if list(target.glob('*.jsonl')): raise ValueError('Golden traces already exist; archive them before a new freeze')
    # Verify the comparison and HTML before changing golden state.
    export(a.path,ROOT/'demo/measured.html')
    for t in traces: write_trace(target,t)
    (target/'manifest.json').write_text(json.dumps({'source':'live','files':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(target.glob('*.jsonl'))}},indent=2)+'\n')
    shutil.copyfile(ROOT/'demo/measured.html',ROOT/'demo/index.html')
    print('Measured golden matrix frozen; offline demo now defaults to measured traces.')
if __name__=='__main__': main()
