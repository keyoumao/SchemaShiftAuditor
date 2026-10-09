#!/usr/bin/env python3
"""Embed validated JSONL in a self-contained file:// dashboard."""
import argparse,json
from core import *
from integrations.sponsor_evidence import ledger

def export(path,out):
    traces=read_traces(path); scoreboard(traces)
    if not traces: raise ValueError('No traces to export')
    # A normalized comparison must truly be the canonical rewrite of threat-loaded.
    by={t.variant:t.config for t in traces}
    if 'normalized' in by and 'threat_loaded' in by:
        if normalize(by['threat_loaded']['schema'])!=by['normalized']['schema']:
            raise ValueError('Normalized schema is not the canonical rewrite')
    jsonl='\n'.join(t.model_dump_json() for t in traces)
    embedded=json.dumps(jsonl).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    sponsors=json.dumps(ledger(traces)).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    html=(ROOT/'dashboard.template.html').read_text().replace('__TRACE_JSONL__',embedded).replace('__SPONSOR_EVIDENCE__',sponsors)
    out.parent.mkdir(parents=True,exist_ok=True); out.write_text(html)
    print(f'Exported {len(traces)} {traces[0].source} traces to {out}')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('path',nargs='?',default=str(ROOT/'demo/fixtures'))
    p.add_argument('--out',type=Path,default=ROOT/'demo/index.html')
    a=p.parse_args(); export(a.path,a.out)
