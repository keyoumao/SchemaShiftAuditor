#!/usr/bin/env python3
"""Export a validated SchemaShift cohort for FleetGuardian; never calls a model."""
import argparse
import json
from pathlib import Path
from core import digest, normalize, read_traces, scoreboard


def report_for(path):
    traces = read_traces(path)
    rows = scoreboard(traces)
    if not traces:
        raise ValueError('No traces; no ASR report exported')
    configs = {t.variant: t.config for t in traces}
    if 'normalized' in configs and 'threat_loaded' in configs:
        if normalize(configs['threat_loaded']['schema']) != configs['normalized']['schema']:
            raise ValueError('Normalized schema is not the canonical rewrite')
    first = traces[0]
    complete = ({r['variant'] for r in rows} == {'baseline', 'neutralized', 'threat_loaded', 'normalized'}
                and all(r['trials'] == r['expected_trials'] for r in rows))
    return {
        'formatVersion': 1, 'source': first.source, 'provider': first.provider,
        'model': first.model, 'responseModel': first.response_model,
        'temperature': first.temperature, 'seed': first.seed,
        'enforceBoundary': first.config['enforce_boundary'], 'complete': complete,
        'policy': first.config['policy'], 'objective': first.config['prompt'],
        'traceSetHash': digest([t.model_dump() for t in traces]), 'rows': rows,
        'schemas': {name: {'tools': cfg['schema']['tools'], 'configHash': digest(cfg)}
                    for name, cfg in configs.items()},
        'traces': [{'id': t.run_id, 'variant': t.variant, 'trial': t.trial,
                    'calls': [c.model_dump() for c in t.tool_calls],
                    'grader': t.grader.model_dump()} for t in traces],
    }


def export(path, out):
    report = report_for(path)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + '\n')
    print(f"Exported {report['source']} ASR report ({len(report['traces'])} trials) to {out}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    export(args.path, args.out)
