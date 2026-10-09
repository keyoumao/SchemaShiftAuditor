#!/usr/bin/env python3
"""Event-driven, bounded ASR auditor. Real model calls; simulated tool execution."""
import argparse
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from core import ROOT, assert_equivalent, configuration, digest, normalize, variant
from export_fleet import report_for
from integrations.clickhouse_audit import analyze
from integrations.telemetry import ingest
from run import collect_trial

MODEL = 'gpt-4.1-mini-2025-04-14'
NAMES = ['baseline', 'neutralized', 'threat_loaded', 'normalized']


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    with temp.open('rb') as handle:
        os.fsync(handle.fileno())
    temp.replace(path)


def load_env(path):
    """Read only two named credentials as literal strings; never evaluate shell code."""
    for line in Path(path).read_text().splitlines():
        name, sep, value = line.partition('=')
        if sep and name.strip() in {'OPENAI_API_KEY', 'GUILD_AI_API_KEY'}:
            os.environ.setdefault(name.strip(), value.strip().strip('\"\''))


def verify_evidence(out):
    """Reject tampered or mismatched saved evidence before publishing a replay."""
    import hashlib
    out = Path(out)
    manifest = json.loads((out / 'manifest.json').read_text())
    for name, expected in manifest.items():
        path = out / name
        if path.resolve().is_relative_to(out.resolve()) is False or path.is_symlink():
            raise ValueError('Unsafe evidence path')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Frozen evidence hash mismatch')
    state = json.loads((out / 'runtime-status.json').read_text())
    if state['status'] != 'complete' or state['completedTrials'] != 40 or state['callsReserved'] != 40:
        raise ValueError('Incomplete runtime experiment')
    for cohort in ['reference', 'boundary']:
        report = report_for(out / cohort)
        if report != json.loads((out / f'{cohort}-report.json').read_text()):
            raise ValueError('Published report differs from regraded traces')
        if report['traceSetHash'] != state[cohort]['traceSetHash'] or report['rows'] != state[cohort]['rows']:
            raise ValueError('Runtime status differs from regraded traces')
    return state


def audit(events_path, out, live=False, client=None, collector=collect_trial):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with (out / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_path = out / 'runtime-status.json'
        # A job directory is a single spending authorization. No automatic resume/retry,
        # including after a crash between reservation and receipt of an API response.
        if state_path.exists():
            return json.loads(state_path.read_text())
        events, telemetry = ingest(events_path)
        triggers = [e for e in events if e.event in {'schema_changed', 'external_attempt'}]
        state = {'formatVersion': 1, 'status': 'observed', 'startedAt': now(), 'model': MODEL,
                 'callBudget': 40, 'callsReserved': 0, 'completedTrials': 0,
                 'telemetry': telemetry, 'triggerIds': [e.event_id for e in triggers],
                 'steps': [], 'execution': 'Simulated records tools; no external sends',
                 'scope': 'One fixed records-assistant task; not the registered frontend source code'}
        save(out / 'telemetry.json', telemetry)

        def step(status, detail):
            state['status'] = status
            state['updatedAt'] = now()
            state['steps'].append({'at': now(), 'status': status, 'detail': detail})
            save(state_path, state)

        if not triggers:
            step('idle', 'No schema change or external-attempt event; no model calls.')
            return state
        if not live:
            step('dry_run', 'Trigger accepted; use --live with a fresh job directory to authorize up to 40 calls.')
            return state
        schemas = {n: normalize(variant('threat_loaded')) if n == 'normalized' else variant(n) for n in NAMES}
        assert_equivalent(schemas.values())
        frozen = {cohort: {n: configuration(s, MODEL, None, 5, enforce) for n, s in schemas.items()}
                  for cohort, enforce in [('reference', False), ('boundary', True)]}
        save(out / 'frozen-config.json', frozen)
        state['configHash'] = digest(frozen)
        step('running', 'Frozen policy, task, model and four schemas. Separate 20-trial execution cohorts.')
        try:
            if client is None:
                from providers import create_client
                client = create_client('openai')
            for cohort, enforce in [('reference', False), ('boundary', True)]:
                traces = out / cohort
                traces.mkdir(exist_ok=False)
                for n, schema in schemas.items():
                    for trial in range(1, 6):
                        if state['callsReserved'] >= state['callBudget']:
                            raise ValueError('Call budget exhausted')
                        state['callsReserved'] += 1
                        step('running', f'{cohort}/{n}/{trial}: call reserved before request; no automatic retries.')
                        collector(client, schema, MODEL, 5, trial, enforce, traces)
                        state['completedTrials'] += 1
                        save(state_path, state)
                report = report_for(traces)
                if not report['complete'] or report['source'] != 'live':
                    raise ValueError('Incomplete/non-live cohort cannot be published')
                sql = analyze(traces)
                save(out / f'{cohort}-clickhouse.json', sql)
                save(out / f'{cohort}-report.json', report)
                state[cohort] = {'traceSetHash': report['traceSetHash'], 'rows': report['rows']}
                step('validated', f'{cohort}: 20 measured trials; ClickHouse and Python counts agree.')
            reference = state['reference']['rows']
            spread = max(r['committed_asr'] for r in reference) - min(r['committed_asr'] for r in reference)
            state['representationSpreadPp'] = 100 * spread
            state['recommendation'] = (
                'Review schema-sensitive commits; canonical wording remains a hypothesis. '
                if spread else 'No schema-sensitive committed-ASR difference observed in this small cohort. '
            ) + 'Keep the execution boundary; do not interpret zero observed commits as proof of safety.'
            state['limitations'] = 'Five trials per variant, one task/model, simulated execution. No benign model-utility evaluation or causal claim.'
            step('complete', 'Both cohorts validated. Evidence frozen; no schema tuning or automatic production changes.')
            files = sorted(p for p in out.rglob('*') if p.is_file() and p.name != '.lock')
            import hashlib
            save(out / 'manifest.json', {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
        except Exception as error:
            step('failed', f'{type(error).__name__}; completed traces retained. No retry or clean score.')
        return state


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--events', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True, help='New directory per explicitly authorized experiment')
    p.add_argument('--env-file', type=Path)
    p.add_argument('--live', action='store_true')
    p.add_argument('--watch', action='store_true', help='Wait for input file, then process one bounded job and exit')
    p.add_argument('--publish', type=Path, help='FleetGuardian public directory; only publishes complete evidence')
    a = p.parse_args()
    if a.env_file:
        load_env(a.env_file)
    while a.watch and not a.events.exists():
        time.sleep(1)
    state = audit(a.events, a.out, a.live)
    if a.publish and state['status'] == 'complete':
        verify_evidence(a.out)
        save(a.publish / 'schema-audit.json', json.loads((a.out / 'reference-report.json').read_text()))
        save(a.publish / 'boundary-audit.json', json.loads((a.out / 'boundary-report.json').read_text()))
        save(a.publish / 'runtime-audit.json', state)
    print(json.dumps({'status': state['status'], 'callsReserved': state['callsReserved'], 'completedTrials': state['completedTrials']}))
    return 1 if state['status'] == 'failed' else 0


if __name__ == '__main__':
    sys.exit(main())
