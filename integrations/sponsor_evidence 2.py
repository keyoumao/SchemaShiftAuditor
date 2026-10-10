"""Build an honest, cacheable sponsor-use ledger linked to traces and code."""
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import ROOT,digest,scoreboard

def file_hash(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def security_summary():
    evidence=ROOT/'security/evidence'
    paths=[evidence/'semgrep-before.json',evidence/'semgrep-after.json',evidence/'reproduction.json']
    if not all(p.exists() for p in paths):return {'tool':'Semgrep CE','status':'not_scanned'}
    before,after,repro=[json.loads(p.read_text()) for p in paths]
    if before.get('errors') or after.get('errors'):raise ValueError('Semgrep scan errors; cannot report scan complete')
    production=after.get('paths',{}).get('scanned',[])
    # Capture exact scanned bytes; subsequent exports reject stale code evidence.
    summary={'tool':'Semgrep CE','status':'executed','version':after['version'],'before_matches':len(before['results']),'after_matches':len(after['results']),'confirmed_vulnerabilities':int(bool(repro['reproduced'])),'finding':'CWE-22 replay output path traversal','triage':'Two matches, one confirmed cache replay vulnerability; live write used a generated UUID. A custom project rule, not a comprehensive security audit.','production_hashes':{p:file_hash(ROOT/p) for p in production},'before_snapshot_hash':file_hash(ROOT/'security/before/run.py'),'rule_hash':file_hash(ROOT/'security/run-id-path.yaml'),'reproduction':repro}
    (evidence/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    return summary

def ledger(traces):
    akash=[t for t in traces if t.source=='live' and t.provider=='akash']
    provider={'tool':'AkashML','status':'executed' if akash else 'pending_live_run','measured_trials':len(akash),'model':akash[0].model if akash else None,'message':'Real AkashML calls recorded in these traces.' if akash else 'Adapter implemented; actual AkashML model trials still required. Fixtures and mocks do not count.'}
    path=ROOT/'demo/clickhouse-report.json'
    if path.exists():
        analytics=json.loads(path.read_text())
        if analytics['trace_set_hash']!=digest([t.model_dump() for t in traces]) or analytics['scoreboard']!=scoreboard(traces):
            raise ValueError('Stale ClickHouse report. Rerun clickhouse_audit.py on this exact trace set before export.')
    else:analytics={'tool':'ClickHouse via chDB','status':'not_executed'}
    path=ROOT/'security/evidence/summary.json'
    security=json.loads(path.read_text()) if path.exists() else {'tool':'Semgrep CE','status':'not_scanned'}
    if security.get('status')=='executed':
        checks=dict(security['production_hashes']);checks['security/before/run.py']=security['before_snapshot_hash'];checks['security/run-id-path.yaml']=security['rule_hash']
        if any(file_hash(ROOT/p)!=sha for p,sha in checks.items()):raise ValueError('Stale Semgrep evidence. Rerun security scan and rebuild summary.')
    return {'akash':provider,'clickhouse':analytics,'semgrep':security,'executed_sponsor_count':sum(x['status']=='executed' for x in [provider,analytics,security]),'eligibility':'Sponsor usage evidence, not organizer confirmation of eligibility. Confirm chDB and Semgrep CE/custom-rule use count for event requirements.'}

if __name__=='__main__':
    result=security_summary();print(f"Semgrep evidence: {result.get('before_matches',0)} before matches, {result.get('after_matches',0)} after matches; confirmed vulnerabilities {result.get('confirmed_vulnerabilities',0)}")
