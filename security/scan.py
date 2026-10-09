#!/usr/bin/env python3
"""Offline local-rule Semgrep before/after scan with a fixed target list."""
import os,shutil,subprocess,sys,sysconfig
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import ROOT
from integrations.sponsor_evidence import security_summary

def main():
    candidates=[shutil.which('pysemgrep'),shutil.which('semgrep'),str(Path(sysconfig.get_path('scripts',scheme='posix_user'))/'pysemgrep')]
    executable=next((p for p in candidates if p and Path(p).is_file()),None)
    if not executable:raise SystemExit('Install requirements-sponsors.txt; Semgrep CLI not available')
    targets=['run.py','core.py','freeze.py','providers.py','export_demo.py','integrations/clickhouse_audit.py','integrations/sponsor_evidence.py','security/scan.py']
    for label,files in [('before',['security/before/run.py']),('after',targets)]:
        command=[executable,'scan','--config','security/run-id-path.yaml','--metrics','off','--disable-version-check','--json','--output',f'security/evidence/semgrep-{label}.json',*files]
        subprocess.run(command,cwd=ROOT,check=True)
    report=security_summary()
    if report['after_matches']!=0:raise SystemExit('Active code still matches path rule; inspect report')
    print(f"Semgrep {report['version']}: {report['before_matches']} original matches → {report['after_matches']} active matches; {report['confirmed_vulnerabilities']} confirmed replay vulnerability.")
if __name__=='__main__':main()
