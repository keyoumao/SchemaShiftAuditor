"""Bounded, offline Semgrep scanning of explicitly registered local Git checkouts.

Repository code is copied as data into a temporary snapshot and never executed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

RULES = Path(__file__).with_name('source-rules.yaml')
EXTENSIONS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
EXCLUDED = {'.git', '.venv', 'venv', 'node_modules', 'dist', 'build', '__pycache__'}
MAX_FILES = 2000
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 20_000_000


class ScanError(Exception):
    """A scan cannot provide complete findings."""


def repository_key(value):
    if not isinstance(value, str):
        raise ValueError('Repository must be a GitHub URL.')
    match = re.fullmatch(r'(?:https://)?github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?/?', value)
    if not match:
        raise ValueError('Use a github.com/owner/repository URL.')
    return match[1].lower()


def git(root, *args):
    try:
        return subprocess.run(['git', '-C', str(root), *args], check=True,
                              capture_output=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanError('Cannot inspect the configured Git checkout.') from exc


def snapshot(root, destination):
    """Include tracked and nonignored working files; reject symlinks and oversized input."""
    names = git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').split(b'\0')
    digest = hashlib.sha256()
    count = total = 0
    for name in sorted(set(names)):
        if not name:
            continue
        relative = Path(os.fsdecode(name))
        if relative.is_absolute() or '..' in relative.parts:
            raise ScanError('Unsafe path in checkout.')
        if relative.suffix not in EXTENSIONS or EXCLUDED.intersection(relative.parts):
            continue
        source = root / relative
        if any(p.is_symlink() for p in [source, *source.parents] if p != root.parent):
            raise ScanError('Source symlinks are not supported; remove them before scanning.')
        if not source.exists():  # locally deleted tracked file
            continue
        if not source.is_file() or not source.resolve().is_relative_to(root):
            raise ScanError('Source path is outside the configured checkout.')
        with source.open('rb') as stream:
            content = stream.read(MAX_FILE_BYTES + 1)
        count += 1
        total += len(content)
        if len(content) > MAX_FILE_BYTES or count > MAX_FILES or total > MAX_TOTAL_BYTES:
            raise ScanError('Source exceeds scan limits (2,000 files, 1 MB/file, 20 MB total).')
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        digest.update(name + b'\0' + hashlib.sha256(content).digest())
    if not count:
        raise ScanError('No supported Python or JavaScript/TypeScript source files found.')
    return count, digest.hexdigest()


def scan_checkout(root):
    root = Path(root).resolve()
    executable = next((str(p) for p in [Path(sys.executable).parent / 'pysemgrep',
                       Path(shutil.which('pysemgrep') or shutil.which('semgrep') or '/nonexistent')]
                       if p.is_file()), None)
    if not executable:
        raise ScanError('Semgrep is unavailable. Install requirements-sponsors.txt in the backend environment.')
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    branch = git(root, 'branch', '--show-current').decode().strip()
    with tempfile.TemporaryDirectory(prefix='fleet-scan-') as temporary:
        work = Path(temporary)
        source = work / 'source'
        source.mkdir()
        count, fingerprint = snapshot(root, source)
        # Semgrep's implicit defaults skip tests/. Our snapshot already defines
        # the intended scope, so override that default instead of reporting clean
        # results for only a subset of the selected files.
        (source / '.semgrepignore').write_text('')
        env = {**os.environ, 'SEMGREP_LOG_FILE': str(work / 'semgrep.log'),
               'SEMGREP_SETTINGS_FILE': str(work / 'settings.yml'), 'SEMGREP_SEND_METRICS': 'off'}
        env.pop('SEMGREP_APP_TOKEN', None)
        command = [executable, 'scan', '--config', str(RULES), '--json', '--quiet',
                   '--metrics', 'off', '--disable-version-check', '--no-git-ignore',
                   '--no-rewrite-rule-ids', '--disable-nosem', '--jobs', '1', '--timeout', '5',
                   '--max-target-bytes', str(MAX_FILE_BYTES), '.']
        try:
            result = subprocess.run(command, cwd=source, env=env, capture_output=True,
                                    timeout=90, check=False)
            if result.returncode != 0:
                raise ScanError('Semgrep failed; no scan results were accepted.')
            report = json.loads(result.stdout)
        except subprocess.TimeoutExpired as exc:
            raise ScanError('Scan exceeded its 90-second time limit.') from exc
        except (OSError, ValueError) as exc:
            raise ScanError('Semgrep did not return a valid report.') from exc
        if report.get('errors'):
            raise ScanError('Semgrep reported parse errors or incomplete analysis. Fix source errors and retry.')
        if len(report.get('paths', {}).get('scanned', [])) != count:
            raise ScanError('Semgrep skipped source files; a complete scan could not be confirmed.')
        now = int(time.time() * 1000)
        findings = []
        for item in report['results']:
            extra = item['extra']
            metadata = extra.get('metadata', {})
            path = Path(item['path'])
            if path.is_absolute() or '..' in path.parts:
                raise ScanError('Scanner returned an invalid finding path.')
            line = item['start']['line']
            rule = item['check_id']
            findings.append({
                'id': hashlib.sha256(f'{rule}:{path}:{line}'.encode()).hexdigest()[:20],
                'ruleId': rule, 'title': extra['message'],
                'severity': {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}[extra['severity']],
                'category': metadata.get('category', 'Unsafe tool execution'),
                'file': path.as_posix(), 'line': line, 'cwe': metadata.get('cwe', ''),
                'status': 'open', 'foundAt': now,
                # Source lines may contain credentials; never return them to the browser.
                'snippet': 'Source omitted. Review this location in your local checkout.',
                'fix': metadata.get('remediation', 'Review and validate the affected operation.'),
            })
        findings.sort(key=lambda f: (f['file'], f['line'], f['ruleId']))
        score = max(0, 100 - sum({'high': 20, 'medium': 10, 'low': 3}[f['severity']] for f in findings))
        return {'vulns': findings, 'securityScore': score, 'lastScan': now,
                'scan': {'source': 'semgrep', 'version': report.get('version'), 'commit': commit,
                         'branch': branch, 'filesScanned': count, 'snapshotSha256': fingerprint,
                         'rulesSha256': hashlib.sha256(RULES.read_bytes()).hexdigest(),
                         'scope': 'Local working tree; Python and JavaScript/TypeScript; seven review rules'}}
