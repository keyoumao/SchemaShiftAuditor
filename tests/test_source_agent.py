import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from security.source_agent import ScanError, repository_key, scan_checkout, snapshot
from security.source_api import make_handler


class SourceAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'repo'
        self.root.mkdir()
        self.git('init', '-b', 'main')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                 'commit', '--allow-empty', '-m', 'test')

    def git(self, *args):
        subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)

    def test_repository_validation(self):
        self.assertEqual(repository_key('https://github.com/Owner/Repo.git'), 'owner/repo')
        for url in ['file:///etc', 'https://github.com.evil/a/b', 'https://github.com/a/b/../../c', None]:
            with self.assertRaises(ValueError):
                repository_key(url)

    def test_snapshot_excludes_ignored_files_and_tracks_changes(self):
        (self.root / '.gitignore').write_text('private.py\n')
        (self.root / 'private.py').write_text('SECRET')
        (self.root / '.env').write_text('SECRET')
        (self.root / 'main.py').write_text('print(1)')
        dest = Path(self.temp.name) / 'snapshot'
        dest.mkdir()
        count, before = snapshot(self.root, dest)
        self.assertEqual(count, 1)
        self.assertEqual(list(dest.iterdir()), [dest / 'main.py'])
        (self.root / 'main.py').write_text('print(2)')
        self.assertNotEqual(snapshot(self.root, dest)[1], before)

    def test_symlink_and_size_limits(self):
        (self.root / 'escape.py').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ScanError, 'symlink'):
            snapshot(self.root, Path(self.temp.name) / 'out')
        (self.root / 'escape.py').unlink()
        (self.root / 'large.py').write_text('x' * 12)
        with patch('security.source_agent.MAX_FILE_BYTES', 10):
            with self.assertRaisesRegex(ScanError, 'limits'):
                snapshot(self.root, Path(self.temp.name) / 'out')

    def test_empty_is_not_clean(self):
        with self.assertRaisesRegex(ScanError, 'No supported'):
            snapshot(self.root, Path(self.temp.name) / 'out')

    def test_engine_failures_are_not_clean_scans(self):
        (self.root / 'main.py').write_text('print(1)')
        real_run = subprocess.run
        for output in ['not JSON', '{"errors":[{"message":"parse error"}]}',
                       '{"errors":[],"paths":{"scanned":[]},"results":[]}']:
            def run(command, **kwargs):
                if command[0] == 'git':
                    return real_run(command, **kwargs)
                return subprocess.CompletedProcess(command, 0, stdout=output.encode(), stderr=b'')
            with patch('security.source_agent.subprocess.run', side_effect=run):
                with self.assertRaises(ScanError):
                    scan_checkout(self.root)

    def start_api(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), lambda *a: None)
        port = server.server_port
        server.RequestHandlerClass = make_handler({'owner/repo': self.root}, port, 'http://localhost:5173')
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return port

    def request(self, port, body, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        self.addCleanup(connection.close)
        connection.request('POST', '/api/source-scans', json.dumps(body),
                           {'Content-Type': 'application/json', **(headers or {})})
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    def test_api_rejects_unregistered_repo_wrong_branch_and_origin(self):
        port = self.start_api()
        with patch('security.source_api.scan_checkout') as scanner:
            for body in [[], {'repo': 'github.com/other/repo', 'branch': 'main'},
                         {'repo': 'github.com/owner/repo', 'branch': 'wrong'}]:
                self.assertEqual(self.request(port, body)[0], 400)
            self.assertEqual(self.request(port, {}, {'Origin': 'https://evil.example'})[0], 403)
            self.assertEqual(self.request(port, {}, {'Host': 'evil.example'})[0], 403)
            scanner.assert_not_called()

    def test_api_reports_failure_and_success(self):
        port = self.start_api()
        body = {'repo': 'github.com/owner/repo', 'branch': 'main'}
        with patch('security.source_api.scan_checkout', side_effect=ScanError('incomplete')):
            self.assertEqual(self.request(port, body), (503, {'error': 'incomplete'}))
        report = {'scan': {'branch': 'main'}, 'vulns': []}
        with patch('security.source_api.scan_checkout', return_value=report):
            self.assertEqual(self.request(port, body), (200, report))

    @unittest.skipUnless(os.environ.get('RUN_SEMGREP_TESTS') == '1', 'Set RUN_SEMGREP_TESTS=1 for real scanner tests')
    def test_real_rules_and_clean_rescan(self):
        (self.root / 'unsafe.py').write_text('''import os, subprocess, pickle, requests
eval(user_input)  # nosemgrep
subprocess.run(user_input, shell=True)
pickle.loads(payload)
requests.get(url, verify=False)
''')
        (self.root / 'unsafe.tsx').write_text('''import * as child_process from "child_process";
eval(userInput);
child_process.exec(userInput);
const view = <div dangerouslySetInnerHTML={{__html: userInput}} />;
''')
        report = scan_checkout(self.root)
        self.assertEqual(len(report['vulns']), 7)
        self.assertEqual(report['scan']['filesScanned'], 2)
        self.assertEqual({f['file'] for f in report['vulns']}, {'unsafe.py', 'unsafe.tsx'})
        self.assertTrue(all(f['line'] > 0 and f['fix'] and f['cwe'] for f in report['vulns']))
        self.assertNotIn('userInput', json.dumps(report))
        (self.root / 'unsafe.py').write_text('import subprocess\nsubprocess.run(["echo", "hello"], shell=False)\n')
        (self.root / 'unsafe.tsx').write_text('const view = <div>{"hello"}</div>;\n')
        clean = scan_checkout(self.root)
        self.assertEqual(clean['vulns'], [])
        self.assertEqual(clean['securityScore'], 100)
        self.assertNotEqual(report['scan']['snapshotSha256'], clean['scan']['snapshotSha256'])


if __name__ == '__main__':
    unittest.main()
