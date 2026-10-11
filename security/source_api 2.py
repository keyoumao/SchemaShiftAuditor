#!/usr/bin/env python3
"""Local development API for FleetGuardian's source scanner (loopback only)."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
from urllib.parse import urlsplit

from security.source_agent import ScanError, git, repository_key, scan_checkout


def make_handler(repositories, port, frontend_origin):
    scan_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def reply(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def trusted_request(self):
            if (self.headers.get('Host') not in {f'127.0.0.1:{port}', f'localhost:{port}'}
                    or self.headers.get('Origin') not in {None, frontend_origin}):
                self.reply(403, {'error': 'Local scanner origin or host rejected.'})
                return False
            return True

        def do_GET(self):
            if not self.trusted_request():
                return
            if self.path != '/api/source-repositories':
                self.reply(404, {'error': 'Unknown endpoint.'})
                return
            try:
                self.reply(200, {'repositories': [
                    {'repo': f'https://github.com/{key}',
                     'branch': git(root, 'branch', '--show-current').decode().strip()}
                    for key, root in repositories.items()]})
            except ScanError as exc:
                self.reply(503, {'error': str(exc)})

        def do_POST(self):
            if not self.trusted_request():
                return
            if self.path != '/api/source-scans':
                self.reply(404, {'error': 'Unknown endpoint.'})
                return
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                self.reply(415, {'error': 'Content-Type must be application/json.'})
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 8192:
                    raise ValueError('Request must be between 1 and 8,192 bytes.')
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError('Expected a JSON object.')
                key = repository_key(data.get('repo'))
                root = repositories.get(key)
                if root is None:
                    raise ValueError('Repository is not configured. Start the scanner with --repo PATH for this checkout.')
                branch = git(root, 'branch', '--show-current').decode().strip()
                if not branch or data.get('branch') != branch:
                    raise ValueError(f'Choose the checked-out branch: {branch or "detached HEAD (checkout a branch first)"}.')
            except (ValueError, UnicodeError) as exc:
                self.reply(400, {'error': str(exc)})
                return
            except ScanError as exc:
                self.reply(503, {'error': str(exc)})
                return
            if not scan_lock.acquire(blocking=False):
                self.reply(409, {'error': 'Another scan is running. Retry after it completes.'})
                return
            try:
                report = scan_checkout(root)
                if report['scan']['branch'] != branch:
                    raise ScanError('Checkout branch changed during the scan. Retry on a stable checkout.')
                self.reply(200, report)
            except ScanError as exc:
                self.reply(503, {'error': str(exc)})
            finally:
                scan_lock.release()

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, action='append', required=True,
                        help='Explicitly permitted local Git checkout; repeat for more repositories.')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--frontend-origin', default='http://localhost:5173')
    args = parser.parse_args()
    origin = urlsplit(args.frontend_origin)
    if origin.scheme != 'http' or origin.hostname not in {'localhost', '127.0.0.1'}:
        parser.error('Frontend origin must be a local HTTP origin.')
    repositories = {}
    try:
        for root in args.repo:
            root = root.resolve(strict=True)
            key = repository_key(git(root, 'remote', 'get-url', 'origin').decode().strip())
            if key in repositories:
                raise ValueError('Configure only one checkout per repository.')
            repositories[key] = root
    except (OSError, ValueError, ScanError) as exc:
        parser.error(str(exc))
    server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(repositories, args.port, args.frontend_origin))
    print(f'Local source scanner: http://127.0.0.1:{args.port} ({len(repositories)} repositories)', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
