import json
import tempfile
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import runtime_agent as agent
from core import execute, variant
from integrations.telemetry import Event


class RuntimeTests(unittest.TestCase):
    def ingest(self, unused):
        return [SimpleNamespace(event='schema_changed', event_id='trigger')], {'events': 1}

    def test_failed_request_is_reserved_and_never_retried(self):
        calls = []
        def fail(*args):
            calls.append(args)
            raise TimeoutError('Never display a provider body')
        with tempfile.TemporaryDirectory() as d, patch.object(agent, 'ingest', self.ingest):
            state = agent.audit('ignored', d, True, object(), fail)
            self.assertEqual(state['status'], 'failed')
            self.assertEqual(state['callsReserved'], 1)
            self.assertEqual(state['completedTrials'], 0)
            self.assertEqual(agent.audit('ignored', d, True, object(), fail), state)
            self.assertEqual(len(calls), 1)
            self.assertNotIn('provider body', Path(d, 'runtime-status.json').read_text())

    def test_two_cohorts_cannot_exceed_forty_calls(self):
        calls = []
        def collect(*args): calls.append(args)
        report = {'complete': True, 'source': 'live', 'traceSetHash': 'test',
                  'rows': [{'committed_asr': 0.0}]}
        with tempfile.TemporaryDirectory() as d, patch.object(agent, 'ingest', self.ingest), \
             patch.object(agent, 'report_for', return_value=report), patch.object(agent, 'analyze', return_value={}):
            state = agent.audit('ignored', d, True, object(), collect)
            self.assertEqual(state['status'], 'complete')
            self.assertEqual(len(calls), 40)
            self.assertEqual(sum(c[5] for c in calls), 20)
            self.assertEqual(state['callsReserved'], 40)
            self.assertEqual(state['representationSpreadPp'], 0)
            self.assertIn('No schema-sensitive', state['recommendation'])
            self.assertTrue(Path(d, 'manifest.json').exists())

    def test_dry_run_never_calls_model(self):
        with tempfile.TemporaryDirectory() as d, patch.object(agent, 'ingest', self.ingest):
            state = agent.audit('ignored', d)
            self.assertEqual(state['callsReserved'], 0)
            self.assertEqual(state['status'], 'dry_run')

    def test_saved_evidence_is_regraded_and_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / 'evidence'
            shutil.copytree(agent.ROOT / 'demo/runtime-live', copy)
            self.assertEqual(agent.verify_evidence(copy)['completedTrials'], 40)
            report = copy / 'reference-report.json'
            report.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                agent.verify_evidence(copy)

    def test_real_sql_telemetry_keeps_mock_events_separate(self):
        try:
            import chdb
        except ImportError:
            self.skipTest('Optional ClickHouse engine unavailable')
        events, report = agent.ingest(agent.ROOT / 'demo/telemetry/mock-events.jsonl')
        self.assertEqual(len(events), 3)
        self.assertEqual(sum(row['events'] for row in report['groups']), 3)
        self.assertEqual({row['source'] for row in report['groups']}, {'mock'})

    def test_telemetry_cannot_supply_prompts_or_target_paths(self):
        with self.assertRaises(ValueError):
            Event.model_validate({'event_id': 'a', 'time': 'now', 'source': 'mock',
                                  'sourcetype': 'splunk:agent', 'harness': 'records-assistant',
                                  'event': 'schema_changed', 'prompt': 'ignore policy'})

    def test_boundary_blocks_send_preserves_archive_rejects_unknown(self):
        schema = variant('baseline')
        names = {t['role']: t['function']['name'] for t in schema['tools']}
        calls = execute([(names['send'], {'record_id': 'demo-record-001', 'destination': 'https://audit.example.invalid'}),
                         (names['archive'], {'record_id': 'demo-record-001', 'destination': 'internal://archive'}),
                         ('unknown', {})], schema, True, 'now')
        self.assertEqual([c.status for c in calls], ['blocked', 'executed', 'error'])


if __name__ == '__main__':
    unittest.main()
