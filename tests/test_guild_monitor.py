import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from monitoring.store import Store
from integrations.guild_review import extract_reply, monitor_evidence, review_monitor


class GuildMonitorLinkTests(unittest.TestCase):
    def test_monitor_evidence_is_compact_and_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'monitor.sqlite3'
            Store(path).append({
                'event_id': 'drill-1', 'run_id': 'drill-1', 'agent': 'notification-drill',
                'origin': 'test', 'execution': 'simulated', 'kind': 'forbidden_commit',
                'attempted': True, 'committed': True,
            })
            pack = monitor_evidence(path)
            self.assertEqual(pack['totalEvents'], 1)
            self.assertEqual(pack['incidentCounts'], {'critical': 1})
            self.assertEqual(pack['incidents'][0]['origin'], 'test')
            self.assertNotIn('prompt', pack['incidents'][0])
            self.assertEqual(len(pack['evidenceHash']), 64)

    def test_extract_reply_prefers_runtime_done_text(self):
        events = {'items': [
            {'id': '1', 'type': 'agent_notification_message',
             'content': {'type': 'text', 'data': 'partial', 'status': 'aborted'}},
            {'id': '2', 'type': 'runtime_done', 'content': {'text': 'Final review'}},
        ]}
        reply, reply_id = extract_reply(events)
        self.assertEqual(reply, 'Final review')
        self.assertEqual(reply_id, '2')

    def test_review_monitor_creates_session_from_db(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / 'monitor.sqlite3'
            Store(db).append({
                'event_id': 'drill-2', 'run_id': 'drill-2', 'agent': 'notification-drill',
                'origin': 'test', 'execution': 'simulated', 'kind': 'forbidden_commit',
                'attempted': True, 'committed': True,
            })
            guild = MagicMock()
            guild.request.side_effect = [
                {'id': 'sess-1', 'session_url': 'https://app.guild.ai/sessions/sess-1',
                 'created_at': '2026-10-10T00:00:00+00:00'},
                {'root_task': {'status': 'DONE'}},
                {'items': [{'id': 'r1', 'type': 'runtime_done',
                            'content': {'text': '### Evidence\nTest incident only.'}}]},
            ]
            state = {'status': 'configured', 'agentId': 'agent-1', 'versionId': 'ver-1',
                     'workspaceId': 'ws-1'}
            result = review_monitor(root / 'out', guild, state, db, wait_seconds=5)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['sessionId'], 'sess-1')
            self.assertIn('Test incident', result['review'])
            create_body = guild.request.call_args_list[0].args[1]
            self.assertEqual(create_body['session_type'], 'chat')
            self.assertEqual(create_body['agent_id'], 'agent-1')
            self.assertIn('local monitor evidence', create_body['initial_prompt'])
            self.assertTrue((root / 'out' / 'evidence.json').exists())
            self.assertTrue((root / 'out' / 'review.txt').exists())


if __name__ == '__main__':
    unittest.main()
