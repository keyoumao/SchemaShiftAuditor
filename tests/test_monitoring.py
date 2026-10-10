import json
import tempfile
import threading
import unittest
import http.client
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from monitoring.store import Store
from monitoring.api import handler
from monitoring.hooks import emit


def event(**changes):
    return {'event_id':'e1','run_id':'r1','agent':'records-assistant','origin':'test',
            'execution':'simulated','kind':'forbidden_commit','attempted':True,'committed':True,**changes}

class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'events.sqlite3';self.store=Store(self.path)

    def test_persistence_deduplication_and_incident_severity(self):
        self.store.append(event());self.assertTrue(self.store.append(event())['duplicate'])
        snapshot=Store(self.path).snapshot()
        self.assertEqual(snapshot['totalEvents'],1)
        self.assertEqual(snapshot['incidentCounts'],{'critical':1})
        self.assertEqual(snapshot['incidents'][0]['origin'],'test')
        self.assertEqual(len(self.store.run_events('r1')),1)
        with self.assertRaises(ValueError):self.store.append(event(agent='different'))

    def test_rejects_unstructured_sensitive_fields_and_inconsistent_flags(self):
        for data in [event(prompt='secret'),event(arguments={'token':'secret'}),event(committed=False),event(kind='completed')]:
            with self.assertRaises(ValueError):self.store.append(data)
        self.assertEqual(self.store.snapshot()['totalEvents'],0)

    def test_blocked_attempt_is_not_critical(self):
        self.store.append(event(kind='blocked_attempt',committed=False,blocked=True))
        self.assertEqual(self.store.snapshot()['incidentCounts'],{'medium':1})

    def test_live_hook_has_provenance_without_payload(self):
        with patch.dict('os.environ',{'SCHEMASHIFT_MONITOR_DB':str(self.path)}):
            emit('run-live','started')
            emit('run-live','provider_error')
        data=self.store.snapshot()
        self.assertEqual(data['totalEvents'],2)
        self.assertEqual(data['incidents'][0]['severity'],'high')
        self.assertEqual(data['incidents'][0]['origin'],'live')
        self.assertNotIn('response',data['incidents'][0])

    def test_http_write_auth_and_read_logs(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),lambda *a:None)
        port=server.server_address[1];server.RequestHandlerClass=handler(self.store,port,'test-token')
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        def call(method,path,payload=None,headers=None):
            conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
            try:
                conn.request(method,path,None if payload is None else json.dumps(payload),{'Content-Type':'application/json',**(headers or {})})
                response=conn.getresponse();return response.status,json.loads(response.read())
            finally:conn.close()
        self.assertEqual(call('POST','/api/monitor/events',event())[0],401)
        self.assertEqual(call('POST','/api/monitor/events',event(),{'Authorization':'Bearer test-token','Origin':'https://bad.example'})[0],403)
        self.assertEqual(call('POST','/api/monitor/events',event(),{'Authorization':'Bearer test-token'})[0],201)
        self.assertEqual(call('POST','/api/monitor/events',event(),{'Authorization':'Bearer test-token'})[0],200)
        self.assertEqual(call('GET','/api/monitor/snapshot')[1]['totalEvents'],1)
        self.assertEqual(len(call('GET','/api/monitor/logs?run_id=r1')[1]['events']),1)
        self.assertEqual(call('GET','/api/monitor/logs?run_id=../../etc')[0],400)

if __name__=='__main__':unittest.main()
