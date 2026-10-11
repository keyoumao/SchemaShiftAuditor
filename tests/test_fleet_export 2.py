import json
from pathlib import Path
import tempfile
import unittest
from core import ROOT, digest, execute, grade, read_traces
from export_fleet import export, report_for


class FleetExportTests(unittest.TestCase):
    def test_fixture_counts_and_provenance(self):
        report = report_for(ROOT / 'demo/fixtures')
        self.assertEqual(report['source'], 'fixture')
        self.assertTrue(report['complete'])
        self.assertEqual(len(report['traces']), 20)
        self.assertTrue(all(row['committed_count'] == 2 and row['delta_vs_baseline'] == 0 for row in report['rows']))
        self.assertFalse(report['enforceBoundary'])
        self.assertEqual(len(report['traceSetHash']), 64)

    def write(self, directory, traces):
        Path(directory, 'traces.jsonl').write_text('\n'.join(t.model_dump_json() for t in traces))

    def test_partial_export_is_never_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, read_traces(ROOT / 'demo/fixtures')[:1])
            out = Path(directory, 'report.json')
            export(directory, out)
            report = json.loads(out.read_text())
            self.assertFalse(report['complete'])
            self.assertEqual(report['rows'][0]['trials'], 1)
            self.assertEqual(report['rows'][0]['expected_trials'], 5)

    def test_tampered_counts_are_rejected(self):
        traces = read_traces(ROOT / 'demo/fixtures')
        traces[0].grader.committed = not traces[0].grader.committed
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, traces)
            with self.assertRaisesRegex(ValueError, 'Grader mismatch'):
                report_for(directory)

    def test_boundary_cohorts_cannot_be_mixed(self):
        traces = read_traces(ROOT / 'demo/fixtures')
        t = traces[0]
        t.config['enforce_boundary'] = True
        t.config_hash = digest(t.config)
        t.tool_calls = execute([(c.name, c.args) for c in t.tool_calls], t.config['schema'], True, t.started_at)
        t.grader = grade(t.tool_calls)
        with tempfile.TemporaryDirectory() as directory:
            self.write(directory, traces)
            with self.assertRaisesRegex(ValueError, 'Mixed sources'):
                report_for(directory)

    def test_empty_report_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'No traces'):
                report_for(directory)


if __name__ == '__main__':
    unittest.main()
