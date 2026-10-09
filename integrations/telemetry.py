"""Bounded Splunk-style event ingestion; telemetry is never an ASR denominator."""
import json
import tempfile
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from core import digest
from integrations.clickhouse_audit import sql_string


class Event(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    event_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,100}$')
    time: str = Field(max_length=80)
    source: Literal['mock', 'observed']
    sourcetype: Literal['splunk:agent', 'otel:span']
    harness: Literal['records-assistant']
    event: Literal['schema_changed', 'external_attempt', 'heartbeat']


def ingest(path):
    path = Path(path)
    if path.stat().st_size > 2_000_000:
        raise ValueError('Telemetry exceeds 2 MB')
    events = [Event.model_validate_json(line) for line in path.read_text().splitlines() if line.strip()]
    if not events or len(events) > 2000:
        raise ValueError('Telemetry must contain 1..2000 events')
    if len({e.event_id for e in events}) != len(events):
        raise ValueError('Duplicate telemetry event IDs')
    import chdb
    with tempfile.TemporaryDirectory(prefix='asr-telemetry-') as directory:
        rows = Path(directory) / 'events.jsonl'
        rows.write_text(''.join(e.model_dump_json() + '\n' for e in events))
        structure = 'event_id String, time String, source String, sourcetype String, harness String, event String'
        # Real SQL ingestion into a separate temporary ClickHouse table, not trace replication.
        sql = (f'CREATE TABLE telemetry ({structure}) ENGINE=Memory; '
               f'INSERT INTO telemetry SELECT * FROM file({sql_string(rows)}, \'JSONEachRow\', {sql_string(structure)}); '
               "SELECT source, event, count() AS events FROM telemetry GROUP BY source,event ORDER BY source,event "
               'SETTINGS output_format_json_quote_64bit_integers=0')
        result = json.loads(str(chdb.query(sql, 'JSON')))['data']
    return events, {'engine': 'ClickHouse via chDB', 'events': len(events), 'groups': result,
                    'inputHash': digest([e.model_dump() for e in events]),
                    'sql': sql.replace(sql_string(rows), "'<validated telemetry JSONL>'"),
                    'note': 'Mock/observed event counts are operational inputs, never independent model trials.'}
