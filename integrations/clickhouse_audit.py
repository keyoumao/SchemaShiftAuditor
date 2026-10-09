#!/usr/bin/env python3
"""Actual embedded ClickHouse analytics over validated traces, no persistent DB."""
import argparse,hashlib,json,platform,statistics,sys,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import ROOT,digest,read_traces,scoreboard

STRUCTURE='run_id String, variant String, trial UInt32, trial_count UInt32, committed UInt8, attempted UInt8, blocked UInt8, tool_selection_error UInt8, task_success UInt8, abstained UInt8'

def sql_string(value):
    return "'"+str(value).replace('\\','\\\\').replace("'","\\'")+"'"

def analyze(path,scale=1):
    if not 1<=scale<=100000:raise ValueError('Synthetic scale must be 1..100000')
    traces=read_traces(path);reference=scoreboard(traces)
    if not traces:raise ValueError('No traces')
    import chdb
    with tempfile.TemporaryDirectory(prefix='schemashift-analytics-') as directory:
        file=Path(directory)/'rows.jsonl'
        flat=[]
        fields=['committed','attempted','blocked','tool_selection_error','task_success','abstained']
        for t in traces:
            row={'run_id':t.run_id,'variant':t.variant,'trial':t.trial,'trial_count':t.trial_count}
            row.update({f:int(getattr(t.grader,f)) for f in fields});flat.append(row)
        file.write_text(''.join(json.dumps(r)+'\n' for r in flat))
        source=f"file({sql_string(file)}, 'JSONEachRow', {sql_string(STRUCTURE)})"
        sql='SELECT variant, count() AS trials, any(trial_count) AS expected_trials, '+', '.join(f'sum({f}) AS {f}_count' for f in fields)+f' FROM {source} GROUP BY variant ORDER BY variant SETTINGS output_format_json_quote_64bit_integers=0'
        started=time.perf_counter();result=json.loads(str(chdb.query(sql,'JSON')));cold_ms=(time.perf_counter()-started)*1000
        warmed=[]
        for _ in range(5):
            started=time.perf_counter();chdb.query(sql,'JSON');warmed.append((time.perf_counter()-started)*1000)
        rows=result['data'];base=next((r['committed_count']/r['trials'] for r in rows if r['variant']=='baseline'),None)
        metrics={'committed_asr':'committed','attempted_asr':'attempted','blocked_rate':'blocked','tool_selection_error_rate':'tool_selection_error','task_success_rate':'task_success','abstained_rate':'abstained'}
        for row in rows:
            for metric,field in metrics.items():row[metric]=row[field+'_count']/row['trials']
            row['delta_vs_baseline']=None if base is None else row['committed_asr']-base
        if rows!=reference:raise ValueError('ClickHouse and programmatic scoreboard disagree')
        # A separate throughput workload. Expanded rows are NEVER counted as model trials.
        benchmark_sql=f'SELECT count() AS expanded_rows, sum(committed) AS scripted_commits FROM {source} AS trace_rows CROSS JOIN numbers({scale}) AS expansion SETTINGS output_format_json_quote_64bit_integers=0'
        started=time.perf_counter();bench=json.loads(str(chdb.query(benchmark_sql,'JSON')))['data'][0];benchmark_ms=(time.perf_counter()-started)*1000
        engine=json.loads(str(chdb.query('SELECT version() AS version','JSON')))['data'][0]['version']
    alerts=[]
    if traces[0].source=='live':
        alerts=[{'variant':r['variant'],'delta_percentage_points':100*r['delta_vs_baseline'],'raw_count':f"{r['committed_count']}/{r['trials']}",'action':'Inspect calls and test cached canonical rewrite; descriptive difference only.'} for r in rows if r['delta_vs_baseline'] is not None and r['delta_vs_baseline']>0]
    evidence={'tool':'ClickHouse via chDB','status':'executed','chdb_version':chdb.__version__,'engine_version':engine,'source':traces[0].source,'trace_count':len(traces),'trace_set_hash':digest([t.model_dump() for t in traces]),'started_at':datetime.now(timezone.utc).isoformat(),'machine':platform.machine(),'query_template':sql.replace(sql_string(file),"'<temporary flattened JSONL>'"),'cold_query_ms':cold_ms,'warm_query_ms':warmed,'warm_median_ms':statistics.median(warmed),'scoreboard':rows,'alerts':alerts,'throughput_workload':{'kind':'synthetic SQL row expansion; not additional model trials','scale':scale,'expanded_rows':bench['expanded_rows'],'query_ms':benchmark_ms,'rows_per_second':bench['expanded_rows']/max(benchmark_ms/1000,1e-9)},'limitations':'Local wall-clock measurements on this machine, not service SLA or comparative speedup. Input is a small trace cohort. Synthetic expansion tests SQL throughput only.'}
    return evidence

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('path',nargs='?',default=str(ROOT/'demo/fixtures'));p.add_argument('--out',type=Path,default=ROOT/'demo/clickhouse-report.json');p.add_argument('--synthetic-scale',type=int,default=1)
    a=p.parse_args();report=analyze(a.path,a.synthetic_scale);a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n')
    print(f"ClickHouse {report['engine_version']}: {report['trace_count']} {report['source']} traces; SQL/Python counts agree; query {report['cold_query_ms']:.2f} ms. Report: {a.out}")
    print('Synthetic SQL-expanded rows are a throughput workload, never independent trials.')
if __name__=='__main__':main()
