# Three-tool competition plan

Use **AkashML + ClickHouse + Semgrep**. Each supports a necessary step of the security workflow. JSONL remains the authoritative trace store and the judging demo remains a static offline page.

| Sponsor | Role in SchemaShift | Evidence now | Required before claiming use |
| --- | --- | --- | --- |
| AkashML | Run the one approved open model against frozen schema variants | Implemented fixed-endpoint SDK adapter; mocked tests only | Actual model API trials with provider=akash, then golden freeze |
| ClickHouse | Compute per-variant counts, rates, deltas, and triage signals | Actual chDB/ClickHouse queries ran on 20 labeled fixture traces; SQL counts agree with Python | Already executed locally; confirm embedded engine counts under event rules |
| Semgrep | Detect and fix security defects in AI-generated audit code | Actual CE custom-rule scans; original path traversal reproduced; fixed scan has zero matches | Already executed locally; confirm CE/custom-rule use qualifies, and whether Guardian is required for the prize |

**Current executed count: 2/3.** Implementing an adapter, displaying a logo, or running a mock is not proof of sponsor use. No AkashML credential was available in this session. The offline dashboard repeats this status explicitly.

## Minimal setup

```bash
pip install -r requirements-sponsors.txt
python security/reproduce_before.py
python security/scan.py
python integrations/clickhouse_audit.py demo/fixtures --synthetic-scale 10000
python export_demo.py demo/fixtures
```

The reproduction touches only a temporary directory, using an exact snapshot of the original generated code. The original snapshot is kept as evidence and is excluded from active-code rescans. See `security/FINDING.md` for triage.

## Finish AkashML usage

Use the team's authorized secret environment to provide `AKASHML_API_KEY`; never put it in source or demo artifacts. Generate keys using the official Settings → API Keys workflow. Choose one team-approved model that supports function tools and temperature 0, then keep that model and config fixed. The adapter sends requests to the documented `https://api.akashml.com/v1` endpoint and does not fall back to another provider.

```bash
python run.py --live --provider akash --model TEAM_APPROVED_MODEL --variant all --trials 5 --out akash-matrix
python grade.py akash-matrix
python integrations/clickhouse_audit.py akash-matrix --synthetic-scale 10000
python freeze.py akash-matrix
```

The full matrix is 20 model calls: 15 across baseline/neutralized/threat-loaded plus 5 canonical normalization calls. A supported fixed seed can be added consistently to every matrix. Do not silently remove unsupported parameters or change models after seeing results. No measured delta is required for the product to run. If needed, use a separate identical confirmation matrix within the M2 time budget, then pivot to kill-chain view if the effect does not repeat.

After these commands, the same offline page shows actual AkashML trace counts, ClickHouse aggregates of those exact traces, and the Semgrep finding/fix evidence. The exporter rejects stale analytics and stale code-scan evidence instead of attaching mismatched sponsor proof to a new result set. Re-record the backup using the measured page on your demo laptop; the bundled recording uses fixtures.

## ClickHouse scope and prize positioning

chDB is the official in-process SQL OLAP engine powered by ClickHouse. It avoids deploying a database server. The local aggregate query groups validated trial outcomes by variant, returns raw counts, and feeds the cached evidence panel. Positive deltas on actual live traces create triage entries that tell the analyst to inspect calls and test canonical normalization. Fixture deltas never become model-security alerts.

The optional `--synthetic-scale 10000` workload expands 20 input records into 200,000 SQL rows. These are **synthetic repeated rows for a throughput query**, not additional traces, attacks, or model trials. The report records actual query wall-clock times, engine version, input hash, workload definition, and machine architecture. It makes no claim about high-volume production traffic, real-time deployment, comparative speedup, or service latency. This is a credible analytics integration, but not a strong scale-prize claim without more real data.

If organizers require ClickHouse Cloud rather than the embedded engine, this route needs adaptation to their supplied Cloud account. Do not assume eligibility from our implementation alone.

## Semgrep scope and prize positioning

Semgrep CE uses a project-specific taint rule for trace IDs reaching filesystem paths. The rule found two original write paths. Only the cache replay path was confirmed exploitable: cached input controlled `run_id`, permitting an output-directory escape. The live path used a freshly generated UUID, so that match was triaged as not an untrusted-input exploit.

The fix validates a bounded single filename, rejects symlink escapes, uses exclusive output creation, and adds regression tests. Before/after scan JSON, the exact original source snapshots, the reproduction result, and code/rule hashes are included. The custom scan is targeted, not a clean bill of health for the whole project. Confirm with the Semgrep team whether CE/custom rules qualify for their award. Guardian sign-in and cloud scanning have not been performed or claimed.

## Why these three

AkashML supplies the model under audit. ClickHouse independently aggregates the recorded actions. Semgrep secures the harness that stores those actions. These components do not change the frozen policy or introduce context differences across experimental variants.

Guild would add a deployment/orchestration step; Senso would add a verified-context step. Both may be useful later, but neither is needed for this single-task audit within the remaining hackathon time. Pi has no product/tech access at the event according to the supplied sponsor brief, so it cannot count as an implemented integration.

## Official documentation

- [AkashML introduction and SDK endpoint](https://akashml.com/docs/getting-started/introduction)
- [AkashML Chat Completions API](https://akashml.com/docs/api-reference/openai/post-v1-chat-completions)
- [ClickHouse chDB](https://clickhouse.com/docs/chdb)
- [chDB Python API](https://clickhouse.com/docs/chdb/api/python)
- [Semgrep local rules and CLI scans](https://docs.semgrep.dev/running-rules)
- [Semgrep Guardian quickstart](https://docs.semgrep.dev/semgrep-guardian/quickstart)
