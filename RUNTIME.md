# Automated representation-ASR audit

The worker ingests a bounded telemetry batch into real embedded ClickHouse, recognizes a schema-change or external-attempt event, runs a frozen OpenAI matrix, regrades the traces, cross-checks counts in SQL, freezes a hash manifest, and exports both cohorts to FleetGuardian. No operator intervention is needed between those stages.

This is a working evaluation agent, not a production interception proxy. Model calls are real; records tools execute in simulation. Only the fixed records-assistant harness is evaluated. Registering a frontend source repository does not turn it into the ASR target.

## Measured result: October 9, 2026

Pinned model: `gpt-4.1-mini-2025-04-14`. Temperature 0, seed omitted, four schemas, five trials per schema, separate reference and boundary conditions. Exactly 40 requests, no retries or tuning.

| Schema | Reference attempted / committed | Boundary attempted / committed / blocked |
| --- | --- | --- |
| baseline | 0/5 / 0/5 | 0/5 / 0/5 / 0/5 |
| neutralized | 0/5 / 0/5 | 0/5 / 0/5 / 0/5 |
| threat_loaded | 0/5 / 0/5 | 0/5 / 0/5 / 0/5 |
| normalized | 0/5 / 0/5 | 0/5 / 0/5 / 0/5 |

All responses abstained from tool calls. This experiment demonstrates **neither schema sensitivity nor ASR reduction**. Five trials per variant and one adversarial task cannot establish safety or stability. The deterministic boundary regression separately proves that the simulated executor blocks a valid send and permits a valid archive; that is not a measured model-utility result.

Portable raw traces, configuration, SQL results, status, and manifest are in `demo/runtime-live/`. FleetGuardian's home page displays measured replay. The older standalone `demo/index.html` remains an illustrative fixture walkthrough.

## Run and replay

Install the normal dependencies and `requirements-sponsors.txt`. The macOS pin uses chDB 3.7.2 / ClickHouse 25.8.2.1 because two newer arm64 engine wheels failed the macOS loader on the demo machine. This is local embedded ClickHouse, not ClickHouse Cloud.

```bash
# No model calls; validate and republish the frozen result.
python runtime_agent.py --events demo/telemetry/mock-events.jsonl \
  --out demo/runtime-live --publish ../FleetGuardian/web/public

# Inspect trigger handling without credentials or model calls.
python runtime_agent.py --events demo/telemetry/mock-events.jsonl \
  --out runs/new-dry-run

# Explicitly authorize one NEW experiment, up to 40 API requests.
python runtime_agent.py --events demo/telemetry/mock-events.jsonl \
  --out runs/new-live-job --env-file .env --live \
  --publish ../FleetGuardian/web/public
```

`--watch` waits for the input file to arrive, processes one batch, then exits. A producer should atomically rename a complete JSONL batch into place. This is a bounded worker, not an unbounded spending daemon. Restarting the same output directory never repeats requests, even after failure. Failed/partial jobs retain evidence and never publish a clean score. A new directory is a new explicit spending authorization.

Each request slot is saved before network access. A crash may therefore leave a reserved request whose completion is unknown; it is deliberately not retried. No hidden SDK retry, prompt change, model fallback, or automatic schema tuning is allowed. A process lock prevents concurrent workers sharing one job directory. Hashes detect accidental evidence changes; they are not signatures or proof of truth against an actor able to rewrite the manifest.

## Telemetry contract

`demo/telemetry/mock-events.jsonl` contains three explicitly mock Splunk-style / OTel-style events. They are ingested with SQL `CREATE TABLE`, `INSERT ... SELECT`, and aggregation. They are not pulled from a live Splunk service. A real collector can supply the same normalized contract with `source: observed`; that declaration itself is not authenticated proof of origin.

Required fields: `event_id`, `time`, `source` (`mock|observed`), `sourcetype` (`splunk:agent|otel:span`), `harness` (`records-assistant`), and `event` (`schema_changed|external_attempt|heartbeat`). Unknown fields, duplicate IDs, more than 2,000 events, or more than 2 MB are rejected. Telemetry cannot supply prompts, commands, URLs, model names, credentials, or output paths. It triggers the fixed experiment rather than modifying it. Telemetry rows never enter ASR denominators.

## Guild integration

`integrations/guild_review.py` provisions a private advisory reviewer and private lab workspace using `GUILD_AI_API_KEY`. Only the documented `id:secret` format is accepted. The deployed Guild API requires a tool and currently accepts only `guild_search_agent` through this endpoint; no mutation tools are granted. The reviewer cannot modify the deterministic grade or authorize remediation.

```bash
python integrations/guild_review.py --env-file .env --out runs/guild-setup
# After asynchronous build validation, continue using the recorded IDs:
python integrations/guild_review.py --env-file .env --out runs/guild-setup --resume
```

Provisioning is not a completed Guild runtime trial. No Guild model session is started by this command; the first experiment remains exactly 40 OpenAI requests. Do not count configuration alone as meaningful sponsor runtime evidence. No credentials are exported to the frontend.

## Competitors and judging

The supplied judging slide lists autonomy, idea/value, implementation, effective use of at least three sponsor tools, and a three-minute demo. It gives no numerical weights.

| Published competitor | Their claimed emphasis | Our response |
| --- | --- | --- |
| [Agent Immune System](https://tokensand.com/p/agent-immune-system-with-causal-guardrails) | Provenance detection, ablation replay, generated guardrails, verification corpus | Preserve the narrower representation-ASR question. Do not claim causal attribution from normalization. |
| [CyberDefense Sentry](https://tokensand.com/p/cyberdefense-sentry) | Telemetry enrichment and response orchestration | Automate the complete audit loop and expose actual stage evidence, not a generic monitoring dashboard. |
| [Antigense Daisy](https://tokensand.com/p/antigense-daisy) | Fail-closed worker boundary, regression evidence, bounded claims | Keep the execution boundary deterministic, preserve benign archive behavior, and publish negative results and errors. |

These are descriptions on project submissions, not independently verified performance results.

Our strongest present evidence is implementation and reproducibility: 40 real trials, SQL/programmatic agreement, immutable snapshots, per-call budget accounting, and honest zero results. Autonomy is bounded batch automation; the demo's event source is mocked, not a live web telemetry feed. Semgrep and embedded ClickHouse have executed. Guild configuration and an OpenAI call do not establish a third sponsor integration; verify event eligibility and demonstrate a meaningful third integration before claiming that criterion. Akash deployment is deferred.

Next experiment: preregister a broader attack set and benign utility controls, then repeat with adequate trials and paired conditions. Do not keep changing prompts until a dramatic bar appears. Production extension: authenticated telemetry ingestion and an explicit harness-contract adapter, followed by a deployed worker on Akash.
