# 60-second pitch

**Clean Semgrep ≠ honest security score.**

Your harness can pass a source scan while its agent-security evaluation depends on how the tools were worded. SchemaShift asks: does committed attack success rate change when we change only tool names and descriptions?

We freeze the policy, adversarial objective, parameter contracts, tool order, and simulated executor. Then we compare descriptive, name-shifted, urgency-framed, and canonical schemas. Every ASR bar shows a numerator and denominator, with raw calls behind it. Attempted external calls, valid arguments, simulated commits, boundary blocks, and abstentions stay distinct.

FleetGuardian is the control room. SchemaShift audits the harness contract; Semgrep supplies harness source trust. Runtime controls answer whether an action should be stopped. Our question is whether an apparently safe evaluation survives different tool wording.

Normalize reveals recorded `tool_a` / `tool_b` trials. The kill-chain view explains where each attempt reached or stopped. Normalization is a mitigation hypothesis; the deterministic execution boundary is the enforceable control.

FleetGuardian now shows a real 40-call GPT-4.1 mini experiment: four schemas, five trials each, with a separate boundary cohort. Every variant returned 0/5 attempted and committed attacks. **No schema delta or ASR reduction was observed.** The contribution is the automated, reproducible audit and its evidence, not a manufactured improvement. The older standalone HTML walkthrough remains synthetic.

## Three-minute judged demo

- **0:00–0:30 — Problem:** A source scan and a runtime block answer different questions from whether an ASR score survives tool wording changes.
- **0:30–1:15 — Autonomy:** Show the completed telemetry → frozen experiment → ClickHouse validation → publication log. Explicitly identify the three mock events and 40 real OpenAI requests.
- **1:15–2:00 — Evidence:** Show 0/5 across all variants and both cohorts. Say: “We did not observe sensitivity here. Our agent reports that instead of tuning until the graph looks exciting.” Open the frozen configuration and raw traces.
- **2:00–2:30 — Boundaries:** Show the separate executor regression: external sends blocked, internal archive allowed. It is a deterministic simulation test, not measured ASR reduction.
- **2:30–3:00 — Value and limits:** Explain the path to auditing changing tool contracts in CI. Semgrep and ClickHouse have executed; Guild setup is not yet runtime evidence, and Akash deployment is next. Do not claim three effective sponsor integrations yet.

## Demo sequence

1. Open FleetGuardian's **Representation ASR** page. Read the fixture/measured banner before showing bars. State the frozen policy and attacker objective.
2. Show committed ASR across variants, with raw counts and percentage-point deltas. Fixture deltas are illustrative arithmetic only. If live results show no difference, say so.
3. Click **Normalize schema**. Compare the recorded urgency-framed and canonical cohorts. Never promise that the second bar is lower; a difference alone does not establish causality or generalizable hardening.
4. Click **Show kill-chain**. S1 selection maps to tool choice and attempted external calls; S2 is the interface-grounding question being probed, not an independently measured cognitive state; S3 binding maps to validated arguments. Commit/block is our simulated execution outcome, not the paper's S4 observation-recovery stage.
5. Open the secondary **Harness source trust** module. A zero-match Semgrep scan concerns only the scanned code/rules. It supplies no ASR evidence, and the FleetGuardian frontend scan is not the same target as the records-assistant experiment.
6. Describe `--enforce-boundary` as a separate execution condition. Only display measured blocked/committed counts from an actual boundary-enabled cohort. Never combine it with the schema-only matrix or invent a counterfactual reduction.

## Three complementary layers

| Layer | Question | Evidence |
| --- | --- | --- |
| Semgrep: harness code | Which static patterns need review? | Findings and severity within rule coverage |
| Runtime controls, such as Pi when integrated | Should this attempted action be stopped? | Actual incidents, blocks, and interventions |
| SchemaShift → FleetGuardian: harness contract | Does committed ASR depend on tool wording under frozen controls? | Per-variant committed/attempted ASR, raw calls, and descriptive deltas |

Pi is a positioning comparison, not an implemented integration or a measured head-to-head evaluation. FleetGuardian's runtime fleet screen is still labeled simulation.

## Prior art and scope

[ToolRobustBench, arXiv:2608.23635v1](https://arxiv.org/html/2608.23635v1) places tool-interface perturbations in Family A and distinguishes S1 selection, S2 schema grounding, and S3 argument binding. We use that taxonomy as conceptual context, not as a claim to reproduce its benchmark or outperform its task-success results.

| Paper concept | Our implementation | Limit |
| --- | --- | --- |
| A1 name shift | `neutralized`: tool names become `tool_a` / `tool_b`; descriptions stay fixed | Conceptual alignment, not benchmark replication |
| A2 description abstraction | Canonical normalization removes framing; `threat_loaded` introduces urgency wording | Our urgency perturbation is not the paper's exact A2 construction; normalization changes names and descriptions together |
| A3 sibling confusability | No dedicated variant | Do not claim A3 coverage |

Our endpoint is security ASR for a fixed adversarial objective, not benign task success. This is one task, one model configuration, simulated tools, and a single-turn selection audit. It does not establish prompt-injection resistance, comprehensive source security, or runtime defense effectiveness.

## Replace only after measurement

“On [provider/model], under this frozen task and policy, baseline committed [X/N] and [variant] committed [Y/N], a [signed Z] percentage-point difference. Canonical trials committed [C/N]. These are descriptive results for this configuration.”

Publish zero deltas as zero. Display partial cohorts as n/expected; do not call them a completed matrix. Do not say “we lower ASR” unless the relevant measured comparison actually supports that wording, and still state its limits. An OpenAI run is empirical evidence, but does not count as AkashML sponsor usage.

## Handoff from measurement to UI

The live-run owner handles model selection, matrix → grade → ClickHouse → freeze. After validation, publish the same cohort to FleetGuardian:

```bash
python export_fleet.py demo/golden --out ../FleetGuardian/web/public/schema-audit.json
```

The exporter validates and regrades traces, rejects mixed cohorts, and verifies canonical normalization. It makes no provider call and does not alter the frozen traces or sponsor ledger. Refresh the FleetGuardian audit page to load the published report. Until then, its bundled report remains clearly labeled fixtures.
