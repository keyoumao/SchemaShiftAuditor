# Confirmed issue: cached trace ID escapes replay output directory

**Category:** CWE-22 path traversal. **Affected code:** original AI-generated `run.py`, cache replay write at line 34, preserved exactly in `security/before/run.py`. `security/before/core.py` preserves the original permissive trace validator. No new vulnerable feature was introduced to create this finding.

The original Trace contract accepted any string as `run_id`. Replay combined that string directly with the output directory:

```python
(a.out / f'{t.run_id}.jsonl').write_text(t.model_dump_json() + '\n')
```

A downloaded or otherwise untrusted cache record with `run_id="../escaped"` passes the original validation and writes `escaped.jsonl` outside the chosen output folder. Config hashing does not protect this field because run identity is outside the config. A malicious absolute path can likewise discard the output base. This is a local CLI vulnerability: exploitation requires the user to replay attacker-controlled JSONL. It is not a remotely exposed service.

## Actual detection and reproduction

Semgrep CE 1.180.0 scanned the exact original runner with `security/run-id-path.yaml`, a custom taint rule marking trace IDs as sources and filesystem write receivers as sinks. It reported two matches. The replay match was confirmed using `security/reproduce_before.py`, which creates a malicious cache and performs the original replay entirely inside a TemporaryDirectory. `security/evidence/reproduction.json` records the successful output escape; the temporary files are removed automatically.

The second match was the live writer. Its `run_id` was a newly generated UUID, so it was not confirmed exploitable through untrusted input. We report **one confirmed vulnerability**, not two. Semgrep localized the unsafe sinks; the local reproduction establishes exploitability. We manually suspected the issue before writing the project rule; it was not discovered by a general vendor ruleset.

## Fix

- Pydantic restricts run IDs to 1–128 ASCII alphanumeric/underscore/hyphen characters, starting with an alphanumeric character.
- `safe_trace_path` independently validates the ID, checks containment, and rejects symlink targets.
- `write_trace` uses exclusive creation (`open('x')`), so replay never overwrites existing evidence or follows an attacker-created target symlink during an output-file race.
- Replay, live logging, and golden freezing share this writer.
- Regression tests cover traversal, absolute paths, backslashes, newline IDs, oversized IDs, symlink escapes, replay containment, and overwrites.

The same targeted rule on eight active files has zero matches. The scan excludes the intentional original-source evidence snapshots and does not claim that other vulnerability classes are absent. Raw scanner output and code hashes are included for verification.

An additional integrity fix rejects a rehashed trace config whose policy or prompt differs from the frozen experiment. A SHA-256 config hash establishes consistency, not authenticity or proof that a model was actually called. Source claims still rely on trusted collection and review of raw traces.

## Reproduce/check

```bash
pip install -r requirements-sponsors.txt
python security/reproduce_before.py
python security/scan.py
python -m unittest discover -s tests -v
```

The original snapshot is not used by the production harness. `reproduce_before.py` explicitly loads both original modules, adapts current fixture metadata back to the original contract, and tests only in a temporary folder.
