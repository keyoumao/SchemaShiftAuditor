# Context (paste as-is)
- Event: Cyberdefense Hackathon #SFTechWeek, Fri Oct 9 2026. Hacking 11:00am–4:30pm PT (5.5h). Submission 4:30pm, demos 5:00pm, awards 7:00pm.
- Tracks: threat discovery + continuous defense.
- One-line pitch: "Your agent-security score may partly measure how the tools were worded — not whether the policy is safe. SchemaShift finds false confidence in agent-security evaluations, then hardens the risky schema."
- Non-goals: no new benchmark, no model training, no infra. One adversarial task, one model, frozen policy.

# Acceptance status

| Milestone | Implemented / checked | Outstanding |
| --- | --- | --- |
| M1 | Three baseline replay traces, CLI help, programmatic grading, mocked API integration | Three actual model trials |
| M2 | Three equivalent schema contracts; five fixture trials per variant; counts and deltas | Measured matrix and repeatability assessment |
| M3 | Static file:// dashboard, bars, trace viewer, config hashes, offline browser check | None for fixture demo |
| M4 | Canonical schema rewrite; five cached normalized fixture trials; before/after button | Actual normalized model trials |
| M5 | README, pitch, backup screen recording, export/freeze commands | Measured golden traces; run freeze.py after approved live matrix |

The recorded/demo numbers are synthetic and prominently labeled. The live measurement blocker is missing AKASHML_API_KEY (or OPENAI_API_KEY for non-sponsor inference) and no team-approved model specified. No live API calls were made. This is not yet the full measured definition of done.

Sponsor integrations: actual embedded ClickHouse analytics and local Semgrep scan/fix evidence; AkashML SDK adapter implemented but no actual inference yet. See SPONSORS.md.
