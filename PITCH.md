# 60-second pitch

Your agent-security score may partly measure how the tools were worded, not whether the policy is safe.

SchemaShift asks one controlled question: with the same policy, prompt, parameters, and tool implementations, does changing tool names and descriptions change the agent's actions?

[Show the raw-count table.] We separate attempted calls, committed simulated actions, actual boundary blocks, and no-call responses. Click any run to see the exact tool call and its configuration hash.

[Click Normalize schema.] Here we compare cached trials using canonical names and descriptions. The button works offline. This is a mitigation test, not a promise that neutral names make an agent safe.

[Click Show kill-chain view.] If representation effects do not repeat, the same traces still show where selection, argument validation, and execution succeeded or stopped.

Today's bundled walkthrough uses explicitly labeled synthetic fixtures. No measured effect is claimed. Once the approved model is run, measured golden traces replace these fixtures, and judging still needs no Wi-Fi.

Our contribution is auditable evidence: one task, one model, frozen policy, visible raw calls, and no hidden scoring shortcuts.

## Replace only after measurement

Replace the fixture sentence with: “On this task and model configuration, baseline committed X/N times and variant Y/N times.” Include both confirmation matrices if discussing stability. Never claim a delta when none was measured.
