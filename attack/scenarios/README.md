# Scenarios (M2)

Declarative, deterministic attack recipes — one `cmd` per step, each tagged with
its ATT&CK `technique` and whether we `expect_detect`. The runner (M2) executes
each step and calls the emitter so every step lands in `runs/<id>/actions.jsonl`.

Start deterministic. The M4 AI agent plugs in here later and is scored against
these same scenarios as the baseline.
