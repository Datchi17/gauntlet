# attack/ — offensive harness (M2)

`emitter.py` writes the ground-truth action log; `scenarios/` holds deterministic
recipes. The runner that executes a scenario end-to-end (wrapping ReconAI's chain)
is the main M2 build. AI comes in M4 and is scored against these baselines.
