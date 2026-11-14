# Scope & authorized use

PurpleLoop is a **lab-only** tool. It exists to attack machines you own, on an
isolated network, to measure your own detections.

- The offensive harness runs **only** against the bundled lab targets on the
  host-only network. A target outside the lab's own CIDR is refused — same
  discipline as ReconAI's `--i-am-authorized` gate.
- Targets are VulnHub images you downloaded for study, run disconnected from any
  production or public network.
- Never point the attacker at a host you are not explicitly authorized to test.
- Secrets detected during a run are redacted before any remote-model call.

If you can't answer "do I own this target and is it isolated?" with yes, stop.
