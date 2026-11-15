# Gauntlet — one entry point for the loop.
# Many targets are thin wrappers that fill in as M0..M4 land; `make score` and
# `make test` already work today on the bundled examples.

PYTHON ?= python3

.DEFAULT_GOAL := help

.PHONY: help up down revert status run score test clean

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

up:  ## bring up the SIEM + targets (M0: fill in lab/)
	@echo "TODO (M0): start Wazuh/Zeek, import boxes, revert to clean snapshots"
	@echo "  see lab/README.md and lab/targets/import-vulnhub.sh"

down:  ## power off the lab
	@echo "TODO (M0): power off SIEM + targets"

revert:  ## reset all targets to their clean snapshot
	bash lab/targets/revert.sh --all

status:  ## show lab VM + SIEM state
	@VBoxManage list runningvms 2>/dev/null || echo "VirtualBox not found"

run:  ## run an attack scenario (M2: SCENARIO=attack/scenarios/<file>)
	@echo "TODO (M2): execute $${SCENARIO:-a scenario} and write runs/<id>/actions.jsonl"

score:  ## score the latest run (defaults to the bundled example)
	$(PYTHON) score/scorer.py $(if $(RUN),--actions runs/$(RUN)/actions.jsonl --alerts runs/$(RUN)/alerts.jsonl,)

test:  ## run detection fixtures + unit tests (CI runs this)
	$(PYTHON) -m pytest -q

clean:  ## remove run output
	rm -rf runs/ out/
