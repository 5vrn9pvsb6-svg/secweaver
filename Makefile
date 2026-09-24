PYTHON ?= python3
VENV_DIR ?= .venv
VENV_PY := $(VENV_DIR)/bin/python
VENV_PIP := $(VENV_DIR)/bin/pip
REPORT_DIR ?= examples/reports

.PHONY: help setup quickstart check-python check-venv-python ai-setup ai-setup-all ai-showcase ci ci-final-release-scan validate validate-all-roots sync-dataasset-contracts validate-policy strict release-scan open-source-export docs-check sbom sbom-check agent-check attack-lab-check catalog demo demo-alert demo-traceability demo-risk demo-completeness list ui test reports clean-reports

help:
	@echo "SecWeaver local commands"
	@echo ""
	@echo "  make quickstart        Set up Python and all AI hosts, validate, run all demos"
	@echo "  make ai-setup HOST=... Generate one adapter; use HOST=all for every supported host"
	@echo "  make ai-showcase       Run all offline cases + readable reports; optionally set CASE=<case_id>"
	@echo "  make ci                CI gate: release, docs, Agent, validation, tests, demos"
	@echo "  make agent-check       Run secweaver-agent fmt, vet, test, race and build gates"
	@echo "  make setup             Check Python 3.10+, create .venv, install dependencies"
	@echo "  make validate          Validate dataasset registry"
	@echo "  make validate-all-roots Validate every local DataAsset root and shared contracts"
	@echo "  make sync-dataasset-contracts Preview shared DataAsset contract drift; WRITE=1 applies"
	@echo "  make validate-policy   Validate behavior-policy MD ↔ JSON sync"
	@echo "  make strict            Validate with strict active gate"
	@echo "  make release-scan      Run open-source pre-release hygiene checks"
	@echo "  make attack-lab-check  Syntax-check Attack Lab scripts and compose file"
	@echo "  make open-source-export OUTPUT=/tmp/secweaver-community.tar.gz"
	@echo "  make docs-check        Check Markdown links and private command references"
	@echo "  make sbom              Regenerate third-party notices and the source SBOM"
	@echo "  make sbom-check        Check supply-chain artifacts against dependency declarations"
	@echo "  make catalog           Sync dataasset/catalog.json"
	@echo "  make demo              Run all offline demos"
	@echo "  make reports           Run demos and generate Markdown reports"
	@echo "  make demo-alert        Run alert-confirmation demo"
	@echo "  make demo-traceability Run traceability demo"
	@echo "  make demo-risk         Run risk-identification demo"
	@echo "  make demo-completeness Run data-source-completeness demo"
	@echo "  make list              List available CLI demos and skills"
	@echo "  make ui                Start local DataAsset Studio"
	@echo "  make test              Run all unit and CLI/demo regression tests"

# Reject an unsupported interpreter before venv creation or dependency installation.
check-python:
	@command -v "$(PYTHON)" >/dev/null 2>&1 || { echo "Python interpreter '$(PYTHON)' was not found; set PYTHON=python3.10 or newer."; exit 2; }
	@$(PYTHON) -c 'import sys; actual = sys.version_info[:2]; minimum = (3, 10); sys.exit("SecWeaver requires Python 3.10+; found Python {}.{}".format(*actual)) if actual < minimum else None'

# Keep the interpreter check on every Make invocation without making an existing
# venv perpetually stale just because check-python is a phony target.
$(VENV_PY): | check-python
	$(PYTHON) -m venv $(VENV_DIR)

# An existing venv may have been created by an older system Python, so validate
# the interpreter that will actually install and run SecWeaver as well.
check-venv-python: $(VENV_PY)
	@$(VENV_PY) -c 'import sys; actual = sys.version_info[:2]; minimum = (3, 10); sys.exit("$(VENV_DIR) uses Python below 3.10; remove it and rerun with PYTHON=python3.10 or newer (found Python {}.{})".format(*actual)) if actual < minimum else None'

setup: check-venv-python
	$(VENV_PY) -m pip install -r requirements-data-access.txt

# The Python orchestrator gives Linux, macOS, and WSL2 the same validation,
# demos, and adapter setup sequence; native Windows is redirected to WSL2.
quickstart:
	$(PYTHON) src/scripts/quickstart.py --venv-dir "$(VENV_DIR)" --report-dir "$(REPORT_DIR)"

ai-setup:
	@test -n "$(HOST)" || { echo "HOST=all|codex|cursor|claude|openclaw|workbuddy is required"; exit 2; }
	$(PYTHON) src/scripts/ai_host_setup.py --host "$(HOST)"

# Quickstart installs every thin adapter so users can open any supported host next.
ai-setup-all:
	$(PYTHON) src/scripts/ai_host_setup.py --host all

ai-showcase: setup
	$(VENV_PY) src/scripts/run_ai_showcase.py $(CASE)

ci: setup hygiene-check release-scan docs-check sbom-check agent-check attack-lab-check validate-all-roots validate-policy test demo ci-final-release-scan

# Demo generation rewrites published report fixtures, so scan the final tree too.
ci-final-release-scan: $(VENV_PY)
	$(VENV_PY) src/scripts/release_scan.py

agent-check:
	$(MAKE) -C src/tools/secweaver-agent check

validate: setup
	$(VENV_PY) src/secweaver.py validate

validate-all-roots: setup
	$(VENV_PY) src/dataasset/validate_roots.py --strict

sync-dataasset-contracts: setup
	$(VENV_PY) src/dataasset/sync_shared_contracts.py $(if $(WRITE),--write,--check)

validate-policy: setup
	$(VENV_PY) src/skills/risk-identification/scripts/validate_policy_sync.py --strict

strict: setup
	$(VENV_PY) src/secweaver.py validate --json --strict

release-scan: $(VENV_PY)
	$(VENV_PY) src/scripts/release_scan.py

open-source-export: $(VENV_PY)
	@test -n "$(OUTPUT)" || { echo "OUTPUT=/path/secweaver-community.tar.gz is required"; exit 2; }
	$(VENV_PY) src/scripts/release_scan.py
	$(VENV_PY) src/scripts/export_open_source.py "$(OUTPUT)"

docs-check: $(VENV_PY)
	$(VENV_PY) src/scripts/check_docs_links.py
	$(VENV_PY) src/scripts/check_public_doc_commands.py

attack-lab-check:
	@fail=0; \
	for script in attack_test/environmentDeployment/*.sh \
	              attack_test/environmentDeployment/lib/*.sh \
	              attack_test/environmentDeployment/case*/*.sh; do \
		bash -n "$$script" || fail=1; \
	done; \
	if command -v docker >/dev/null 2>&1; then \
		docker compose -f attack_test/environmentDeployment/case4-webPenetrateToSSH/docker-compose.yml config >/dev/null \
			|| fail=1; \
	else \
		echo "docker not available; compose validation runs in CI"; \
	fi; \
	exit $$fail

sbom:
	$(PYTHON) src/scripts/generate_supply_chain.py

sbom-check:
	$(PYTHON) src/scripts/generate_supply_chain.py --check

catalog: setup
	$(VENV_PY) src/secweaver.py catalog sync

demo: setup
	$(VENV_PY) src/secweaver.py demo all -o $(REPORT_DIR)

reports: demo
	$(VENV_PY) src/secweaver.py report markdown --demo all --input-dir $(REPORT_DIR) --bundle -o $(REPORT_DIR)/investigation-report.md

demo-alert: setup
	$(VENV_PY) src/secweaver.py demo alert

demo-traceability: setup
	$(VENV_PY) src/secweaver.py demo traceability

demo-risk: setup
	$(VENV_PY) src/secweaver.py demo risk

demo-completeness: setup
	$(VENV_PY) src/secweaver.py demo completeness

list: setup
	$(VENV_PY) src/secweaver.py list

ui: setup
	$(VENV_PY) dataasset-ui/server.py

test: setup
	$(VENV_PY) tests/run_tests.py

clean-reports:
	rm -f examples/reports/demo-*-output.json

.PHONY: test-operator-contract
# Private integration is explicit; public CI must not fetch private source.
test-operator-contract:
	REQUIRE_OPERATOR_CONTRACT_TESTS=1 $(PYTHON) -m unittest discover -s tests -p test_operator_standalone.py -v

.PHONY: hygiene-check
hygiene-check:
	$(PYTHON) src/scripts/check_tracked_hygiene.py
