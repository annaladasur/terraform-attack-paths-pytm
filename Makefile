# terraform-attack-paths-pytm
#
#   make setup      create .venv and install the package (no cloud, no API keys)
#   make demo       the whole story on the canonical fixture, offline
#   make demo-live  the live conference demo runbook (local stack + model)
#   make conference produce artifacts/ exactly as shown on stage
#
# Every target works offline from committed plans and baselines. Targets marked
# (tools) need `make tools` (pinned Terraform, provider mirror, tfsec, Trivy) and
# (scanners) need `make setup-scanners` (Checkov in its own venv).

SHELL      := /bin/bash
PY         ?= python3
VENV       := .venv
BIN        := $(VENV)/bin
TAPM       := $(BIN)/tapm
FIXTURE    ?= 006
INJECT     ?= 019
LLM        ?= simulated
DEMO_LLM   ?= ollama
JEV        ?= local
PATCH_LLM  ?= $(LLM)
ART        := artifacts/$(shell ls fixtures | grep '^$(FIXTURE)' | head -1)

export TAPM_TERRAFORM       ?= $(CURDIR)/.tools/bin/terraform
export TAPM_PROVIDER_MIRROR ?= $(CURDIR)/.tools/mirror
export TAPM_TFSEC           ?= $(CURDIR)/.tools/bin/tfsec
export TAPM_TRIVY           ?= $(CURDIR)/.tools/bin/trivy
export TAPM_CHECKOV         ?= $(CURDIR)/.venv-scanners/bin/checkov
export TAPM_GITLEAKS        ?= $(CURDIR)/.tools/bin/gitleaks

.PHONY: help setup setup-scanners tools demo demo-live pr scan model paths story ask explain remediate gate replay-fix canary tamper inject security-tests ai-model \
        conference snapshot fresh-plan rescan replay benchmark report report-check test test-fresh-clone test-fresh-clone-standalone critic secret-scan experiment lab-1 lab-2 lab-3 lab-reset \
        test-pytm-main record docker-build docker-demo clean \
        local-up local-down local-clean local-status local-logs local-bootstrap local-pr local-seed \
        lab-cluster lab-cluster-down lab-cluster-status lab-cluster-bootstrap lab-cluster-pr

help:
	@grep -E '^#   make' Makefile | sed 's/^#   //'
	@echo "  make scan | model | paths | story | ask | explain | remediate | gate | replay-fix | canary | tamper | inject | security-tests | replay | benchmark | test"
	@echo "  make lab-1 | lab-2 | lab-3 | lab-reset      (audience lab)"

$(BIN)/python:
	@$(PY) -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required (pytm 1.4.0)"'
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip

setup: $(BIN)/python
	$(BIN)/pip install -q -e '.[dev]'
	@$(TAPM) --help >/dev/null && echo "setup ok: $$($(BIN)/python --version), pytm $$($(BIN)/python -c 'import importlib.metadata as m; print(m.version("pytm"))')"
	@command -v dot >/dev/null || echo "note: Graphviz 'dot' not found; DFD PNGs will not be re-rendered (pre-rendered copies are in conference-snapshot/)"

setup-scanners:
	$(PY) -m venv .venv-scanners
	.venv-scanners/bin/pip install -q 'checkov==3.3.20'

tools:
	bash scripts/fetch-tools.sh

# ---------------------------------------------------------------- the live demo
demo: pr scan paths model story ask explain tamper inject gate remediate replay-fix
	@echo; echo "report: $(ART)/report.md"

demo-live:
	bash demo/demo-live.sh $(if $(AUTO),--auto,) $(if $(RESET),--reset,) $(if $(BEAT),--beat $(BEAT),) --llm $(if $(filter command line,$(origin LLM)),$(LLM),$(DEMO_LLM)) $(if $(MODEL),--model $(MODEL),)

pr:
	@echo "== Live 1 · the pull request"; bash scripts/pr-diff.sh

scan:
	@echo "== Live 1 · what the scanners say"; $(TAPM) scan $(FIXTURE)

model:
	@echo "== Live 2 · the model: plan -> typed graph -> IAM -> PyTM"; $(TAPM) model $(FIXTURE)

paths:
	@echo "== Live 2 · the attack path"; $(TAPM) paths $(FIXTURE)

ask:
	@echo "== Live 2 · threat modeling as yes/no questions for the app team"; $(TAPM) ask $(FIXTURE)

story:
	@echo "== Live 2 · the same path in plain words (for anyone on the team)"; $(TAPM) story $(FIXTURE) --audience everyone -n 1

explain:
	@echo "== Live 3 · AI enrichment (bounded, evidence-validated)"; $(TAPM) explain $(FIXTURE) --llm $(LLM) --jev $(JEV)

remediate:
	@echo "== Live 4 · AI proposes a fix; the pipeline proves it"; $(TAPM) remediate $(FIXTURE) --llm $(PATCH_LLM)

gate:
	@echo "== Live 4 · the PR through the check at Level 3 (validate)"
	@$(TAPM) gate $(ART) --level validate || echo "  exit $$?: this is how CI blocks the merge"

replay-fix:
	@echo "== Live 4 · the same PR with the verified fix applied, through the same check"; TAPM=$(TAPM) bash scripts/replay-fixed.sh

canary:
	@echo "== Level 5: known-bad plans must block, known-good must pass"; $(TAPM) canary

tamper:
	@echo "== Live 3 · remove the evidence from an accepted annotation"; $(TAPM) tamper --artifacts $(ART)

inject:
	@echo "== Live 3 · prompt injection in Terraform comments"; $(TAPM) inject $(INJECT) --llm $(LLM) --jev $(JEV)

security-tests:
	$(TAPM) security-tests $(FIXTURE)

ai-model:
	$(TAPM) ai-model

# ------------------------------------------------------------ conference mode
conference:
	rm -rf artifacts/conference && $(TAPM) run $(FIXTURE) --out artifacts/conference --llm $(LLM) --jev $(JEV) --remediate
	$(TAPM) inject $(INJECT) --out artifacts/conference-injection --llm $(LLM) --jev $(JEV) >/dev/null
	cp artifacts/conference-injection/prompt-injection.json artifacts/conference/
	$(TAPM) ai-model --out artifacts/conference/ai-threat-model >/dev/null
	@ls -1 artifacts/conference
	@echo "open artifacts/conference/report.md"

snapshot: conference
	rm -rf conference-snapshot && cp -r artifacts/conference conference-snapshot

# ------------------------------------------------ regenerate inputs (tools)
fresh-plan:
	@echo "WARNING: Terraform plans can contain sensitive values in cleartext. Never commit plans of real infrastructure."
	$(TAPM) plan $(FIXTURE) --no-cache

rescan:
	$(TAPM) scan $(FIXTURE) --live

# ------------------------------------------------------------ evidence
replay:
	$(TAPM) replay $(FIXTURE) -n 10

benchmark:
	$(TAPM) bench --replay 10 --llm $(LLM) --jev $(JEV)$(if $(MODEL), --model $(MODEL),)
	$(TAPM) canary $$(ls fixtures) --json evaluations/results/canary.json
	$(TAPM) strata --write-results

report:
	$(BIN)/python -m tapm.eval.report

report-check: report
	git diff --exit-code evaluations/

test:
	$(BIN)/python -m pytest -rs

critic:
	bash scripts/critic.sh

test-fresh-clone:
	bash scripts/test-fresh-clone.sh

test-fresh-clone-standalone:
	bash scripts/test-fresh-clone.sh --standalone


secret-scan:
	bash scripts/critic.sh C16

# forward compatibility: the whole suite against pytm's main branch (unreleased fixes #338-#340)
PYTM_MAIN ?= 7889579
test-pytm-main:
	$(PY) -m venv .venv-pytm-main && .venv-pytm-main/bin/pip install -q -e '.[dev]'
	.venv-pytm-main/bin/pip install -q --force-reinstall --no-deps "pytm @ git+https://github.com/OWASP/pytm@$(PYTM_MAIN)"
	.venv-pytm-main/bin/python -m pytest -q

experiment:
	@echo "v1 (LLM writes the threat model) vs v2 (deterministic + bounded AI). Needs a live model or recorded cassettes."
	$(TAPM) experiment $(FIXTURE) -n $${N:-10} --llm $${RECORD_LLM:-recorded} $${RECORD:+--record}

record:
	@echo "Records live LLM (and optionally Jev) responses into cassettes/ for offline replay."
	$(TAPM) run $(FIXTURE) --llm $${RECORD_LLM:-anthropic} --jev $${RECORD_JEV:-local} --record
	$(TAPM) inject $(INJECT) --llm $${RECORD_LLM:-anthropic} --jev $${RECORD_JEV:-local} --record

# ------------------------------------------------------------ audience lab
lab-1:
	LLM=$(LLM) JEV=$(JEV) bash labs/lab.sh 1
lab-2:
	LLM=$(LLM) JEV=$(JEV) bash labs/lab.sh 2
lab-3:
	LLM=$(LLM) JEV=$(JEV) bash labs/lab.sh 3
lab-reset:
	bash labs/lab.sh reset

# ------------------------------------------------------------ container
docker-build:
	docker build -t terraform-attack-paths-pytm .
docker-demo:
	docker run --rm -it terraform-attack-paths-pytm make demo

# ------------------------------------------------------------ local stack (W2.1)
LOCAL_COMPOSE := examples/local-stack/compose.yaml

local-up:
	docker compose -f $(LOCAL_COMPOSE) up -d gitea analysis-service
	bash examples/local-stack/bootstrap.sh

local-down:
	docker compose -f $(LOCAL_COMPOSE) down

local-clean:
	docker compose -f $(LOCAL_COMPOSE) down -v

local-status:
	docker compose -f $(LOCAL_COMPOSE) ps
	@echo
	@curl -sf http://localhost:8080/health && echo " tapm-service: healthy" || echo " tapm-service: unreachable"
	@curl -sf http://localhost:3000/api/v1/version && echo " gitea: healthy" || echo " gitea: unreachable"

local-logs:
	docker compose -f $(LOCAL_COMPOSE) logs -f

local-bootstrap:
	bash examples/local-stack/bootstrap.sh

local-seed:
	bash examples/local-stack/seed-demo-repo.sh --bundle examples/local-stack/demo-repo.bundle

local-pr:
	bash examples/local-stack/open-pr.sh

# ------------------------------------------------------------ local cluster (W2.3)
CLUSTER_SCRIPT := examples/local-cluster/cluster.sh

lab-cluster:
	bash $(CLUSTER_SCRIPT) up

lab-cluster-down:
	bash $(CLUSTER_SCRIPT) down

lab-cluster-status:
	bash $(CLUSTER_SCRIPT) status

lab-cluster-bootstrap:
	bash $(CLUSTER_SCRIPT) bootstrap

lab-cluster-pr:
	bash $(CLUSTER_SCRIPT) pr

clean:
	rm -rf artifacts .pytest_cache
