# ULPF developer/operator shortcuts. Every target wraps commands documented in
# docs/; nothing here needs the network once runtime/dist and runtime/wheelhouse
# are populated (`make fetch` downloads them once; see README.md, Setup).
PY      ?= python3
VENV    := .venv
U       := $(VENV)/bin/ulpf
PYTEST  := $(VENV)/bin/python -m pytest

.PHONY: help fetch venv runtime doctor lint compile test test-fast test-golden up down status \
        secure demo-live demo-stop demo-onboarding demo-tamper demo-outage bundle airgap-test bench lake clean

help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/' | expand -t 18

fetch: ## ONLINE, once: download the pinned wheels and Vector/OpenSearch artifacts into runtime/ (sha256-checked)
	$(PY) -m venv $(VENV)
	mkdir -p runtime/wheelhouse
	cp -p deploy/wheels/*.whl runtime/wheelhouse/
	$(VENV)/bin/pip download --quiet --require-hashes --only-binary=:all: --find-links runtime/wheelhouse \
	  --dest runtime/wheelhouse -r requirements.lock
	PYTHONPATH=$(CURDIR) $(PY) -c 'from ulpf import paths, runtime; print("\n".join(runtime.fetch(paths.RUNTIME / "dist", include_optional=False)))'

venv: ## offline venv from runtime/wheelhouse (hash-pinned) + ulpf from this tree
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --no-index --find-links runtime/wheelhouse --require-hashes \
	  --only-binary=:all: -r requirements.lock
	$(VENV)/bin/python -c 'import sysconfig,pathlib; pathlib.Path(sysconfig.get_paths()["purelib"],"ulpf-src.pth").write_text("$(CURDIR)\n")'
	printf '#!$(CURDIR)/$(VENV)/bin/python\nimport sys\nfrom ulpf.cli import main\nsys.exit(main())\n' > $(U)
	chmod 0755 $(U)

runtime: ## verify pinned artifacts in runtime/dist and install Vector/OpenSearch(+security)
	$(U) runtime verify
	$(U) runtime install --with-security

doctor: ## installation self-check
	$(U) doctor

lint: ## lint every approved spec
	$(U) spec lint

compile: ## compile specs, validate with Vector, write the live config atomically
	$(U) spec compile

test: ## full pytest suite (live tests skip when the stack is down)
	$(PYTEST) -q

test-fast: ## unit + golden tests only
	$(PYTEST) -q tests/unit tests/golden

test-golden: ## spec vectors through the real Vector binary
	$(U) test

secure: ## generate secrets/certs and enable OpenSearch security (restart opensearch afterwards)
	$(U) secrets init
	$(U) certs init
	$(U) os secure

up: compile ## start OpenSearch, Vector and the UI
	$(U) stack up

down:
	$(U) stack down

status:
	$(U) stack status

demo-live: ## live parsing demo: UI in demo mode, Start/Stop synthetic traffic on the Live feed page
	$(U) stack up opensearch
	$(U) stack up vector
	$(U) stack down ui
	ULPF_DEMO=1 $(U) stack up ui
	@echo "Open http://127.0.0.1:8501/?page=live and press Start (traffic stops by itself after 15 minutes)."

demo-stop: ## stop demo traffic and restart the UI in normal mode
	$(VENV)/bin/python -c 'from ulpf import demo; print(demo.stop())'
	$(U) stack down ui
	$(U) stack up ui

demo-onboarding: ## Scenario 3 live in an isolated home (shared OpenSearch)
	$(VENV)/bin/python scripts/demo_onboarding.py 200

demo-tamper: ## Scenario 5 on a copy of the archive
	bash scripts/demo_tamper.sh

demo-outage: ## OpenSearch outage: archive keeps up, index catches up
	$(VENV)/bin/python scripts/demo_outage.py 2000

bundle: ## signed offline bundle in runtime/bundle
	$(U) bundle lock
	$(U) bundle build

airgap-test: ## Scenario 9: install + run from the bundle inside a no-network namespace
	bash scripts/airgap_test.sh

bench: ## throughput / latency / resource benchmark against the live stack
	$(VENV)/bin/python scripts/benchmark.py

lake: ## compact closed normalized files to Parquet, prune the NDJSON (~16x larger), verify
	$(U) lake compact --prune
	$(U) lake verify

clean: ## remove regenerable leftovers: batch configs, air-gap sandbox, bundle dir, test caches (never data/keys)
	rm -rf -- runtime/tmp runtime/airgap-test runtime/bundle .pytest_cache
	find . -name __pycache__ -type d -prune -not -path './.venv/*' -exec rm -rf -- {} +
