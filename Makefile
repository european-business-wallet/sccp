# SCC specification tooling.
#
# Requires: python3, and the cddl and cbor-diag tools:
#   cargo install cddl --locked
#   cargo install cbor-diag-cli --locked

PYTHON ?= .venv/bin/python

.PHONY: check examples venv

check: $(PYTHON)
	$(PYTHON) tools/check.py

examples: $(PYTHON)
	rm -rf spec/examples/invalid spec/examples/delivery spec/examples/json \
	       spec/examples/*.cbor spec/examples/*.diag spec/examples/manifest.json
	$(PYTHON) tools/gen_examples.py

venv: $(PYTHON)

$(PYTHON):
	python3 -m venv .venv
	.venv/bin/pip install -q -r requirements.txt
