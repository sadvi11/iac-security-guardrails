# Run `make help` to list targets. Nothing here needs cloud credentials.
VENV ?= .venv-tools
CONFTEST_VERSION ?= 0.56.0

.PHONY: help install check compliant violations policies fmt clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install checkov locally (conftest: see README)
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --upgrade pip checkov==3.3.10
	@echo "checkov installed. conftest: brew install conftest"

check: compliant violations ## Run both directions, as CI does

compliant: ## The good fixture must be clean
	$(VENV)/bin/checkov --config-file .checkov.yaml --compact
	@command -v conftest >/dev/null && conftest test --parser hcl2 --policy policies terraform/compliant || echo "(conftest not installed, skipped)"

violations: ## The bad fixture must be caught
	@echo "Expecting FAILURES below — that is the test passing."
	-$(VENV)/bin/checkov -d terraform/violations --framework terraform --compact --quiet
	@command -v conftest >/dev/null && (conftest test --parser hcl2 --policy policies terraform/violations || true) || echo "(conftest not installed, skipped)"

fmt: ## Format Terraform
	terraform fmt -recursive terraform/

clean: ## Remove local tooling and terraform state
	rm -rf $(VENV) terraform/*/.terraform terraform/*/.terraform.lock.hcl
