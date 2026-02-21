# Soul Protocol — Build & Coverage Automation
# Usage: make build | make test | make coverage | make coverage-analyze

SHELL := /bin/bash
FORGE := forge
PYTHON := python3

# ─── Build ────────────────────────────────────────
.PHONY: build test clean

build:
	$(FORGE) build
	npx hardhat compile

test:
	$(FORGE) test -vvv
	npx hardhat test test/privacy/PrivacyZoneManager.test.ts test/privacy/DataAvailabilityOracle.test.ts test/relayer/HeterogeneousRelayerRegistry.test.ts

clean:
	$(FORGE) clean
	npx hardhat clean
	rm -f lcov.info .gas-snapshot

# ─── Coverage ─────────────────────────────────────
.PHONY: coverage coverage-lcov coverage-analyze coverage-ci coverage-restore coverage-forge

## Run coverage with summary output (uses stub-swap)
coverage:
	$(PYTHON) scripts/run_coverage.py --report=summary

## Run coverage and produce lcov.info (uses stub-swap)
coverage-lcov:
	$(PYTHON) scripts/run_coverage.py --report=lcov

## Analyze existing lcov.info and print per-module report
coverage-analyze:
	$(PYTHON) scripts/analyze_coverage.py --lcov lcov.info

## Full CI coverage pipeline: generate lcov → analyze → enforce threshold
coverage-ci:
	$(PYTHON) scripts/run_coverage.py --report=lcov
	$(PYTHON) scripts/analyze_coverage.py --lcov lcov.info --threshold 85

## Emergency restore after interrupted coverage run
coverage-restore:
	$(PYTHON) scripts/run_coverage.py --restore

## Direct Foundry coverage (memory-safe assembly required, ~30 min)
coverage-forge:
	FOUNDRY_PROFILE=coverage $(FORGE) coverage --ir-minimum --report summary

# ─── Validate stubs match production ABIs ─────────
.PHONY: validate-stubs
validate-stubs:
	$(PYTHON) scripts/validate_stubs.py

# ─── Security ─────────────────────────────────────
.PHONY: lint slither security-quick

lint:
	npx solhint 'contracts/**/*.sol' --config .solhint.json

slither:
	slither . --config-file slither.config.json

security-quick: lint slither
	$(FORGE) test --match-path 'test/fuzz/*' --fuzz-runs 1000

# ─── Gas ──────────────────────────────────────────
.PHONY: gas-report gas-snapshot

gas-report:
	$(FORGE) test --gas-report

gas-snapshot:
	$(FORGE) snapshot --match-contract GasSnapshotBenchmark

# ─── Noir ─────────────────────────────────────────
.PHONY: noir-test noir-compile

noir-compile:
	cd noir && nargo compile --workspace

noir-test:
	cd noir && nargo test --workspace

# ─── Certora ──────────────────────────────────────
.PHONY: certora-check certora-verify

## Compile-check all Certora specs (no prover run)
certora-check:
	@for conf in certora/conf/*.conf; do \
		echo "=== Compile-checking $$conf ==="; \
		certoraRun "$$conf" --compilation_steps_only || true; \
	done

## Run full Certora prover verification (requires CERTORAKEY)
certora-verify:
	@if [ -z "$$CERTORAKEY" ]; then \
		echo "ERROR: CERTORAKEY not set. Export your Certora API key first."; \
		exit 1; \
	fi
	@for conf in certora/conf/*.conf; do \
		echo "=== Verifying $$conf ==="; \
		certoraRun "$$conf" || true; \
	done

# ─── SDK ──────────────────────────────────────────
.PHONY: sdk-build sdk-test

sdk-build:
	cd sdk && npm ci && npm run build

sdk-test: sdk-build
	cd sdk && npm run test:all
