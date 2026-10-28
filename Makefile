.PHONY: help install test lint scan bench check docs build clean

PY ?= python

help:           ## list the targets
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | sort

install:        ## editable install with dev tools
	$(PY) -m pip install -e ".[dev]"

test:           ## run the test suite
	$(PY) -m pytest -q

lint:           ## ruff on code, tests and benchmark scripts
	ruff check src tests benchmarks/compare.py benchmarks/realworld.py

scan:           ## slopguard scans itself
	slopguard scan . --no-network

bench:          ## benchmark gate on the labelled corpus
	slopguard bench --min-precision 0.85

check: lint test scan bench   ## everything CI runs

docs:           ## regenerate docs/rules.md and docs/cli.md
	$(PY) -m slopguard.docgen

build:          ## build the wheel and sdist and check them
	$(PY) -m pip install build twine
	$(PY) -m build
	twine check dist/*

clean:
	rm -rf dist build .pytest_cache .ruff_cache src/*.egg-info
