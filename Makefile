.PHONY: install lint test check policy-test eval demo serve docker clean

PY ?= python

install:
	$(PY) -m pip install -e ".[dev,llm]"

lint:
	ruff check src tests scripts
	ruff format --check src tests scripts
	mypy
	bandit -q -r src -c pyproject.toml
	$(PY) scripts/check_hidden_chars.py

test:
	pytest -W error --cov --cov-report=term-missing

policy-test:
	agentwarden policy validate
	agentwarden policy test tests/policy/default_policy_cases.yaml

eval:
	agentwarden eval

check: lint test policy-test eval

demo:
	agentwarden demo

serve:
	agentwarden serve --port 8000

docker:
	docker build -t agentwarden:local .

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist build
