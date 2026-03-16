.PHONY: install install-dev lint format typecheck test test-coverage build clean

PYTHON ?= python3
SRC = src/phantompilot
TESTS = tests

install:
	$(PYTHON) -m pip install .

install-dev:
	$(PYTHON) -m pip install -e ".[all]"

lint:
	ruff check $(SRC) $(TESTS)
	ruff format --check $(SRC) $(TESTS)

format:
	ruff check --fix $(SRC) $(TESTS)
	ruff format $(SRC) $(TESTS)

typecheck:
	mypy --strict $(SRC)

test:
	pytest $(TESTS) -x -q

test-coverage:
	pytest $(TESTS) --cov=phantompilot --cov-report=term-missing --cov-report=html:htmlcov -x -q

build: clean
	$(PYTHON) -m build

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
