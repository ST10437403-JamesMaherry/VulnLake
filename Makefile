.PHONY: test lint ingest-cisa ingest-epss

# Run the deterministic VulnLake test suite.
test:
	.venv/bin/python -m pytest -v

# Run static lint checks across application and test code.
lint:
	.venv/bin/python -m ruff check src tests

# Retrieve the live CISA KEV dataset and persist it to Bronze.
ingest-cisa:
	.venv/bin/python -m vulnlake.cli ingest-cisa

# Retrieve the live FIRST EPSS bulk score set and persist it to Bronze.
ingest-epss:
	.venv/bin/python -m vulnlake.cli ingest-epss