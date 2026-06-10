# Contributing to IOC Analyzer

Thank you for helping improve IOC Analyzer.

## Development Workflow

1. Fork the repository and create a feature branch.
2. Install dependencies with `pip install -r requirements.txt`.
3. Run tests with `pytest`.
4. Keep changes focused, documented, and covered by tests.
5. Open a pull request with a clear summary, threat-intel rationale, and validation notes.

## Coding Standards

- Follow PEP 8 and use type hints.
- Prefer small, testable functions with descriptive docstrings.
- Add or update tests for behavior changes.
- Avoid introducing external dependencies unless they clearly improve maintainability.

## Reporting Bugs

Please include:

- The IOC input that triggered the problem.
- Expected behavior versus actual behavior.
- Python version and operating system details.
- Relevant logs from `logs/analysis.log`.
