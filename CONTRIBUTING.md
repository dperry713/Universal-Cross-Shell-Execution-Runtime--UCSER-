# Contributing

## Setup

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
```

## Before You Open a PR

Run the local checks:

```powershell
ruff check .
black --check .
mypy core semantic api cli engine security utils
pytest
```

## Working Rules

- Do not commit private keys, SQLite databases, or bytecode caches.
- Keep runtime state under the local data directory.
- Prefer small, reviewable changes with a focused test update.

## Reporting Issues

Use the issue templates in `.github/ISSUE_TEMPLATE/` when filing bugs or feature
requests. Include reproduction steps, environment details, and expected versus
actual behavior.
