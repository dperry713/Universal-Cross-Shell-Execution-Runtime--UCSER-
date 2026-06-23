# UCSER

UCSER is a Python-based control plane for compiling an intent into a UCER
(`Universal Cross-Execution Record`), validating it through policy gates, and
executing it through shell, sandbox, or microVM-oriented adapters.

The repository currently exposes:

- A CLI in `cli/sder_cli.py`
- A FastAPI control plane in `api/rest_server.py`
- Semantic compilation in `semantic/`
- Security policy and audit layers in `security/`
- Execution, storage, and orchestration primitives in `core/` and `engine/`

## Repository Layout

- `api/` - REST and MCP entrypoints plus the dashboard UI
- `cli/` - command-line interface
- `core/` - configuration, UCER models, execution, storage, orchestration
- `engine/` - lower-level execution and adapter helpers
- `semantic/` - intent-to-UCER compilation and LLM client wrappers
- `security/` - policy gates, auditors, and sandbox controls
- `tests/` - unit, integration, and verification tests
- `docs/` - architecture notes and planning artifacts

## Requirements

- Python 3.11 or newer
- A writable local data directory for keys and SQLite state

Runtime dependencies are listed in `requirements.txt`.
Development dependencies are listed in `requirements-dev.txt`.

## Setup

Install the project dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
```

The control-plane key pair and SQLite database are created under a local data
directory. By default, the code uses:

- Windows: `%LOCALAPPDATA%\ucser`
- Unix-like systems: `~/.local/share/ucser`

Override the location with `UCSER_DATA_DIR` if needed.

## CLI Usage

List stored UCER records:

```powershell
python -m cli.sder_cli list
```

Compile and execute a local intent:

```powershell
python -m cli.sder_cli exec "list recent log files" --local
```

Compile an intent and dispatch it through the distributed scheduler path:

```powershell
python -m cli.sder_cli exec "inspect running processes"
```

Replay a recorded UCER:

```powershell
python -m cli.sder_cli replay <ucer_id>
```

## API Usage

Run the FastAPI control plane:

```powershell
python -m api.rest_server
```

Then open:

- `http://localhost:8000/` for the dashboard
- `http://localhost:8000/api/workflows` for workflow data
- `http://localhost:8000/api/audit-logs` for audit entries

## Architecture

The current control flow is:

1. A user submits an intent through the CLI or API.
2. `semantic/` compiles the intent into a UCER object.
3. `security/policy.py` evaluates the UCER against safety rules.
4. `core/executor.py` routes the UCER to the active adapter and records traces.
5. `core/db.py` persists the record locally or through NATS-backed state.

See `docs/architecture.md` for a slightly more detailed overview.

## Security Model

- Do not commit private keys or local SQLite files.
- Runtime keys and state are generated outside the repository root.
- `security/` contains AST-driven policy checks, sandbox helpers, and
  environment-specific guards.

This repository is still an active implementation, so the security layers
should be reviewed before exposing it to untrusted inputs or production use.

## Development

Run the quality checks locally:

```powershell
ruff check .
black --check .
mypy core semantic api cli engine security utils
pytest
```

If you only want a quick smoke test, start with:

```powershell
pytest tests
```

## Notes

- `engine/adapters/` is the current adapter implementation surface.
- The top-level `adapters/` package remains as compatibility glue.
- No license file is currently included in the repository.
