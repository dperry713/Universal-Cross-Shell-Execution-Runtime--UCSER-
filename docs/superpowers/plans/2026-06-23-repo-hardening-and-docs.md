# Repo Hardening and Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove committed secrets and generated artifacts, move runtime state out of the repository root, and add the missing project docs and developer tooling.

**Architecture:** Treat repo hygiene and runtime safety as the first-class fix: add ignore rules, stop writing control-plane keys and SQLite state into the project root, and keep runtime files under a dedicated local data directory. Then add a single source of truth for build/test tooling and document how to run the CLI, API, and tests.

**Tech Stack:** Python, FastAPI, SQLite, pytest, Ruff, Black, mypy, GitHub Actions.

---

### Task 1: Remove tracked secrets and build artifacts

**Files:**
- Modify: `.gitignore`
- Delete: `cp_private.pem`
- Delete: `cp_public.pem`
- Delete: `sder.db`
- Delete: `.pytest_cache/**`
- Delete: `**/__pycache__/**`

- [ ] **Step 1: Add ignore rules for secrets, databases, caches, and runtime outputs**

```gitignore
# Python
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.coverage
htmlcov/

# Local runtime state
cp_private.pem
cp_public.pem
sder.db
runtime_space/

# Virtual environments and packaging
.venv/
venv/
dist/
build/
*.egg-info/
```

- [ ] **Step 2: Remove the committed secret/database/cache files from the working tree**

Run:
```powershell
Remove-Item -LiteralPath cp_private.pem, cp_public.pem, sder.db -Force
Remove-Item -LiteralPath .pytest_cache -Recurse -Force
Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
```

Expected: the repo no longer contains private keys, database snapshots, or bytecode caches.

- [ ] **Step 3: Verify the tree is clean of generated artifacts**

Run:
```powershell
git status --short
```

Expected: no tracked secrets or cache directories remain in the tree.

### Task 2: Move runtime key and DB defaults out of the repo root

**Files:**
- Modify: `core/config.py`
- Modify: `core/executor.py`
- Modify: `core/db.py`

- [ ] **Step 1: Add a dedicated local data directory helper in config**

```python
from pathlib import Path

def _local_data_dir() -> str:
    base = Path(os.getenv("UCSER_DATA_DIR", Path(os.getenv("LOCALAPPDATA", Path.home() / ".local" / "share")) / "ucser"))
    base.mkdir(parents=True, exist_ok=True)
    return str(base)
```

- [ ] **Step 2: Point private key, public key, and SQLite defaults at the local data directory**

```python
data_dir = _local_data_dir()
cp_private_key_path: str = os.getenv("UCSER_CP_PRIVATE_KEY", os.path.join(data_dir, "cp_private.pem"))
cp_public_key_path: str = os.getenv("UCSER_CP_PUBLIC_KEY", os.path.join(data_dir, "cp_public.pem"))
db_path: str = os.getenv("UCSER_DB_PATH", os.path.join(data_dir, "sder.db"))
```

- [ ] **Step 3: Ensure executor bootstrap creates parent directories before writing keys**

```python
os.makedirs(os.path.dirname(self.cp_priv_path), exist_ok=True)
os.makedirs(os.path.dirname(self.cp_pub_path), exist_ok=True)
```

- [ ] **Step 4: Make the SQLite backend create its parent directory before opening the database**

```python
os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
```

- [ ] **Step 5: Run focused tests or a smoke import to confirm the new defaults work**

Run:
```powershell
python -c "from core.config import config; print(config.cp_private_key_path); print(config.db_path)"
```

Expected: both paths point outside the repo root and their parent directory exists.

### Task 3: Add a real README with setup, usage, and architecture

**Files:**
- Create: `README.md`
- Create: `docs/architecture.md`

- [ ] **Step 1: Write a README that explains what the project is and how to run it**

Include:
```markdown
# UCSER

## What it does
## Repository layout
## Requirements
## Setup
## CLI usage
## API usage
## Security model
## Development
## Testing
## Troubleshooting
```

- [ ] **Step 2: Document concrete commands for install, CLI, and API**

Include:
```powershell
pip install -r requirements.txt
python -m cli.sder_cli list
python -m cli.sder_cli exec "list recent log files" --local
python -m api.rest_server
```

- [ ] **Step 3: Document the architecture and note the current adapter layout**

Explain:
```markdown
- `core/` contains execution, policy, storage, and orchestration primitives.
- `semantic/` handles intent-to-UCER compilation.
- `engine/adapters/` is the current execution adapter layer.
- Top-level `adapters/` is compatibility/legacy surface area.
```

- [ ] **Step 4: Include a security note about local secrets and runtime data**

Document that private keys and SQLite state are generated under the local data directory, not checked into git.

### Task 4: Add developer tooling and CI

**Files:**
- Create: `pyproject.toml`
- Create: `requirements-dev.txt`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Add tool configuration for Ruff, Black, and mypy**

```toml
[tool.black]
line-length = 100

[tool.ruff]
line-length = 100

[tool.mypy]
python_version = "3.11"
ignore_missing_imports = true
```

- [ ] **Step 2: Add development dependencies**

```text
ruff>=0.6.0
black>=24.0.0
mypy>=1.10.0
pytest>=8.0.0
pytest-asyncio>=0.23.0
```

- [ ] **Step 3: Add a CI workflow that runs formatting, linting, type checking, and tests**

```yaml
name: ci
on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install --upgrade pip
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: ruff check .
      - run: black --check .
      - run: mypy core semantic api cli engine security utils
      - run: pytest
```

- [ ] **Step 4: Run the same checks locally**

Run:
```powershell
python -m pip install -r requirements.txt -r requirements-dev.txt
ruff check .
black --check .
mypy core semantic api cli engine security utils
pytest
```

Expected: the repo has a reproducible developer workflow and CI gate.

### Task 5: Add basic contribution and issue templates

**Files:**
- Create: `.github/ISSUE_TEMPLATE/bug_report.md`
- Create: `.github/ISSUE_TEMPLATE/feature_request.md`
- Create: `CONTRIBUTING.md`

- [ ] **Step 1: Add a bug report template that asks for reproduction steps and environment details**

```markdown
---
name: Bug report
about: Report a reproducible problem
---
```

- [ ] **Step 2: Add a feature request template that asks for use case and acceptance criteria**

```markdown
---
name: Feature request
about: Request an enhancement
---
```

- [ ] **Step 3: Add contribution guidance for tests, linting, and secret handling**

Explain how to run the checks from Task 4 and state that secrets and runtime databases must not be committed.

### Task 6: Verification pass

**Files:**
- Modify: any files touched above if verification exposes issues

- [ ] **Step 1: Run the test suite and fix any regressions introduced by the cleanup**

Run:
```powershell
pytest
```

- [ ] **Step 2: Run formatting and lint checks**

Run:
```powershell
ruff check .
black --check .
```

- [ ] **Step 3: Inspect git status and confirm only intentional files are changed**

Run:
```powershell
git status --short
```

Expected: only the intended repo-hardening and docs/tooling changes remain.
