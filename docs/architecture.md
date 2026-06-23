# Architecture Overview

UCSER is organized around a single flow: intent in, policy validation, execution,
and durable trace capture.

## Major Components

- `cli/` provides the terminal entrypoint.
- `api/rest_server.py` exposes the dashboard, SSE stream, and control-plane APIs.
- `semantic/` converts user intent into a UCER structure.
- `security/` audits the resulting command plan before execution is allowed.
- `core/` contains the execution pipeline, scheduler, configuration, and storage.
- `engine/` contains adapter and execution-layer helpers used by the core facade.

## Data Flow

```text
intent -> semantic compiler -> UCER -> policy gate -> executor -> traces -> db
```

## Runtime State

Keys, databases, and other writable state are stored in the local data directory
resolved by `core.config`. The default location is outside the repository root
so runtime artifacts do not get committed accidentally.

## Adapter Layout

There are two adapter surfaces in the tree:

- `engine/adapters/` is the current implementation layer.
- `adapters/` exists for compatibility with older entrypoints and wrappers.

When adding new execution behavior, prefer the `engine/adapters/` layer unless
you are preserving an older API contract.
