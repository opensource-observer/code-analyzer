# Code Analyzer

Index GitHub repositories from OSO `artifacts_v1` and collect direct dependencies (npm, Python/PyPI, Rust crates), git submodules, and Foundry libs into Parquet snapshots and an events stream.

## Quick start (local)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Configure credentials (use .env locally if you prefer)
export OSO_API_KEY="<your_api_key>"
# optional for higher clone rate limits
export GITHUB_TOKEN="<your_gh_pat>"

# Small test run (default limit applies if no --only)
./.venv/bin/python scripts/sbom_fetcher.py --output-dir data/sbom --incremental

# Focused owner run (no default limit when --only is provided)
./.venv/bin/python scripts/sbom_fetcher.py --output-dir data/sbom --only opensource-observer/ --limit 0 --incremental

# Source the deactivate script:
source .venv/bin/deactivate
```

## GitHub Actions

1. Add repository secrets: `OSO_API_KEY` and (optionally) `GITHUB_TOKEN`.
2. Run the "SBOM fetcher" workflow manually or wait for the daily schedule.

Outputs are written under `data/sbom/` and committed back to the repo.

Notes:
- Provide `OSO_API_KEY` and optionally `GITHUB_TOKEN` as repository Secrets.
- `.env` files are for local development only; Actions will not read them.

## Supported ecosystems (direct deps)

- npm (`package.json`) — dependencies, devDependencies, peerDependencies
- Python/PyPI (`pyproject.toml`, `requirements*.txt`) — PEP 621 and Poetry
- Rust/Cargo (`Cargo.toml`) — dependencies, dev-dependencies, build-dependencies
- Git submodules (`.gitmodules`)
- Foundry (`foundry.toml`, `lib/*`)

## Output layout

- `data/sbom/snapshots/{artifact_namespace__artifact_name}/{YYYY-MM-DD}/*.parquet`
- `data/sbom/events/{YYYY-MM-DD}/*.parquet`
- `data/sbom/state.json`
- `data/sbom/run_summaries/*.parquet`

## Data model

- Snapshots (subset of columns):
  - `artifact_id`, `artifact_source`, `artifact_namespace`, `artifact_name`, `artifact_url`, `repo_head_sha`
  - `package_manager`, `dependency_name`, `dependency_version_requirement`, `dependency_scope`, `manifest_path`, `direct`
  - `time_collected`

- Events columns:
  - `artifact_namespace`, `artifact_name`, `package_manager`, `dependency_name`, `change_type` (added/removed/updated), `previous_version`, `current_version`, `event_time_collected`

## Runtime controls

- Flags:
  - `--only <owner>`: filter by owner/namespace (trailing slash optional)
  - `--limit <N>`: cap number of repos (use `0` for all; recommended with `--only`)
  - `--incremental`: skip repos whose HEAD SHA is unchanged
  - `--max-workers <N>`: concurrent clones/parsers (default via `SBOM_MAX_WORKERS`)

- Environment variables:
  - `SBOM_MAX_WORKERS` (default 8)
  - `SBOM_GIT_CLONE_RETRIES` (default 2)
  - `SBOM_GIT_CLONE_TIMEOUT` (seconds, default 120)
  - `SBOM_GIT_CMD_TIMEOUT` (seconds, default 60)