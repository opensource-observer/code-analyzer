import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
import xml.etree.ElementTree as ET
from pyoso import Client

try:
    import tomllib # Python 3.11+
except Exception:
    tomllib = None
try:
    import toml # Fallback for <3.11
except Exception:
    toml = None

def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_toml(path: Path) -> Optional[dict]:
    try:
        if tomllib:
            return tomllib.loads(path.read_text(encoding="utf-8"))
        if toml:
            return toml.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None


def _git_clone(url: str, dest: Path, token: Optional[str]) -> bool:
    if token:
        url = re.sub(r"^https://", f"https://{token}@", url)
    retries = int(os.getenv("SBOM_GIT_CLONE_RETRIES", "2"))
    timeout_seconds = int(os.getenv("SBOM_GIT_CLONE_TIMEOUT", "120"))
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    for attempt in range(retries + 1):
        cmd = ["git", "clone", "--depth", "1", "--no-tags", url, str(dest)]
        try:
            cp = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_seconds, env=env)
            if cp.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
        # Cleanup and retry
        shutil.rmtree(dest, ignore_errors=True)
    return False


def _git_head_sha(repo_dir: Path) -> Optional[str]:
    try:
        cp = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], check=False, capture_output=True, text=True, timeout=int(os.getenv("SBOM_GIT_CMD_TIMEOUT", "60")))
        return cp.stdout.strip() if cp.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return None


def _find_files(root: Path, filename: str) -> List[Path]:
    return [p for p in root.rglob(filename)]

# Python/PyPI: pyproject.toml (PEP 621 + Poetry), requirements*.txt

def _parse_python(repo: Path) -> List[dict]:
    results = []
    for pyproj in _find_files(repo, "pyproject.toml"):
        data = _read_toml(pyproj)
        if not data:
            continue
        for dep in (data.get("project", {}).get("dependencies") or []):
            results.append({
                "package_manager": "pypi",
                "dependency_name": str(dep).split()[0],
                "dependency_version_requirement": str(dep),
                "dependency_scope": "runtime",
                "manifest_path": str(pyproj.relative_to(repo)),
                "source_type": "manifest",
                "direct": True,
            })
        poetry = data.get("tool", {}).get("poetry", {})
        for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development")):
            for name, spec in (poetry.get(section) or {}).items():
                results.append({
                    "package_manager": "pypi",
                    "dependency_name": name,
                    "dependency_version_requirement": spec if isinstance(spec, str) else json.dumps(spec),
                    "dependency_scope": scope,
                    "manifest_path": str(pyproj.relative_to(repo)),
                    "source_type": "manifest",
                    "direct": True,
                })
    for req in list(repo.rglob("requirements*.txt")):
        content = _read_text(req) or ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-r") or line.startswith("--"):
                continue
            results.append({
                "package_manager": "pypi",
                "dependency_name": re.split(r"[<>=!~ ]", line, maxsplit=1)[0],
                "dependency_version_requirement": line,
                "dependency_scope": "runtime",
                "manifest_path": str(req.relative_to(repo)),
                "source_type": "manifest",
                "direct": True,
            })
    return results

# npm: package.json

def _parse_npm(repo: Path) -> List[dict]:
    results = []
    for pkg in _find_files(repo, "package.json"):
        data = _read_json(pkg)
        if not data:
            continue
        for field, scope in (("dependencies", "runtime"), ("devDependencies", "development"), ("peerDependencies", "peer")):
            for name, version in (data.get(field) or {}).items():
                results.append({
                    "package_manager": "npm",
                    "dependency_name": name,
                    "dependency_version_requirement": str(version),
                    "dependency_scope": scope,
                    "manifest_path": str(pkg.relative_to(repo)),
                    "source_type": "manifest",
                    "direct": True,
                })
    return results

# Rust/Cargo: Cargo.toml sections

def _parse_rust(repo: Path) -> List[dict]:
    results = []
    for cargo in _find_files(repo, "Cargo.toml"):
        data = _read_toml(cargo)
        if not data:
            continue
        for section, scope in (("dependencies", "runtime"), ("dev-dependencies", "development"), ("build-dependencies", "build")):
            for name, spec in (data.get(section) or {}).items():
                version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else json.dumps(spec))
                results.append({
                    "package_manager": "cargo",
                    "dependency_name": name,
                    "dependency_version_requirement": version or "",
                    "dependency_scope": scope,
                    "manifest_path": str(cargo.relative_to(repo)),
                    "source_type": "manifest",
                    "direct": True,
                })
    return results


# Git submodules: .gitmodules

def _parse_gitmodules(repo: Path) -> List[dict]:
    gm = repo / ".gitmodules"
    if not gm.exists():
        return []
    content = (gm.read_text(encoding="utf-8", errors="ignore") or "")
    entries: List[dict] = []
    current: dict = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[submodule"):
            if current:
                entries.append(current)
            current = {
                "package_manager": "gitmodules",
                "dependency_scope": "submodule",
                "source_type": "submodule",
                "direct": True,
            }
            m = re.search(r"\[submodule\s+\"([^\"]+)\"\]", line)
            if m:
                current["name"] = m.group(1)
        elif "=" in line:
            k, v = [x.strip() for x in line.split("=", 1)]
            current[k] = v
    if current:
        entries.append(current)

    results: List[dict] = []
    for entry in entries:
        name = entry.get("name") or entry.get("path") or ""
        url = entry.get("url") or ""
        results.append({
            "package_manager": "gitmodules",
            "dependency_name": name,
            "dependency_version_requirement": url,
            "dependency_scope": "submodule",
            "manifest_path": ".gitmodules",
            "source_type": "submodule",
            "direct": True,
        })
    return results


# Foundry: foundry.toml, lib/*

def _parse_foundry(repo: Path) -> List[dict]:
    results = []
    for fpath in _find_files(repo, "foundry.toml"):
        data = _read_toml(fpath) or {}
        profile = (data.get("profile") or {}).get("default") or {}
        libs = profile.get("libs") or []
        if isinstance(libs, str):
            libs = [libs]
        for lib in libs:
            results.append({
                "package_manager": "foundry",
                "dependency_name": lib,
                "dependency_version_requirement": "",
                "dependency_scope": "runtime",
                "manifest_path": str(fpath.relative_to(repo)),
                "source_type": "manifest",
                "direct": True,
            })
        remaps = profile.get("remappings") or []
        if isinstance(remaps, str):
            remaps = [remaps]
        for rem in remaps:
            name = str(rem).split("=")[0].strip()
            results.append({
                "package_manager": "foundry",
                "dependency_name": name,
                "dependency_version_requirement": str(rem),
                "dependency_scope": "runtime",
                "manifest_path": str(fpath.relative_to(repo)),
                "source_type": "manifest",
                "direct": True,
            })
    libdir = repo / "lib"
    if libdir.exists():
        for child in sorted(p for p in libdir.iterdir() if p.is_dir()):
            results.append({
                "package_manager": "foundry",
                "dependency_name": child.name,
                "dependency_version_requirement": "",
                "dependency_scope": "runtime",
                "manifest_path": "lib/",
                "source_type": "heuristic",
                "direct": True,
            })
    return results


def _collect_dependencies(repo_dir: Path) -> List[dict]:
    deps: List[dict] = []
    deps.extend(_parse_npm(repo_dir))
    deps.extend(_parse_python(repo_dir))
    deps.extend(_parse_rust(repo_dir))
    deps.extend(_parse_gitmodules(repo_dir))
    deps.extend(_parse_foundry(repo_dir))
    return deps


def _load_state(path: Path) -> Dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path: Path, data: Dict[str, dict]) -> None:
    _mkdir(path.parent)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def _load_previous_snapshot_for_repo(base: Path, artifact_namespace: str, artifact_name: str) -> Optional[pd.DataFrame]:
    repo_key = f"{artifact_namespace}__{artifact_name}"
    snapshots_dir = base / "snapshots" / repo_key
    if not snapshots_dir.exists():
        return None
    dates = sorted([p.name for p in snapshots_dir.iterdir() if p.is_dir()])
    if not dates:
        return None
    latest = snapshots_dir / dates[-1]
    dfs = [pd.read_parquet(f) for f in latest.glob("*.parquet")]
    return pd.concat(dfs, ignore_index=True) if dfs else None


def _write_snapshot(base: Path, artifact_namespace: str, artifact_name: str, df: pd.DataFrame) -> Path:
    repo_key = f"{artifact_namespace}__{artifact_name}"
    outdir = base / "snapshots" / repo_key / _snapshot_date()
    _mkdir(outdir)
    outfile = outdir / f"snapshot-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.parquet"
    df.to_parquet(outfile, index=False)
    return outfile


def _write_events(base: Path, df: pd.DataFrame) -> Path:
    outdir = base / "events" / _snapshot_date()
    _mkdir(outdir)
    outfile = outdir / f"events-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.parquet"
    df.to_parquet(outfile, index=False)
    return outfile


def _diff_events(prev_df: Optional[pd.DataFrame], curr_df: pd.DataFrame, artifact_namespace: str, artifact_name: str, time_collected: str) -> pd.DataFrame:
    if prev_df is None or prev_df.empty:
        out = curr_df.copy()
        out["change_type"] = "added"
        out["previous_version"] = None
        out["current_version"] = out["dependency_version_requirement"]
        out["artifact_namespace"] = artifact_namespace
        out["event_time_collected"] = time_collected
        out["artifact_name"] = artifact_name
        return out[["artifact_namespace", "artifact_name", "package_manager", "dependency_name", "change_type", "previous_version", "current_version", "event_time_collected"]]

    prev = prev_df[["package_manager", "dependency_name", "dependency_version_requirement"]].drop_duplicates()
    curr = curr_df[["package_manager", "dependency_name", "dependency_version_requirement"]].drop_duplicates()

    prev_keys = set((r.package_manager, r.dependency_name) for r in prev.itertuples(index=False))
    curr_keys = set((r.package_manager, r.dependency_name) for r in curr.itertuples(index=False))

    added_keys = curr_keys - prev_keys
    removed_keys = prev_keys - curr_keys
    common_keys = curr_keys & prev_keys

    events = []
    for pm, name in added_keys:
        cv = curr[(curr.package_manager == pm) & (curr.dependency_name == name)].iloc[0].dependency_version_requirement
        events.append((artifact_namespace, artifact_name, pm, name, "added", None, cv, time_collected))
    for pm, name in removed_keys:
        pv = prev[(prev.package_manager == pm) & (prev.dependency_name == name)].iloc[0].dependency_version_requirement
        events.append((artifact_namespace, artifact_name, pm, name, "removed", pv, None, time_collected))
    for pm, name in common_keys:
        pv = prev[(prev.package_manager == pm) & (prev.dependency_name == name)].iloc[0].dependency_version_requirement
        cv = curr[(curr.package_manager == pm) & (curr.dependency_name == name)].iloc[0].dependency_version_requirement
        if str(pv) != str(cv):
            events.append((artifact_namespace, artifact_name, pm, name, "updated", pv, cv, time_collected))

    return pd.DataFrame(events, columns=["artifact_namespace", "artifact_name", "package_manager", "dependency_name", "change_type", "previous_version", "current_version", "event_time_collected"])


def _process_repo(row: dict, output_dir: Path, token: Optional[str], incremental: bool, state: Dict[str, dict]) -> Tuple[str, Optional[str], Optional[Path], Optional[Path], Optional[str]]:
    owner = row["artifact_namespace"]
    repo_name = row["artifact_name"]
    repo_url = f"https://github.com/{owner}/{repo_name}.git"
    artifact_id = row.get("artifact_id")
    time_collected = _now_utc_iso()
    tmpdir = Path(tempfile.mkdtemp(prefix="sbom_"))
    local = tmpdir / "repo"
    try:
        if not _git_clone(repo_url, local, token):
            return f"{owner}/{repo_name}", "clone_failed", None, None, None
        head = _git_head_sha(local) or ""
        if incremental:
            prev_sha = (state.get(f"{owner}/{repo_name}") or {}).get("head_sha")
            if prev_sha and prev_sha == head:
                return f"{owner}/{repo_name}", "skipped_unchanged", None, None, head

        deps = _collect_dependencies(local)
        for d in deps:
            d.setdefault("dependency_scope", "runtime")
            d.setdefault("direct", True)
            d.setdefault("source_type", "manifest")

        df = pd.DataFrame(deps or [])
        for required_col in [
            "package_manager",
            "dependency_name",
            "dependency_version_requirement",
        ]:
            if required_col not in df.columns:
                df[required_col] = None
        df["artifact_id"] = artifact_id
        df["artifact_source"] = "GITHUB"
        df["artifact_namespace"] = owner
        df["artifact_name"] = repo_name
        df["artifact_url"] = repo_url
        df["repo_head_sha"] = head
        df["time_collected"] = time_collected

        prev_df = _load_previous_snapshot_for_repo(output_dir, owner, repo_name)
        events_df = _diff_events(prev_df, df, owner, repo_name, time_collected)
        events_path = _write_events(output_dir, events_df)
        snap_path = _write_snapshot(output_dir, owner, repo_name, df)

        state[f"{owner}/{repo_name}"] = {"head_sha": head, "last_collected": time_collected}
        return f"{owner}/{repo_name}", None, snap_path, events_path, head
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="SBOM fetcher for GitHub repos from OSO artifacts_v1 (direct dependencies only).")
    parser.add_argument("--output-dir", default="data/sbom", help="Base output directory for parquet results.")
    parser.add_argument("--max-workers", type=int, default=int(os.getenv("SBOM_MAX_WORKERS", "8")), help="Max concurrent clones/parsers.")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of repos to process (0 = all). For production, use 0 with --only.")
    parser.add_argument("--only", type=str, default="", help="Process only repos that start with this owner prefix (e.g., opensource-observer or opensource-observer/). Trailing slash is optional.")
    parser.add_argument("--incremental", action="store_true", help="Skip repos with unchanged HEAD SHA since last run.")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    _mkdir(output_dir)
    state_path = output_dir / "state.json"
    state = _load_state(state_path)

    # 0. OSO client
    client = Client(os.getenv("OSO_API_KEY"))

    # Normalize owner filter (accept with or without trailing slash)
    normalized_only = (args.only or "").rstrip("/")
    # Choose an effective LIMIT: if user provided a positive limit, use it. If owner filter is set and limit is 0, run unbounded for that owner; otherwise, cap to 100 to prevent huge queries.
    effective_limit = args.limit if (args.limit and args.limit > 0) else (0 if normalized_only else 100)

    # 1. Build SQL for discovery, pushing filters server-side for speed
    where_clauses = ["artifact_source = 'GITHUB'"]
    if normalized_only:
        owner_prefix = normalized_only.replace("'", "''")
        where_clauses.append(f"artifact_namespace LIKE '{owner_prefix}%'")
    sql_query = (
        "SELECT artifact_id, artifact_source, artifact_namespace, artifact_name\n"
        "FROM oso.artifacts_v1\n"
        f"WHERE {' AND '.join(where_clauses)}\n"
        + (f"LIMIT {int(effective_limit)}\n" if effective_limit and effective_limit > 0 else "")
    )

    # 2. Execute
    print("Querying artifacts...", flush=True)
    print(f"Filter owner='{normalized_only or '*'}', limit={effective_limit or 'ALL'}", flush=True)
    try:
        df = client.to_pandas(sql_query)
    except Exception as e:
        print(f"Query failed: {e}", flush=True)
        if not normalized_only and (not args.limit or args.limit == 0):
            print("Hint: add --only <owner> or --limit <N> to reduce result size.", flush=True)
        return 1

    # Optional filters (already pushed to SQL; keep as safety no-ops)
    if normalized_only:
        df = df[df["artifact_namespace"].astype(str).str.startswith(normalized_only)]
    if effective_limit and effective_limit > 0:
        df = df.head(effective_limit)

    print(f"Fetched {len(df)} repos. Processing with max_workers={args.max_workers}...", flush=True)

    rows = df.to_dict(orient="records")
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or None

    results = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        futs = [ex.submit(_process_repo, row, output_dir, token, args.incremental, state) for row in rows]
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            repo_full_name, err, snap_path, events_path, head = res
            print(f"{repo_full_name}: {'ok' if err is None else err}", flush=True)

    _save_state(state_path, state)

    # Emit run summary
    summary = []
    for repo_key, err, snap_path, events_path, head in results:
        summary.append({
            "artifact_namespace": repo_key.split("/")[0] if repo_key else "",
            "status": "ok" if err is None else err,
            "snapshot_path": str(snap_path) if snap_path else "",
            "events_path": str(events_path) if events_path else "",
            "repo_head_sha": head or "",
        })
    summary_df = pd.DataFrame(summary, columns=[
        "artifact_namespace",
        "status",
        "snapshot_path",
        "events_path",
        "repo_head_sha",
    ])
    _mkdir(output_dir / "run_summaries")
    outfile = output_dir / "run_summaries" / f"summary-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.parquet"
    summary_df.to_parquet(outfile, index=False)
    print(summary_df.to_string(index=False))
    print(f"Summary written to {outfile}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
