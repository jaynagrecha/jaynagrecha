#!/usr/bin/env python3
"""Generate the live Fusion Center SVG from GitHub profile telemetry.

Uses only the Python standard library. On transient API failure, the most recent
data/profile.json snapshot is retained so the workflow never destroys the profile.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / "data" / "profile.json"
TEMPLATE_FILE = ROOT / "light.template.svg"
OUTPUT_FILE = ROOT / "light.svg"

USERNAME = "jaynagrecha"
API = "https://api.github.com"
PROFILE_TOKEN = os.getenv("PROFILE_TOKEN")
TOKEN = PROFILE_TOKEN or os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")

INVESTIGATIONS = [
    ("Credential Access", "OS Credential Dumping", "T1003"),
    ("Initial Access", "Spearphishing Attachment", "T1566.001"),
    ("Persistence", "Scheduled Task/Job", "T1053"),
    ("Credential Access", "Kerberoasting", "T1558.003"),
    ("Defense Evasion", "Signed Binary Proxy Execution", "T1218"),
    ("Discovery", "Account Discovery", "T1087"),
    ("Execution", "PowerShell", "T1059.001"),
    ("Lateral Movement", "Remote Services", "T1021"),
]

def request_json(url: str, *, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "jaynagrecha-profile-generator",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"

    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=25) as response:
        return json.load(response)

def paginate(url: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    page = 1
    while True:
        separator = "&" if "?" in url else "?"
        batch = request_json(f"{url}{separator}per_page=100&page={page}")
        if not isinstance(batch, list):
            break
        items.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return items

def contribution_count() -> int:
    if not TOKEN:
        return 0
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=365)
    query = """
    query($login:String!, $from:DateTime!, $to:DateTime!) {
      user(login:$login) {
        contributionsCollection(from:$from, to:$to) {
          contributionCalendar { totalContributions }
        }
      }
    }
    """
    result = request_json(
        "https://api.github.com/graphql",
        method="POST",
        body={
            "query": query,
            "variables": {
                "login": USERNAME,
                "from": start.isoformat(),
                "to": now.isoformat(),
            },
        },
    )
    return int(
        result["data"]["user"]["contributionsCollection"]
              ["contributionCalendar"]["totalContributions"]
    )

def event_label(event: dict[str, Any]) -> str:
    created = event.get("created_at", "")
    try:
        time = dt.datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%H:%M")
    except Exception:
        time = "--:--"

    repo = str(event.get("repo", {}).get("name", "")).split("/")[-1] or "GitHub"
    kind = event.get("type", "Activity")
    payload = event.get("payload", {})

    if kind == "PushEvent":
        count = int(payload.get("size", 0)) or len(payload.get("commits", []))
        return f"{time} Pushed {count} commit{'s' if count != 1 else ''} to {repo}"
    if kind == "PullRequestEvent":
        action = payload.get("action", "updated")
        return f"{time} Pull request {action} in {repo}"
    if kind == "CreateEvent":
        ref_type = payload.get("ref_type", "resource")
        return f"{time} Created {ref_type} in {repo}"
    if kind == "IssuesEvent":
        action = payload.get("action", "updated")
        return f"{time} Issue {action} in {repo}"
    if kind == "IssueCommentEvent":
        return f"{time} Investigation note added in {repo}"
    if kind == "WatchEvent":
        return f"{time} Starred {repo}"
    return f"{time} {kind.removesuffix('Event')} activity in {repo}"

def trim(text: str, limit: int = 52) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"

def owned_repo_count() -> tuple[int, str, str]:
    """Return count, short label, and explanatory scope.

    GITHUB_TOKEN can only see public repositories outside this profile repo.
    A classic/fine-grained PAT stored as PROFILE_TOKEN can see all repositories
    the token owner has permission to read, including private repositories.
    """
    if PROFILE_TOKEN:
        query = """
        query($login:String!) {
          user(login:$login) {
            repositories(ownerAffiliations: OWNER) { totalCount }
          }
        }
        """
        result = request_json(
            "https://api.github.com/graphql",
            method="POST",
            body={"query": query, "variables": {"login": USERNAME}},
        )
        count = int(result["data"]["user"]["repositories"]["totalCount"])
        return count, "OWNED REPOS", "all visible to PROFILE_TOKEN"

    user = request_json(f"{API}/users/{USERNAME}")
    return int(user.get("public_repos", 0)), "PUBLIC REPOS", "public repositories only"


def collect_live_data() -> dict[str, Any]:
    user = request_json(f"{API}/users/{USERNAME}")
    repos = paginate(f"{API}/users/{USERNAME}/repos?type=owner&sort=pushed")
    events = request_json(f"{API}/users/{USERNAME}/events/public?per_page=50")

    non_forks = [r for r in repos if not r.get("fork")]
    code_repos = [r for r in non_forks if r.get("name") != USERNAME]
    total_stars = sum(int(r.get("stargazers_count", 0)) for r in non_forks)
    latest_repo = code_repos[0]["name"] if code_repos else (non_forks[0]["name"] if non_forks else "No public repositories")

    # Exclude the profile repo's own bot refreshes so the timeline shows real work.
    meaningful_events = [
        e for e in events
        if str(e.get("repo", {}).get("name", "")).lower() != f"{USERNAME}/{USERNAME}".lower()
    ]
    recent = [trim(event_label(e)) for e in meaningful_events[:3]]
    while len(recent) < 3:
        recent.append("Awaiting new public GitHub activity")

    contributions = contribution_count()
    if contributions == 0 and DATA_FILE.exists():
        contributions = int(json.loads(DATA_FILE.read_text()).get("contributions", 0))

    repo_count, repo_label, repo_scope = owned_repo_count()

    return {
        "username": USERNAME,
        "repositories": repo_count,
        "repo_label": repo_label,
        "repo_scope": repo_scope,
        "followers": int(user.get("followers", 0)),
        "contributions": contributions,
        "total_stars": total_stars,
        "latest_repo": latest_repo,
        "updated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "recent_events": recent,
    }


def load_snapshot() -> dict[str, Any]:
    if DATA_FILE.exists():
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    raise RuntimeError("No cached profile snapshot is available.")

def render(data: dict[str, Any]) -> None:
    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    index = dt.datetime.now(dt.timezone.utc).date().toordinal() % len(INVESTIGATIONS)
    tactic, technique, mitre_id = INVESTIGATIONS[index]

    events = list(data.get("recent_events", []))[:3]
    while len(events) < 3:
        events.append("Awaiting new public GitHub activity")

    values = {
        "REPOSITORIES": str(data.get("repositories", 0)),
        "REPO_LABEL": str(data.get("repo_label", "PUBLIC REPOS")),
        "REPO_SCOPE": str(data.get("repo_scope", "public repositories only")),
        "FOLLOWERS": str(data.get("followers", 0)),
        "CONTRIBUTIONS": str(data.get("contributions", 0)),
        "TOTAL_STARS": str(data.get("total_stars", 0)),
        "UPDATED_AT": str(data.get("updated_at", "UNKNOWN")),
        "LATEST_REPO": str(data.get("latest_repo", "UNKNOWN")),
        "INVESTIGATION_TACTIC": tactic,
        "INVESTIGATION_TECHNIQUE": technique,
        "INVESTIGATION_ID": mitre_id,
        "EVENT_1": events[0],
        "EVENT_2": events[1],
        "EVENT_3": events[2],
    }

    for key, value in values.items():
        template = template.replace("{{" + key + "}}", html.escape(value, quote=False))

    unresolved = [part for part in template.split("{{")[1:] if "}}" in part]
    if unresolved:
        raise RuntimeError("Unresolved SVG placeholders remain.")

    OUTPUT_FILE.write_text(template, encoding="utf-8")
    DATA_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="Render only from cached data.")
    args = parser.parse_args()

    if args.offline:
        data = load_snapshot()
    else:
        try:
            data = collect_live_data()
            print("Fetched fresh GitHub telemetry.")
        except Exception as exc:
            print(f"Warning: live fetch failed; retaining cached telemetry: {exc}", file=sys.stderr)
            data = load_snapshot()

    render(data)
    print(f"Generated {OUTPUT_FILE.relative_to(ROOT)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
