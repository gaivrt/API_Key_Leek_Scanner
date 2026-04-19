"""DEPRECATED — Anthropic-only API key leak scanner & responsible-disclosure helper.

Superseded by the Rust CLI in `src/` (see README.md). Kept for reference during
the v1 rewrite. Do not add features here.

Policy (do not relax without review):
  1. Never call the Anthropic API with a discovered key. Validating someone
     else's credential is unauthorized access.
  2. Never persist or print the full key. Only a short prefix + length.
  3. Notify Anthropic Security first (security@anthropic.com); they can
     revoke faster than the repo owner can rotate.
  4. When notifying repo owners, open ONE short issue per repo. No PRs, no
     forks. Default cap: 5 repos per run, 30s spacing, --confirm required.

Subcommands:
  scan          search GitHub for leaked keys (read-only, redacted output)
  draft-email   render a disclosure email to Anthropic Security
  notify-repos  open a single issue per affected repo (rate-limited)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass

KEY_RE = re.compile(r"sk-ant-(?:api|admin|sid)\d{2}-[A-Za-z0-9_\-]{80,120}")

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_ISSUES_URL_FMT = "https://api.github.com/repos/{owner}/{repo}/issues"

SEARCH_QUERIES = [
    '"sk-ant-api03" in:file',
    '"sk-ant-api03" filename:claude_desktop_config.json',
    '"sk-ant-api03" filename:.env',
]

USER_AGENT = "anthropic-leak-scanner/0.1 (responsible-disclosure)"


@dataclass(frozen=True)
class Finding:
    repo_full_name: str
    path: str
    html_url: str
    key_prefix: str
    key_length: int


def redact(key: str) -> str:
    head = key[:16] if len(key) >= 16 else key[: max(0, len(key) - 4)]
    return f"{head}...[redacted, len={len(key)}]"


def gh_request(
    url: str,
    token: str,
    *,
    method: str = "GET",
    body: dict | None = None,
) -> tuple[int, object]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8") or "null"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") or "null"
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def _to_raw_url(html_url: str) -> str:
    raw = html_url.replace("https://github.com/", "https://raw.githubusercontent.com/")
    return raw.replace("/blob/", "/", 1)


def fetch_blob(html_url: str, token: str) -> str:
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
    }
    req = urllib.request.Request(_to_raw_url(html_url), headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError:
        return ""


def search(token: str, query: str, max_pages: int = 1) -> list[dict]:
    items: list[dict] = []
    for page in range(1, max_pages + 1):
        params = urllib.parse.urlencode({"q": query, "per_page": 30, "page": page})
        status, data = gh_request(f"{GITHUB_SEARCH_URL}?{params}", token)
        if status != 200 or not isinstance(data, dict):
            break
        page_items = data.get("items", [])
        items.extend(page_items)
        if len(page_items) < 30:
            break
        time.sleep(2)
    return items


def scan(token: str, max_pages: int = 1) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []
    for q in SEARCH_QUERIES:
        for item in search(token, q, max_pages=max_pages):
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            key_id = (repo, path)
            if key_id in seen or not html_url:
                continue
            blob = fetch_blob(html_url, token)
            match = KEY_RE.search(blob)
            if not match:
                continue
            key = match.group(0)
            seen.add(key_id)
            findings.append(
                Finding(
                    repo_full_name=repo,
                    path=path,
                    html_url=html_url,
                    key_prefix=key[:16],
                    key_length=len(key),
                )
            )
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("error: GITHUB_TOKEN env var is required", file=sys.stderr)
        return 2
    findings = scan(token, max_pages=args.max_pages)
    payload = [asdict(f) for f in findings]
    text = json.dumps(payload, indent=2)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"wrote {len(payload)} findings -> {args.out}")
    else:
        print(text)
    return 0


def build_anthropic_email(findings: list[dict]) -> str:
    lines = [
        "To: security@anthropic.com",
        "Subject: Responsible disclosure: leaked Anthropic API keys on GitHub",
        "",
        "Hello Anthropic Security team,",
        "",
        f"The following {len(findings)} public GitHub locations appear to contain",
        "live `sk-ant-*` API keys. I have NOT validated any of them against the",
        "Anthropic API. Please review and revoke as appropriate.",
        "",
    ]
    for f in findings:
        lines.append(f"- {f['html_url']}")
        lines.append(f"  repo:   {f['repo_full_name']}")
        lines.append(f"  path:   {f['path']}")
        lines.append(f"  key:    {f['key_prefix']}... (len={f['key_length']})")
        lines.append("")
    lines.append("Reported via an automated scanner; happy to share more metadata.")
    return "\n".join(lines)


def cmd_draft_email(args: argparse.Namespace) -> int:
    with open(args.input) as fh:
        findings = json.load(fh)
    text = build_anthropic_email(findings)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"wrote draft -> {args.out}")
    else:
        print(text)
    return 0


ISSUE_TITLE = "Possible leaked Anthropic API key in this repository"
ISSUE_BODY_TEMPLATE = """\
Hi - an automated scan found what looks like a live Anthropic API key
(`sk-ant-*`) committed to this repository at:

  {path}

I have **not** tested the key against the Anthropic API. To stay safe:

1. **Rotate the key immediately** at https://console.anthropic.com/ - even if
   it has been removed from the latest commit, it remains valid in git
   history.
2. Purge the key from history (e.g. `git filter-repo`) and force-push.
3. Move secrets to environment variables or a secret manager; never commit
   `.env` or `claude_desktop_config.json` with live credentials.

Anthropic Security has been notified separately so they can revoke the key
on their end.

This issue was opened by an automated responsible-disclosure tool. Apologies
for the noise if it is a false positive - please close the issue.
"""


def build_issue_body(path: str) -> str:
    return ISSUE_BODY_TEMPLATE.format(path=path)


def cmd_notify_repos(args: argparse.Namespace) -> int:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("error: GITHUB_TOKEN env var is required", file=sys.stderr)
        return 2
    with open(args.input) as fh:
        findings = json.load(fh)

    by_repo: dict[str, dict] = {}
    for f in findings:
        by_repo.setdefault(f["repo_full_name"], f)

    targets = list(by_repo.items())[: args.max]
    print(f"will notify {len(targets)} repo(s) (cap={args.max}, spacing={args.spacing}s)")
    if not args.confirm:
        print("dry-run (pass --confirm to actually open issues):")
        for repo, f in targets:
            print(f"  - {repo}: {f['path']}")
        return 0

    opened = 0
    for i, (repo, f) in enumerate(targets):
        if i > 0:
            time.sleep(args.spacing)
        owner, name = repo.split("/", 1)
        url = GITHUB_ISSUES_URL_FMT.format(owner=owner, repo=name)
        body = {"title": ISSUE_TITLE, "body": build_issue_body(f["path"])}
        status, resp = gh_request(url, token, method="POST", body=body)
        if 200 <= status < 300 and isinstance(resp, dict):
            opened += 1
            print(f"  opened: {repo} -> {resp.get('html_url', '?')}")
        else:
            print(f"  FAILED ({status}): {repo}: {resp}")
    print(f"done; opened {opened}/{len(targets)} issues")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="search GitHub for leaked keys (read-only)")
    s.add_argument("--max-pages", type=int, default=1)
    s.add_argument("--out", help="write JSON findings here")
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("draft-email", help="render a disclosure email")
    d.add_argument("--input", required=True, help="findings JSON from `scan`")
    d.add_argument("--out", help="write draft here (default stdout)")
    d.set_defaults(func=cmd_draft_email)

    n = sub.add_parser("notify-repos", help="open ONE issue per affected repo")
    n.add_argument("--input", required=True)
    n.add_argument("--max", type=int, default=5, help="hard cap on repos per run")
    n.add_argument("--spacing", type=int, default=30, help="seconds between issues")
    n.add_argument("--confirm", action="store_true", help="actually create issues")
    n.set_defaults(func=cmd_notify_repos)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
