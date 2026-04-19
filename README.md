# API Key Leak Scanner

Responsible-disclosure helper: scans public GitHub code for leaked vendor API keys across many providers (LLM/AI, cloud, SaaS), and opens ONE issue per affected repo to ask the owner to rotate.

## Status

- **v0**: `leak_scanner.py` — Python single-file, Anthropic-only. Kept for reference, deprecated.
- **v1**: Rust CLI + GitHub Action, Tier A+B multi-vendor. **In progress.**

## Hard Policy (non-negotiable)

1. The scanner **never** calls a vendor's API to validate a discovered key. Validating someone else's credential is unauthorized access.
2. The scanner **never** persists or prints the full key — only `prefix[:16]` + `sha256[:8]` + `length`.
3. At most one issue is opened per `(repository, vendor)` pair, tracked in a dedicated `state` branch.
4. Opening issues requires `--confirm`; default is dry-run.

## Subcommands

```
leak-scanner scan         --out findings.json       # read-only scan
leak-scanner report       --input findings.json     # open GitHub issues (default dry-run)
leak-scanner draft-email  --input findings.json     # render per-vendor email drafts to artifacts
```

## GitHub Action

`.github/workflows/scan.yml` runs every 3 hours and commits de-dup state to a protected `state` branch in this repo.

Required secret:

- `LEAK_SCANNER_PAT` — classic PAT with `public_repo` scope. Used for both cross-org code search and cross-repo issue creation.

## Development

```
cargo build --release
cargo test
```

## See Also

- `SCHEMA.md` — wiki knowledge-base layout
- `wiki/overview.md` — project overview and risks
