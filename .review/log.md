# Review Pattern Memory

Short-lived reviewers dump durable `REVISE`-grade patterns here. Every reviewer
MUST Read this file before starting.

## [2026-04-19] leak-scanner/c2 | REVISE
Pattern: redaction prefix must scale with key length (`min(8, key.len()/4)` or vendor-configured), never a fixed count. Test must assert hidden-char count per rule at `min_len`, not just substring non-containment.
Context: src/redact.rs:20 hardcoded `prefix_len = 16` leaked 75% of AWS key entropy.

## [2026-04-19] leak-scanner/c2 | REVISE
Pattern: cross-doc coverage claims (overview.md promises N vendors, rules.rs ships M < N) must be reconciled in the same checkpoint as the code change. Silent under-delivery is blocking.
Context: overview.md listed 14 Tier A vendors; rules.rs shipped 8 with 6 undocumented as deferred.

## [2026-04-19] leak-scanner/c2 | PASS (round 2)
Pattern: round-2 resolution confirmed both patterns. Remaining reviewer nits are always cosmetic-only once the two above are green.
Context: redact.rs:28 + redaction_hides_enough_entropy_per_rule + overview.md Tier A split.

## [2026-04-19] leak-scanner/c3 | PASS
Pattern: none.
Context: github.rs + ratelimit.rs. Confirmed — governor::Quota::per_minute is GCRA (not a fixed-window burst), reqwest-retry 0.6 DefaultRetryableStrategy DOES classify 429 as Retryable::Transient. Good to cite in future checkpoints.

## [2026-04-19] leak-scanner/c4 | PASS
Pattern: none.
Context: scan.rs. Confirmed — RegexSet.matches(blob) is membership (which rules match), rule.regex.find_iter(blob) enumerates occurrences; use BOTH (prune + extract). min_len guard after regex is defensive (cheap insurance against future rule-quantifier changes). buffer_unordered(128) has no starvation risk for collect-then-flatten.

## [2026-04-19] leak-scanner/c5 | REVISE
Pattern: pre-loop state filter is necessary but not sufficient — idempotency requires pre-dedup of the batch OR in-loop re-check, because one input batch can contain duplicate dedup-keys. "Filter once, iterate" leaks duplicates within a single invocation.
Context: issue.rs run_report — missing dedup_batch between state filter and take(max) allowed two findings with same (repo, rule_id) to both trigger open_issue.

## [2026-04-19] leak-scanner/c5 | PASS (round 2)
Pattern: dedup-batch tests must assert first-occurrence winner (not just size), so future edits that keep "some survivor" rather than "the first one" are caught.
Context: issue.rs dedup_batch + dedup_batch_collapses_same_repo_and_rule test.
