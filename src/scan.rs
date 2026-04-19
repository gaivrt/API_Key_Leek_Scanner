//! Main scan pipeline.
//!
//! Three stages:
//!   1. **Search**: for each rule, issue paginated GitHub code-search
//!      queries. Rate-limited at 10 req/min (governor). Collect hits
//!      deduped by `html_url` — one file may match multiple rules and we
//!      only want to fetch it once.
//!   2. **Fetch + match**: for each unique hit, download the raw blob and
//!      run `RULE_SET` across it. `buffer_unordered(128)` for concurrency.
//!   3. **Emit**: dedup findings by `(repo, rule_id, sha256_prefix)` and
//!      write JSON to disk. Policy: the full key NEVER appears in the output.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};

use crate::github::{self, Hit};
use crate::redact;
use crate::rules::{self, Finding, RULES, RULE_SET};

const FETCH_CONCURRENCY: usize = 128;
const SEARCH_PER_PAGE: u32 = 30;

pub async fn run(out_path: &str, max_pages: u32) -> Result<()> {
    let client = Arc::new(github::Client::from_env()?);

    tracing::info!(
        rules = RULES.len(),
        max_pages,
        "search stage begin"
    );
    let hits = aggregate_hits(&client, max_pages).await?;
    tracing::info!(unique_hits = hits.len(), "search stage complete");

    tracing::info!(concurrency = FETCH_CONCURRENCY, "fetch+match stage begin");
    let mut findings = scan_hits(Arc::clone(&client), hits).await;
    tracing::info!(raw_findings = findings.len(), "scan stage complete");

    dedup_findings(&mut findings);
    tracing::info!(deduped = findings.len(), "dedup complete");

    let json = serde_json::to_string_pretty(&findings).context("encode findings")?;
    std::fs::write(out_path, json).with_context(|| format!("write {out_path}"))?;
    tracing::info!(out = out_path, "findings written");
    Ok(())
}

/// Walk every rule × page, accumulate unique `Hit`s keyed by `html_url`.
async fn aggregate_hits(client: &github::Client, max_pages: u32) -> Result<Vec<Hit>> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut hits: Vec<Hit> = Vec::new();
    for rule in RULES.iter() {
        for page in 1..=max_pages {
            let resp = match client.search(rule.search_query, page, SEARCH_PER_PAGE).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(rule = rule.id, page, err = %e, "search failed");
                    break;
                }
            };
            let n = resp.items.len();
            for item in resp.items {
                if seen.insert(item.html_url.clone()) {
                    hits.push(item);
                }
            }
            if n < SEARCH_PER_PAGE as usize {
                break;
            }
        }
    }
    Ok(hits)
}

/// Fan out blob fetches + regex matching with bounded concurrency.
async fn scan_hits(client: Arc<github::Client>, hits: Vec<Hit>) -> Vec<Finding> {
    let results: Vec<Vec<Finding>> = stream::iter(hits)
        .map(|hit| {
            let client = Arc::clone(&client);
            async move {
                match client.fetch_blob(&hit.html_url).await {
                    Ok(blob) if !blob.is_empty() => match_blob(&hit, &blob),
                    Ok(_) => Vec::new(),
                    Err(e) => {
                        tracing::warn!(url = %hit.html_url, err = %e, "fetch failed");
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(FETCH_CONCURRENCY)
        .collect()
        .await;
    results.into_iter().flatten().collect()
}

/// Run the full rule set against a blob; return one `Finding` per distinct key.
pub(crate) fn match_blob(hit: &Hit, blob: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen_keys: HashSet<String> = HashSet::new();
    for idx in RULE_SET.matches(blob) {
        let rule = &RULES[idx];
        for m in rule.regex.find_iter(blob) {
            let key = m.as_str();
            if key.len() < rule.min_len {
                continue;
            }
            // Dedup per blob by sha256 prefix to avoid emitting the same key
            // twice if two rules' regexes are subsumed (unlikely given our
            // prefixes, but cheap insurance).
            let red = redact::redact(key);
            let dedup_key = format!("{}:{}", rule.id, red.sha256_prefix);
            if !seen_keys.insert(dedup_key) {
                continue;
            }
            out.push(Finding {
                repo_full_name: hit.repository.full_name.clone(),
                path: hit.path.clone(),
                html_url: hit.html_url.clone(),
                vendor: rule.vendor.to_string(),
                rule_id: rule.id.to_string(),
                key_prefix: red.prefix,
                key_sha256_prefix: red.sha256_prefix,
                key_length: red.length,
                discovered_at: chrono::Utc::now(),
            });
        }
    }
    out
}

/// Global dedup across all hits by `(repo, rule_id, sha256_prefix)`.
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    findings.retain(|f| {
        seen.insert((
            f.repo_full_name.clone(),
            f.rule_id.clone(),
            f.key_sha256_prefix.clone(),
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::{Hit, Repo};

    fn hit(repo: &str, path: &str) -> Hit {
        Hit {
            path: path.to_string(),
            html_url: format!("https://github.com/{repo}/blob/main/{path}"),
            repository: Repo { full_name: repo.to_string() },
        }
    }

    /// Synthetic Anthropic-shaped key. Built via `format!` so the contiguous
    /// secret-format literal does not appear in the source (otherwise GitHub
    /// secret-scanning push protection rejects this file).
    fn fake_anthropic() -> String {
        format!("sk-ant-{}-{}", "api03", "A".repeat(85))
    }

    fn fake_openai() -> String {
        let alnum40 = "abcdefghijklmnopqrstuvwxyz1234567890ABCD";
        format!("sk-{}-{}{}{}", "proj", alnum40, "T3BlbkFJ", alnum40)
    }

    /// A blob containing a well-formed Anthropic key must produce exactly one
    /// Finding tagged with the `anthropic-api03` rule. The full key must not
    /// appear anywhere in the serialized Finding.
    #[test]
    fn match_blob_emits_redacted_finding() {
        let fake_key = fake_anthropic();
        let blob = format!("# config\nANTHROPIC_KEY = \"{fake_key}\"\n");
        let h = hit("octocat/demo", ".env");
        let findings = match_blob(&h, &blob);
        assert_eq!(findings.len(), 1, "expected one Anthropic finding");
        let f = &findings[0];
        assert_eq!(f.rule_id, "anthropic-api03");
        assert_eq!(f.repo_full_name, "octocat/demo");
        // Policy: full key never appears.
        let json = serde_json::to_string(f).unwrap();
        assert!(!json.contains(&fake_key), "redacted JSON leaked full key");
        assert!(f.key_length >= 93);
    }

    /// A blob with two different vendors' keys must produce two Findings.
    #[test]
    fn match_blob_handles_multiple_vendors() {
        let anthropic = fake_anthropic();
        let openai = fake_openai();
        let blob = format!("A={anthropic}\nB={openai}\n");
        let findings = match_blob(&hit("x/y", "secrets.txt"), &blob);
        assert_eq!(findings.len(), 2);
        let ids: HashSet<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains("anthropic-api03"));
        assert!(ids.contains("openai-t3blbkfj"));
    }

    /// Repeated identical keys within one blob dedup to a single Finding.
    #[test]
    fn match_blob_dedups_repeated_keys() {
        let k = fake_anthropic();
        let blob = format!("{k} {k} {k}");
        let findings = match_blob(&hit("x/y", "a"), &blob);
        assert_eq!(findings.len(), 1);
    }

    /// Across multiple hits in the same repo, identical (rule, sha256) pairs
    /// are also deduped (e.g., same leaked key referenced in two files).
    #[test]
    fn dedup_findings_cross_hit() {
        let key = fake_anthropic();
        let mut findings: Vec<Finding> = [".env", ".env.local"]
            .iter()
            .flat_map(|p| match_blob(&hit("x/y", p), &key))
            .collect();
        assert_eq!(findings.len(), 2, "before dedup");
        dedup_findings(&mut findings);
        assert_eq!(findings.len(), 1, "after dedup");
    }
}
