//! Issue template + report / draft-email commands.
//!
//! `run_report` is the GitHub-Action-facing entry point: load findings JSON,
//! filter through `State`, and open ONE issue per (repo, rule_id) with rate
//! limiting (30s default spacing, 5/run cap, `--confirm` required).
//!
//! `run_draft_email` produces per-vendor text drafts for human review; it
//! does NOT send mail.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::github;
use crate::rules::{self, Finding};
use crate::state::State;

pub const ISSUE_TITLE: &str = "Possible leaked API key in this repository";

pub fn build_issue_body(f: &Finding) -> String {
    format!(
        "Hi — an automated scan found what looks like a live **{vendor}** API \
         key committed to this repository at:\n\n\
         - path: `{path}`\n\
         - file: {url}\n\
         - vendor rule: `{rule_id}`\n\
         - key fingerprint: `{prefix}...` (sha256[:8] = `{sha}`, length = {len})\n\n\
         The scanner did **not** validate the key against the vendor's API — \
         validating someone else's credential would be unauthorized access. \
         Please treat the key as compromised regardless:\n\n\
         1. **Rotate the key immediately** in the vendor's console. Even if you \
            have already removed it from the latest commit, it remains valid in \
            git history.\n\
         2. Purge the key from history (e.g. `git filter-repo`) and force-push.\n\
         3. Move secrets to environment variables or a secret manager; never \
            commit `.env` or equivalent config with live credentials.\n\n\
         The vendor's security team has been notified separately where a \
         contact is known.\n\n\
         This issue was opened by an automated responsible-disclosure tool. \
         Apologies for the noise if it is a false positive — please close the \
         issue and I will not re-open it for this `(repo, rule)` pair.",
        vendor = f.vendor,
        path = f.path,
        url = f.html_url,
        rule_id = f.rule_id,
        prefix = f.key_prefix,
        sha = f.key_sha256_prefix,
        len = f.key_length,
    )
}

pub async fn run_report(
    input: &str,
    max: usize,
    spacing: u64,
    confirm: bool,
) -> Result<()> {
    let findings = load_findings(input)?;
    let state_dir = std::env::var("LEAK_SCANNER_STATE_DIR").unwrap_or_else(|_| ".".into());
    let mut state = State::load(&state_dir)?;

    let fresh: Vec<Finding> = findings
        .into_iter()
        .filter(|f| !state.already_reported(&f.repo_full_name, &f.rule_id))
        .collect();
    tracing::info!(fresh = fresh.len(), "filtered against state");

    // Within-run dedup: one issue per (repo, rule_id) even if the input
    // contains multiple findings with the same pair (two keys of the same
    // vendor in the same repo, or the same key in two files).
    let fresh = dedup_batch(fresh);
    tracing::info!(batched = fresh.len(), "dedup within-run");

    let targets: Vec<&Finding> = fresh.iter().take(max).collect();
    tracing::info!(
        targets = targets.len(),
        cap = max,
        spacing_s = spacing,
        "report plan"
    );

    if !confirm {
        tracing::info!("dry-run (pass --confirm to actually open issues)");
        for f in &targets {
            println!(
                "  - {} [{}]: {} (sha={})",
                f.repo_full_name, f.rule_id, f.path, f.key_sha256_prefix
            );
        }
        return Ok(());
    }

    let client = github::Client::from_env()?;
    let mut opened = 0usize;
    for (i, f) in targets.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(spacing)).await;
        }
        let (owner, repo) = f
            .repo_full_name
            .split_once('/')
            .ok_or_else(|| anyhow!("invalid repo_full_name: {}", f.repo_full_name))?;
        match client
            .open_issue(owner, repo, ISSUE_TITLE, &build_issue_body(f))
            .await
        {
            Ok(url) => {
                tracing::info!(
                    repo = %f.repo_full_name,
                    rule = %f.rule_id,
                    url = %url,
                    "issue opened"
                );
                state.record(f, Some(url));
                opened += 1;
            }
            Err(e) => {
                tracing::warn!(
                    repo = %f.repo_full_name,
                    rule = %f.rule_id,
                    err = %e,
                    "open_issue failed"
                );
            }
        }
    }
    state.save()?;
    state.append_ndjson(&fresh)?;
    tracing::info!(opened, total = targets.len(), "report complete");
    Ok(())
}

pub fn run_draft_email(input: &str, out_dir: &str) -> Result<()> {
    let findings = load_findings(input)?;
    std::fs::create_dir_all(out_dir).ok();

    // Group findings by (vendor, disclosure_email). Vendors without a known
    // contact are skipped — the repo issue is the only disclosure channel.
    let mut by_vendor: BTreeMap<(&'static str, &'static str), Vec<&Finding>> = BTreeMap::new();
    for f in &findings {
        if let Some(rule) = rules::by_id(&f.rule_id) {
            if let Some(email) = rule.disclosure_email {
                by_vendor.entry((rule.vendor, email)).or_default().push(f);
            }
        }
    }

    if by_vendor.is_empty() {
        tracing::info!("no findings had a known disclosure email; no drafts written");
        return Ok(());
    }

    for ((vendor, email), group) in &by_vendor {
        let body = render_email(email, vendor, group);
        let fname = format!(
            "{}.txt",
            email.replace('@', "_at_").replace('.', "_")
        );
        let path = PathBuf::from(out_dir).join(fname);
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        tracing::info!(
            path = %path.display(),
            n = group.len(),
            vendor,
            "draft email written"
        );
    }
    Ok(())
}

fn load_findings(input: &str) -> Result<Vec<Finding>> {
    let text = std::fs::read_to_string(input).with_context(|| format!("read {input}"))?;
    serde_json::from_str(&text).with_context(|| format!("parse {input}"))
}

/// Collapse a batch of `Finding`s so at most one remains per `(repo, rule_id)`.
/// Keeps the first occurrence in iteration order.
fn dedup_batch(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    findings
        .into_iter()
        .filter(|f| seen.insert((f.repo_full_name.clone(), f.rule_id.clone())))
        .collect()
}

fn render_email(email: &str, vendor: &str, group: &[&Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!("To: {email}\n"));
    out.push_str(&format!(
        "Subject: Responsible disclosure: leaked {vendor} API keys on GitHub\n\n"
    ));
    out.push_str(&format!("Hello {vendor} Security team,\n\n"));
    out.push_str(&format!(
        "The following {} public GitHub location(s) appear to contain live \
         {vendor} keys. I have NOT validated any of them against the vendor \
         API. Please review and revoke as appropriate.\n\n",
        group.len()
    ));
    for f in group {
        out.push_str(&format!("- {}\n", f.html_url));
        out.push_str(&format!("  repo:  {}\n", f.repo_full_name));
        out.push_str(&format!("  path:  {}\n", f.path));
        out.push_str(&format!("  rule:  {}\n", f.rule_id));
        out.push_str(&format!(
            "  key:   {}... (sha256[:8]={}, len={})\n",
            f.key_prefix, f.key_sha256_prefix, f.key_length
        ));
        out.push('\n');
    }
    out.push_str("Reported via an automated scanner; happy to share more metadata.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_finding() -> Finding {
        Finding {
            repo_full_name: "alice/demo".to_string(),
            path: ".env".to_string(),
            html_url: "https://github.com/alice/demo/blob/main/.env".to_string(),
            vendor: "Anthropic".to_string(),
            rule_id: "anthropic-api03".to_string(),
            key_prefix: "sk-ant-a".to_string(),
            key_sha256_prefix: "deadbeef".to_string(),
            key_length: 100,
            discovered_at: chrono::Utc::now(),
        }
    }

    /// Issue body must include identifying metadata and NEVER a full key.
    #[test]
    fn issue_body_redacted() {
        let body = build_issue_body(&mk_finding());
        assert!(body.contains("Anthropic"));
        assert!(body.contains("anthropic-api03"));
        assert!(body.contains("sk-ant-a..."));
        assert!(body.contains("deadbeef"));
        assert!(body.contains("Rotate"));
        // Sanity: no magic full-key substring.
        assert!(!body.contains("sk-ant-api03-AAAAAAAA"));
    }

    /// Within-run dedup: two findings with the same (repo, rule_id) but
    /// different sha256_prefix collapse to one. Different rule_id keeps both.
    #[test]
    fn dedup_batch_collapses_same_repo_and_rule() {
        let mut a = mk_finding();
        a.key_sha256_prefix = "aaaaaaaa".to_string();
        let mut b = mk_finding();
        b.path = ".env.local".to_string();
        b.key_sha256_prefix = "bbbbbbbb".to_string();
        let mut c = mk_finding();
        c.rule_id = "openai-t3blbkfj".to_string();
        c.vendor = "OpenAI".to_string();
        c.key_sha256_prefix = "cccccccc".to_string();

        let out = dedup_batch(vec![a, b, c]);
        assert_eq!(out.len(), 2, "same (repo,rule) must collapse; different rule stays");
        assert_eq!(out[0].key_sha256_prefix, "aaaaaaaa"); // first kept
        assert_eq!(out[1].rule_id, "openai-t3blbkfj");
    }

    #[test]
    fn email_render_has_address_and_redaction() {
        let f = mk_finding();
        let group = vec![&f];
        let txt = render_email("security@anthropic.com", "Anthropic", &group);
        assert!(txt.starts_with("To: security@anthropic.com\n"));
        assert!(txt.contains("Subject:"));
        assert!(txt.contains("sk-ant-a..."));
        assert!(txt.contains("sha256[:8]=deadbeef"));
        assert!(!txt.contains("sk-ant-api03-AAAAAAAA"));
    }
}
