//! State persistence across scheduled runs.
//!
//! Layout on disk (committed to the `state` branch by the GitHub Action):
//!
//! ```text
//! <state-root>/
//!   reported.json                   # dedup index, one entry per (repo, rule_id, sha)
//!   findings/YYYY-MM-DD.ndjson      # append-only audit log of raw findings
//! ```
//!
//! The dedup key is `(repo_full_name, rule_id)`: one issue per repo per vendor
//! rule, for life. A leak re-introduced after rotation will NOT re-open an
//! issue. This avoids harassment at the cost of missing re-leaks; acceptable
//! per the project policy.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::rules::Finding;

pub const REPORTED_FILE: &str = "reported.json";
pub const FINDINGS_DIR: &str = "findings";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportedEntry {
    pub repo_full_name: String,
    pub rule_id: String,
    pub key_sha256_prefix: String,
    pub first_reported_at: chrono::DateTime<chrono::Utc>,
    pub issue_url: Option<String>,
}

#[derive(Debug)]
pub struct State {
    root: PathBuf,
    entries: Vec<ReportedEntry>,
    index: HashSet<(String, String)>,
}

impl State {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let reported = root.join(REPORTED_FILE);
        let entries: Vec<ReportedEntry> = if reported.exists() {
            let text = std::fs::read_to_string(&reported)
                .with_context(|| format!("read {}", reported.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("parse {}", reported.display()))?
        } else {
            Vec::new()
        };
        let index = entries
            .iter()
            .map(|e| (e.repo_full_name.clone(), e.rule_id.clone()))
            .collect();
        Ok(Self { root, entries, index })
    }

    pub fn already_reported(&self, repo: &str, rule_id: &str) -> bool {
        self.index.contains(&(repo.to_string(), rule_id.to_string()))
    }

    pub fn record(&mut self, f: &Finding, issue_url: Option<String>) {
        self.index
            .insert((f.repo_full_name.clone(), f.rule_id.clone()));
        self.entries.push(ReportedEntry {
            repo_full_name: f.repo_full_name.clone(),
            rule_id: f.rule_id.clone(),
            key_sha256_prefix: f.key_sha256_prefix.clone(),
            first_reported_at: chrono::Utc::now(),
            issue_url,
        });
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root).ok();
        let path = self.root.join(REPORTED_FILE);
        let json = serde_json::to_string_pretty(&self.entries)
            .context("encode reported.json")?;
        std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Append `findings` to `findings/YYYY-MM-DD.ndjson` (UTC).
    pub fn append_ndjson(&self, findings: &[Finding]) -> Result<()> {
        if findings.is_empty() {
            return Ok(());
        }
        let dir = self.root.join(FINDINGS_DIR);
        std::fs::create_dir_all(&dir).ok();
        let today = chrono::Utc::now().format("%Y-%m-%d");
        let path = dir.join(format!("{today}.ndjson"));
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        for f in findings {
            let line = serde_json::to_string(f).context("encode finding")?;
            writeln!(file, "{line}").context("write ndjson")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Finding;

    fn mk_finding(repo: &str, rule_id: &str, sha: &str) -> Finding {
        Finding {
            repo_full_name: repo.to_string(),
            path: "a.env".to_string(),
            html_url: format!("https://github.com/{repo}/blob/main/a.env"),
            vendor: "Vendor".to_string(),
            rule_id: rule_id.to_string(),
            key_prefix: "xxxx".to_string(),
            key_sha256_prefix: sha.to_string(),
            key_length: 100,
            discovered_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn load_missing_root_is_empty() {
        let td = tempdir();
        let s = State::load(&td).unwrap();
        assert!(!s.already_reported("x/y", "r"));
    }

    #[test]
    fn round_trip_reported_json() {
        let td = tempdir();
        let mut s = State::load(&td).unwrap();
        s.record(
            &mk_finding("alice/demo", "anthropic-api03", "deadbeef"),
            Some("https://example/1".to_string()),
        );
        s.save().unwrap();

        let loaded = State::load(&td).unwrap();
        assert!(loaded.already_reported("alice/demo", "anthropic-api03"));
        assert!(!loaded.already_reported("alice/demo", "openai-t3blbkfj"));
        assert!(!loaded.already_reported("bob/repo", "anthropic-api03"));
    }

    #[test]
    fn append_ndjson_appends() {
        let td = tempdir();
        let s = State::load(&td).unwrap();
        s.append_ndjson(&[mk_finding("x/y", "r1", "aaaa")]).unwrap();
        s.append_ndjson(&[mk_finding("x/y", "r2", "bbbb")]).unwrap();
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = td.join(FINDINGS_DIR).join(format!("{today}.ndjson"));
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    // Minimal tempdir helper — we don't need the `tempfile` crate for this.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let i = N.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("leak-scanner-test-{pid}-{i}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
