//! GitHub REST v3 client.
//!
//! Three operations:
//!   - `search`:     paginated code search (up to 1,000 items per query)
//!   - `fetch_blob`: read the raw file content for a search hit
//!   - `open_issue`: POST an issue to an arbitrary repo
//!
//! Transient 429 / 5xx are retried by `reqwest-retry` with exponential
//! backoff (1 → 60s, up to 5 retries). Per-bucket rate limiters live in
//! `ratelimit::Limits` and MUST be waited on before every request.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use serde::Deserialize;

use crate::ratelimit::Limits;

const USER_AGENT: &str = concat!(
    "leak-scanner/",
    env!("CARGO_PKG_VERSION"),
    " (responsible-disclosure)"
);
const SEARCH_URL: &str = "https://api.github.com/search/code";
const API_VERSION: &str = "2022-11-28";

#[derive(Debug, Deserialize)]
pub struct SearchResponse {
    #[serde(default)]
    pub total_count: u64,
    #[serde(default)]
    pub items: Vec<Hit>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Hit {
    pub path: String,
    pub html_url: String,
    pub repository: Repo,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Repo {
    pub full_name: String,
}

pub struct Client {
    http: ClientWithMiddleware,
    token: String,
    limits: Limits,
}

impl Client {
    pub fn new(token: String, limits: Limits) -> Result<Self> {
        let retry_policy = ExponentialBackoff::builder()
            .retry_bounds(Duration::from_secs(1), Duration::from_secs(60))
            .build_with_max_retries(5);
        let http = ClientBuilder::new(
            reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .timeout(Duration::from_secs(30))
                .build()
                .context("building reqwest client")?,
        )
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build();
        Ok(Self { http, token, limits })
    }

    /// Read `GITHUB_TOKEN` and construct a client with standard GitHub limits.
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("GITHUB_TOKEN")
            .context("GITHUB_TOKEN env var is required")?;
        Self::new(token, Limits::standard())
    }

    /// Code search, one page. Caller paginates and aggregates.
    pub async fn search(
        &self,
        query: &str,
        page: u32,
        per_page: u32,
    ) -> Result<SearchResponse> {
        self.limits.search.until_ready().await;
        let per_page = per_page.min(100).to_string();
        let page = page.to_string();
        let resp = self
            .http
            .get(SEARCH_URL)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .query(&[
                ("q", query),
                ("per_page", per_page.as_str()),
                ("page", page.as_str()),
            ])
            .send()
            .await
            .context("search send")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("search {status}: {body}"));
        }
        let parsed = resp.json::<SearchResponse>().await.context("search decode")?;
        Ok(parsed)
    }

    /// Fetch the raw file content for a search hit's `html_url`.
    /// Returns empty string for 404 (file deleted since indexing).
    pub async fn fetch_blob(&self, html_url: &str) -> Result<String> {
        self.limits.rest.until_ready().await;
        let raw = to_raw_url(html_url);
        let resp = self
            .http
            .get(&raw)
            .bearer_auth(&self.token)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .context("blob send")?;
        if resp.status().as_u16() == 404 {
            return Ok(String::new());
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("blob {status}: {body}"));
        }
        Ok(resp.text().await.context("blob text")?)
    }

    /// POST a new issue. Returns the created issue's `html_url`.
    pub async fn open_issue(
        &self,
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
    ) -> Result<String> {
        self.limits.rest.until_ready().await;
        let url = format!("https://api.github.com/repos/{owner}/{repo}/issues");
        let payload = serde_json::json!({ "title": title, "body": body });
        let body_bytes = serde_json::to_vec(&payload).context("issue payload encode")?;
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .context("issue send")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("open_issue {status}: {text}"));
        }
        let resp_body: serde_json::Value = resp.json().await.context("issue decode")?;
        Ok(resp_body
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string())
    }
}

fn to_raw_url(html_url: &str) -> String {
    html_url
        .replacen("https://github.com/", "https://raw.githubusercontent.com/", 1)
        .replacen("/blob/", "/", 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_url_conversion() {
        assert_eq!(
            to_raw_url("https://github.com/foo/bar/blob/main/src/file.py"),
            "https://raw.githubusercontent.com/foo/bar/main/src/file.py"
        );
        // Nested branch paths: only the first /blob/ should be rewritten.
        assert_eq!(
            to_raw_url("https://github.com/foo/bar/blob/feat/blob-handling/file.py"),
            "https://raw.githubusercontent.com/foo/bar/feat/blob-handling/file.py"
        );
    }

    #[test]
    fn user_agent_contains_version() {
        assert!(USER_AGENT.starts_with("leak-scanner/"));
        assert!(USER_AGENT.contains("responsible-disclosure"));
    }

    /// SearchResponse must tolerate absent `total_count` and `items`
    /// (e.g., when GitHub returns a partial error payload).
    #[test]
    fn search_response_tolerates_missing_fields() {
        let empty: SearchResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.total_count, 0);
        assert!(empty.items.is_empty());
    }
}
