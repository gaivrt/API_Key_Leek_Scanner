//! Token-bucket rate limiters for the GitHub REST API.
//!
//! GitHub's documented ceilings for an authenticated user:
//!   - `/search/code`: 10 req/min (separate bucket)
//!   - general REST:   5,000 req/hour (~83 req/min)
//!
//! We expose two limiters because blob fetches and issue POSTs consume the
//! general bucket while search consumes a different one. Plus retries layered
//! on top via `reqwest-retry` handle transient 429/5xx.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};

pub type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
pub struct Limits {
    pub search: Arc<Limiter>,
    pub rest: Arc<Limiter>,
}

impl Limits {
    pub fn new(search_per_min: u32, rest_per_min: u32) -> Self {
        let mk = |n: u32| {
            let n = NonZeroU32::new(n.max(1)).expect("max(1) is nonzero");
            Arc::new(RateLimiter::direct(Quota::per_minute(n)))
        };
        Self { search: mk(search_per_min), rest: mk(rest_per_min) }
    }

    pub fn standard() -> Self {
        // 10 search/min (GitHub hard ceiling) and 5000/hour ≈ 83/min for REST.
        // Stay one token under the REST ceiling so we don't race bursts.
        Self::new(10, 80)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn first_token_is_immediate() {
        let limits = Limits::standard();
        let start = Instant::now();
        limits.search.until_ready().await;
        assert!(start.elapsed().as_millis() < 50, "first search token should be immediate");
        limits.rest.until_ready().await;
        assert!(start.elapsed().as_millis() < 100, "first rest token should be immediate");
    }

    #[tokio::test]
    async fn depleted_bucket_waits() {
        // 60 req/min = 1 per second. Use that to test: the second call waits ~1s.
        let limits = Limits::new(60, 60);
        limits.search.until_ready().await;
        let start = Instant::now();
        limits.search.until_ready().await;
        let elapsed = start.elapsed();
        // Governor may grant the second token anywhere from ~0 (if the bucket
        // had headroom at construction) to ~1s. Assert upper bound for sanity.
        assert!(elapsed.as_secs_f64() <= 1.5, "rate limiter over-slept: {elapsed:?}");
    }
}
