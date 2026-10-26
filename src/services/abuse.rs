//! Conservative in-process throttling for the localhost-only prototype.
//! This is not distributed rate limiting and is not sufficient at an edge proxy.
use std::{collections::HashMap, time::Duration};

use sha2::{Digest, Sha256};
use tokio::{sync::Mutex, time::Instant};

const WINDOW: Duration = Duration::from_secs(60);

struct Bucket {
    start: Instant,
    count: u32,
}

#[derive(Default)]
pub struct AbuseGuard {
    buckets: Mutex<HashMap<[u8; 32], Bucket>>,
}

fn key(scope: &str, identity: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(scope.as_bytes());
    hasher.update([0]);
    hasher.update(identity.as_bytes());
    hasher.finalize().into()
}

fn count(buckets: &mut HashMap<[u8; 32], Bucket>, name: [u8; 32], now: Instant) -> u32 {
    let entry = buckets.entry(name).or_insert(Bucket { start: now, count: 0 });
    if now.duration_since(entry.start) >= WINDOW {
        entry.start = now;
        entry.count = 0;
    }
    entry.count
}

impl AbuseGuard {
    pub async fn allow(
        &self,
        scope: &str,
        identity: &str,
        global_limit: u32,
        identity_limit: u32,
    ) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        buckets.retain(|_, value| now.duration_since(value.start) < WINDOW);
        let global = key(scope, "");
        let specific = key(scope, identity);
        if count(&mut buckets, global, now) >= global_limit
            || count(&mut buckets, specific, now) >= identity_limit
        {
            return false;
        }
        buckets.get_mut(&global).expect("global bucket").count += 1;
        buckets.get_mut(&specific).expect("identity bucket").count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::AbuseGuard;

    #[tokio::test]
    async fn limits_account_and_global_budget() {
        let guard = AbuseGuard::default();
        assert!(guard.allow("login", "first@example.com", 3, 2).await);
        assert!(guard.allow("login", "first@example.com", 3, 2).await);
        assert!(!guard.allow("login", "first@example.com", 3, 2).await);
        assert!(guard.allow("login", "second@example.com", 3, 2).await);
        assert!(!guard.allow("login", "third@example.com", 3, 2).await);
        assert!(guard.allow("register", "third@example.com", 3, 2).await);
    }
}
