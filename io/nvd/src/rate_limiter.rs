use log::debug;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    name: &'static str,
    requests: Mutex<VecDeque<Instant>>,
    max_requests: usize,
    window: Duration,
    waiters: AtomicUsize,
}

impl RateLimiter {
    pub fn nvd(has_api_key: bool) -> Self {
        Self {
            name: "nvd",
            requests: Mutex::new(VecDeque::new()),
            max_requests: if has_api_key { 50 } else { 5 },
            window: Duration::from_secs(30),
            waiters: AtomicUsize::new(0),
        }
    }

    pub fn github(has_token: bool) -> Self {
        Self {
            name: "github",
            requests: Mutex::new(VecDeque::new()),
            max_requests: if has_token { 5000 } else { 60 },
            window: Duration::from_secs(3600),
            waiters: AtomicUsize::new(0),
        }
    }

    pub fn osv() -> Self {
        Self {
            name: "osv",
            requests: Mutex::new(VecDeque::new()),
            max_requests: 25,
            window: Duration::from_secs(30),
            waiters: AtomicUsize::new(0),
        }
    }

    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut reqs = self.requests.lock().unwrap();
                let now = Instant::now();

                while reqs
                    .front()
                    .is_some_and(|t| now.duration_since(*t) >= self.window)
                {
                    reqs.pop_front();
                }

                if reqs.len() < self.max_requests {
                    let waiters = self.waiters.load(Ordering::Relaxed);
                    debug!(
                        "[{}] rate limiter: slot acquired ({}/{}, {} waiting)",
                        self.name,
                        reqs.len() + 1,
                        self.max_requests,
                        waiters,
                    );
                    reqs.push_back(now);
                    return;
                }

                self.window - now.duration_since(*reqs.front().unwrap())
            };

            self.waiters.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(wait).await;
            self.waiters.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
