use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    requests: Mutex<VecDeque<Instant>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(has_api_key: bool) -> Self {
        Self {
            requests: Mutex::new(VecDeque::new()),
            max_requests: if has_api_key { 50 } else { 5 },
            window: Duration::from_secs(30),
        }
    }

    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut reqs = self.requests.lock().unwrap();
                let now = Instant::now();

                while reqs.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
                    reqs.pop_front();
                }

                if reqs.len() < self.max_requests {
                    reqs.push_back(now);
                    return;
                }

                self.window - now.duration_since(*reqs.front().unwrap())
            };

            tokio::time::sleep(wait).await;
        }
    }
}
