use std::time::{Duration, Instant};
use std::sync::Mutex;
use std::collections::VecDeque;

pub struct RateLimiter {
    requests: Mutex<VecDeque<Instant>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(api_key: bool) -> Self {
        Self {
            requests: Mutex::new(VecDeque::new()),
            max_requests: if api_key { 50 } else { 5 },
            window: Duration::from_secs(30),
        }
    }

    pub fn acquire(&self) {
        loop {
            let mut reqs = self.requests.lock().unwrap();
            let now = Instant::now();

            // Drop timestamps outside the window
            while reqs.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
                reqs.pop_front();
            }

            if reqs.len() < self.max_requests {
                reqs.push_back(now);
                return;
            }

            // Calculate how long until the oldest request expires
            let wait = self.window - now.duration_since(*reqs.front().unwrap());
            drop(reqs);
            std::thread::sleep(wait);
        }
    }
}