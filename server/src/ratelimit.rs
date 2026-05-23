use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct LoginRateLimiter {
    attempts: HashMap<String, Vec<Instant>>,
    max_attempts: usize,
    window_minutes: i64,
}

impl LoginRateLimiter {
    pub fn new(max_attempts: usize, window_minutes: i64) -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts,
            window_minutes,
        }
    }

    pub fn is_blocked(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_minutes as u64 * 60);

        if let Some(times) = self.attempts.get_mut(ip) {
            times.retain(|t| now.duration_since(*t) < window);
            times.len() >= self.max_attempts
        } else {
            false
        }
    }

    pub fn record_attempt(&mut self, ip: &str) {
        let now = Instant::now();
        let window = Duration::from_secs(self.window_minutes as u64 * 60);

        let times = self.attempts.entry(ip.to_string()).or_default();
        times.push(now);
        times.retain(|t| now.duration_since(*t) < window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_first_attempt() {
        let mut limiter = LoginRateLimiter::new(3, 1);
        assert!(!limiter.is_blocked("1.2.3.4"));
    }

    #[test]
    fn test_blocks_after_max_attempts() {
        let mut limiter = LoginRateLimiter::new(3, 1);
        assert!(!limiter.is_blocked("1.2.3.4"));
        limiter.record_attempt("1.2.3.4");
        limiter.record_attempt("1.2.3.4");
        limiter.record_attempt("1.2.3.4");
        assert!(limiter.is_blocked("1.2.3.4"));
    }

    #[test]
    fn test_different_ips_independent() {
        let mut limiter = LoginRateLimiter::new(2, 1);
        limiter.record_attempt("1.1.1.1");
        limiter.record_attempt("1.1.1.1");
        assert!(limiter.is_blocked("1.1.1.1"));
        assert!(!limiter.is_blocked("2.2.2.2"));
    }

    #[test]
    fn test_is_blocked_records_implicitly() {
        let mut limiter = LoginRateLimiter::new(1, 1);
        assert!(!limiter.is_blocked("1.1.1.1"));
        limiter.record_attempt("1.1.1.1");
        assert!(limiter.is_blocked("1.1.1.1"));
    }
}
