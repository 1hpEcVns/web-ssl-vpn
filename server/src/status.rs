use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub uptime: u64,
    pub connections: u64,
    pub requests_total: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub active_sessions: u64,
    pub timestamp: i64,
}

impl Default for SystemStats {
    fn default() -> Self {
        Self {
            uptime: 0,
            connections: 0,
            requests_total: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            active_sessions: 0,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

pub struct StatusCollector {
    start_time: std::time::Instant,
    requests_count: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    sessions: HashMap<String, SessionInfo>,
}

#[derive(Debug, Clone)]
struct SessionInfo;

impl StatusCollector {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            requests_count: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            sessions: HashMap::new(),
        }
    }

    pub fn record_request(&mut self, _session_id: &str, _sent: u64, _recv: u64) {
        self.requests_count += 1;
    }

    #[allow(dead_code)]
    pub fn add_session(&mut self, session_id: String) {
        self.sessions.insert(session_id, SessionInfo);
    }

    #[allow(dead_code)]
    pub fn remove_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn get_stats(&self) -> SystemStats {
        SystemStats {
            uptime: self.start_time.elapsed().as_secs(),
            connections: self.sessions.len() as u64,
            requests_total: self.requests_count,
            bytes_sent: self.bytes_sent,
            bytes_recv: self.bytes_recv,
            active_sessions: self.sessions.len() as u64,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_collector_starts_with_zeros() {
        let c = StatusCollector::new();
        let stats = c.get_stats();
        assert_eq!(stats.uptime, 0);
        assert_eq!(stats.connections, 0);
        assert_eq!(stats.requests_total, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_recv, 0);
        assert_eq!(stats.active_sessions, 0);
    }

    #[test]
    fn test_record_request_increments_counter() {
        let mut c = StatusCollector::new();
        c.record_request("s1", 0, 0);
        c.record_request("s2", 0, 0);
        let stats = c.get_stats();
        assert_eq!(stats.requests_total, 2);
    }

    #[test]
    fn test_add_and_remove_session() {
        let mut c = StatusCollector::new();
        c.add_session("session-1".into());
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.connections, 1);

        c.add_session("session-2".into());
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 2);

        c.remove_session("session-1");
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 1);

        c.remove_session("session-2");
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 0);
    }

    #[test]
    fn test_uptime_increases() {
        let c = StatusCollector::new();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let stats = c.get_stats();
        assert!(stats.uptime >= 1, "uptime was {}", stats.uptime);
    }

    #[test]
    fn test_system_stats_default() {
        let stats = SystemStats::default();
        assert_eq!(stats.uptime, 0);
        assert_eq!(stats.connections, 0);
        assert_eq!(stats.requests_total, 0);
    }
}
