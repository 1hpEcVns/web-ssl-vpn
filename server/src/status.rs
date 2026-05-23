use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDetail {
    pub username: String,
    pub source_ip: String,
    pub connected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub uptime: u64,
    pub connections: u64,
    pub requests_total: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub active_sessions: u64,
    pub session_details: Vec<SessionDetail>,
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
            session_details: Vec::new(),
            timestamp: Utc::now().timestamp(),
        }
    }
}

#[derive(Debug, Clone)]
struct SessionInfo {
    username: String,
    source_ip: String,
    connected_at: DateTime<Utc>,
}

pub struct StatusCollector {
    start_time: std::time::Instant,
    requests_count: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    sessions: HashMap<String, SessionInfo>,
}

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

    pub fn record_request(&mut self, _session_id: &str, sent: u64, recv: u64) {
        self.requests_count += 1;
        self.bytes_sent = self.bytes_sent.wrapping_add(sent);
        self.bytes_recv = self.bytes_recv.wrapping_add(recv);
    }

    pub fn add_session_with_info(&mut self, session_id: String, username: &str, source_ip: &str) {
        self.sessions.insert(session_id, SessionInfo {
            username: username.to_string(),
            source_ip: source_ip.to_string(),
            connected_at: Utc::now(),
        });
    }

    pub fn remove_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn get_stats(&self) -> SystemStats {
        let session_details = self.sessions.iter().map(|(_id, info)| {
            SessionDetail {
                username: info.username.clone(),
                source_ip: info.source_ip.clone(),
                connected_at: info.connected_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            }
        }).collect();

        SystemStats {
            uptime: self.start_time.elapsed().as_secs(),
            connections: self.sessions.len() as u64,
            requests_total: self.requests_count,
            bytes_sent: self.bytes_sent,
            bytes_recv: self.bytes_recv,
            active_sessions: self.sessions.len() as u64,
            session_details,
            timestamp: Utc::now().timestamp(),
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
        c.add_session_with_info("session-1".into(), "admin", "1.2.3.4");
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 1);
        assert_eq!(stats.connections, 1);
        assert_eq!(stats.session_details.len(), 1);
        assert_eq!(stats.session_details[0].username, "admin");

        c.add_session_with_info("session-2".into(), "user1", "5.6.7.8");
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 2);

        c.remove_session("session-1");
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 1);

        c.remove_session("session-2");
        let stats = c.get_stats();
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.session_details.len(), 0);
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
