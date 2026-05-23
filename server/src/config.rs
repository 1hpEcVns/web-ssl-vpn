use std::path::PathBuf;
use std::env;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub http_bind: String,
    pub https_bind: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub ca_bundle: PathBuf,
    pub db_path: PathBuf,
    pub static_dir: PathBuf,
    pub session_hours: i64,
    pub log_level: String,
    pub demo: bool,
    pub ebpf_iface: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_bind: "0.0.0.0:8080".into(),
            https_bind: "0.0.0.0:8443".into(),
            tls_cert: PathBuf::from("certs/server.crt"),
            tls_key: PathBuf::from("certs/server.key"),
            ca_bundle: PathBuf::from("certs/ca-bundle.crt"),
            db_path: PathBuf::from("vpn.db"),
            static_dir: PathBuf::from("web/dist"),
            session_hours: 8,
            log_level: "info".into(),
            demo: false,
            ebpf_iface: "lo".into(),
        }
    }
}

impl ServerConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        if let Ok(v) = env::var("VPN_HTTP_BIND") { cfg.http_bind = v; }
        if let Ok(v) = env::var("VPN_HTTPS_BIND") { cfg.https_bind = v; }
        if let Ok(v) = env::var("VPN_TLS_CERT") { cfg.tls_cert = PathBuf::from(v); }
        if let Ok(v) = env::var("VPN_TLS_KEY") { cfg.tls_key = PathBuf::from(v); }
        if let Ok(v) = env::var("VPN_CA_BUNDLE") { cfg.ca_bundle = PathBuf::from(v); }
        if let Ok(v) = env::var("VPN_DB_PATH") { cfg.db_path = PathBuf::from(v); }
        if let Ok(v) = env::var("VPN_STATIC_DIR") { cfg.static_dir = PathBuf::from(v); }
        if let Ok(v) = env::var("VPN_SESSION_HOURS") {
            if let Ok(h) = v.parse::<i64>() { cfg.session_hours = h; }
        }
        if let Ok(v) = env::var("VPN_LOG_LEVEL") { cfg.log_level = v; }
        if let Ok(v) = env::var("VPN_DEMO") {
            cfg.demo = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Ok(v) = env::var("VPN_EBPF_IFACE") { cfg.ebpf_iface = v; }

        cfg
    }

    pub fn is_tls_configured(&self) -> bool {
        self.tls_cert.exists() && self.tls_key.exists()
    }

    pub fn print_config(&self) {
        log::info!("HTTP listener:   {}", self.http_bind);
        log::info!("HTTPS listener:  {}", self.https_bind);
        log::info!("TLS cert:        {} ({})", self.tls_cert.display(), if self.is_tls_configured() { "OK" } else { "MISSING" });
        log::info!("DB path:         {}", self.db_path.display());
        log::info!("Static dir:      {}", self.static_dir.display());
        log::info!("Session timeout: {} hours", self.session_hours);
        log::info!("eBPF interface:  {}", self.ebpf_iface);
        if self.demo { log::warn!("*** DEMO MODE ENABLED - Authentication bypassed, data is simulated ***"); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.http_bind, "0.0.0.0:8080");
        assert_eq!(cfg.https_bind, "0.0.0.0:8443");
        assert_eq!(cfg.session_hours, 8);
        assert_eq!(cfg.log_level, "info");
    }

    #[test]
    fn test_from_env_defaults() {
        let cfg = ServerConfig::from_env();
        assert_eq!(cfg.http_bind, "0.0.0.0:8080");
        assert_eq!(cfg.session_hours, 8);
    }

    #[test]
    fn test_is_tls_configured_false_when_missing() {
        let cfg = ServerConfig {
            tls_cert: PathBuf::from("/nonexistent/cert.crt"),
            tls_key: PathBuf::from("/nonexistent/key.key"),
            ..Default::default()
        };
        assert!(!cfg.is_tls_configured());
    }
}