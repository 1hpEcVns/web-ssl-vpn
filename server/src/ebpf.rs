use anyhow::{Context, Result};
use std::path::PathBuf;

pub struct EbpfStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub active_conns: u64,
}

pub struct EbpfMonitor {
    ebpf: Option<aya::Ebpf>,
}

fn default_bpf_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("target/bpfel-unknown-none/release/ebpf"),
        PathBuf::from("../target/bpfel-unknown-none/release/ebpf"),
    ]
}

impl EbpfMonitor {
    pub fn try_new(iface: &str, bpf_path: Option<&str>) -> Self {
        let paths_to_try: Vec<PathBuf> = if let Some(p) = bpf_path {
            vec![PathBuf::from(p)]
        } else {
            default_bpf_paths()
        };

        for path in &paths_to_try {
            match Self::init_ebpf(iface, path) {
                Ok(ebpf) => {
                    log::info!("eBPF monitor attached to interface '{}' via {}", iface, path.display());
                    return EbpfMonitor { ebpf: Some(ebpf) };
                }
                Err(e) => {
                    log::debug!("eBPF not found at {}: {:#}", path.display(), e);
                }
            }
        }

        log::warn!("eBPF not available (BPF binary not found): using StatusCollector counters");
        EbpfMonitor { ebpf: None }
    }

    pub(crate) fn init_ebpf(iface: &str, bpf_path: &PathBuf) -> Result<aya::Ebpf> {
        use aya::programs::tc::SchedClassifier;
        use aya::programs::TcAttachType;

        let bytes = std::fs::read(bpf_path)
            .with_context(|| format!("failed to read BPF binary at {}", bpf_path.display()))?;

        let mut ebpf = aya::Ebpf::load(&bytes).context("failed to load BPF bytecode")?;

        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_ingress")
            .context("tc_ingress program not found")?
            .try_into()
            .context("tc_ingress program is not a TC classifier")?;
        prog.load().context("failed to load tc_ingress")?;
        prog.attach(iface, TcAttachType::Ingress)
            .context("failed to attach tc_ingress")?;

        let prog: &mut SchedClassifier = ebpf
            .program_mut("tc_egress")
            .context("tc_egress program not found")?
            .try_into()
            .context("tc_egress program is not a TC classifier")?;
        prog.load().context("failed to load tc_egress")?;
        prog.attach(iface, TcAttachType::Egress)
            .context("failed to attach tc_egress")?;

        Ok(ebpf)
    }

    pub fn read_stats(&self) -> EbpfStats {
        let ebpf = match &self.ebpf {
            Some(b) => b,
            None => return EbpfStats { bytes_sent: 0, bytes_recv: 0, active_conns: 0 },
        };

        EbpfStats {
            bytes_sent: Self::read_hash(ebpf, "BYTES_SENT"),
            bytes_recv: Self::read_hash(ebpf, "BYTES_RECV"),
            active_conns: Self::read_array(ebpf, "CONN_COUNT"),
        }
    }

    fn read_hash(ebpf: &aya::Ebpf, name: &str) -> u64 {
        use aya::maps::HashMap;
        if let Some(map) = ebpf.map(name) {
            if let Ok(map) = TryInto::<HashMap<_, u32, u64>>::try_into(map) {
                return map.get(&0, 0).unwrap_or(0);
            }
        }
        0
    }

    fn read_array(ebpf: &aya::Ebpf, name: &str) -> u64 {
        use aya::maps::Array;
        if let Some(map) = ebpf.map(name) {
            if let Ok(map) = TryInto::<Array<_, u64>>::try_into(map) {
                return map.get(&0, 0).unwrap_or(0);
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_monitor_returns_zeros() {
        let mon = EbpfMonitor { ebpf: None };
        let stats = mon.read_stats();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_recv, 0);
        assert_eq!(stats.active_conns, 0);
    }

    #[test]
    fn test_default_bpf_paths_contains_two_paths() {
        let paths = default_bpf_paths();
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with("target/bpfel-unknown-none/release/ebpf"));
        assert!(paths[1].ends_with("../target/bpfel-unknown-none/release/ebpf"));
    }

    #[test]
    fn test_try_new_nonexistent_path_returns_fallback() {
        let mon = EbpfMonitor::try_new("lo", Some("/nonexistent/bpf/binary.ebpf"));
        let stats = mon.read_stats();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_recv, 0);
        assert_eq!(stats.active_conns, 0);
    }

    #[test]
    fn test_try_new_empty_iface_returns_fallback() {
        let mon = EbpfMonitor::try_new("", Some("/nonexistent/bpf.ebpf"));
        let stats = mon.read_stats();
        assert_eq!(stats.bytes_sent, 0);
    }

    #[test]
    fn test_try_new_no_path_tries_defaults_and_falls_back() {
        let mon = EbpfMonitor::try_new("lo", None);
        let stats = mon.read_stats();
        assert_eq!(stats.bytes_sent, 0);
    }

    #[test]
    fn test_read_hash_missing_map() {
        let mon = EbpfMonitor { ebpf: None };
        let stats = mon.read_stats();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_recv, 0);
    }

    #[test]
    fn test_ebpf_stats_defaults() {
        let stats = EbpfStats { bytes_sent: 1024, bytes_recv: 2048, active_conns: 5 };
        assert_eq!(stats.bytes_sent, 1024);
        assert_eq!(stats.bytes_recv, 2048);
        assert_eq!(stats.active_conns, 5);
    }

    #[test]
    fn test_init_ebpf_missing_file() {
        let result = EbpfMonitor::init_ebpf("lo", &PathBuf::from("/nonexistent/bpf.o"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read BPF binary"));
    }
}
