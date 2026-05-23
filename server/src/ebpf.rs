use anyhow::{Context, Result};

pub struct EbpfStats {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub active_conns: u64,
}

pub struct EbpfMonitor {
    ebpf: Option<aya::Ebpf>,
}

impl EbpfMonitor {
    pub fn try_new(iface: &str) -> Self {
        match Self::init_ebpf(iface) {
            Ok(ebpf) => {
                log::info!("eBPF monitor attached to interface '{}'", iface);
                EbpfMonitor { ebpf: Some(ebpf) }
            }
            Err(e) => {
                log::warn!("eBPF attach failed ({:#}): using fallback counters", e);
                EbpfMonitor { ebpf: None }
            }
        }
    }

    fn init_ebpf(iface: &str) -> Result<aya::Ebpf> {
        use aya::programs::tc::SchedClassifier;
        use aya::programs::TcAttachType;

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../target/bpfel-unknown-none/release/ebpf");
        let bytes = std::fs::read(&path)
            .with_context(|| format!("failed to read BPF binary at {}", path.display()))?;

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
}
