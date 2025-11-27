//! Metrics export for VPN server (Prometheus format).

use super::SuspicionTracker;
use crate::probe_protection::ProbeProtector;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::warn;

/// Background task to periodically export probe metrics to Prometheus text file
pub async fn probe_metrics_task(
    protector: Arc<ProbeProtector>,
    suspicion: Arc<SuspicionTracker>,
    path: PathBuf,
    interval_secs: u64,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;
        let path = path.clone();
        let protector_clone = protector.clone();
        let suspicion_clone = suspicion.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let content = protector_clone.metrics().to_prometheus("probe");
            let susp = suspicion_clone.prometheus("suspicion");
            let tmp = path.with_extension(".tmp");
            fs::write(&tmp, format!("{content}{susp}").as_bytes())?;
            fs::rename(&tmp, &path)?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .unwrap_or_else(|e| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        }) {
            warn!(%e, "Failed to persist probe metrics");
        }
    }
}
