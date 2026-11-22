//! Stream IDS Engine - High Performance Streaming Anomaly Detector in Rust
pub mod stream;
pub mod detector;
pub mod alerts;

pub use stream::{NetworkPacket, FlowMetrics, FlowKey, PacketDecoder, FlowTracker};
pub use detector::{StreamingDetector, AnomalyResult};
pub use alerts::{ThreatReport, ThreatSeverity, AttackType};
