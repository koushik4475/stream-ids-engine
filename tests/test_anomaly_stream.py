"""
Comprehensive synthetic network stream test suite validating real-time anomaly detection,
isolation forest, streaming autoencoder, threat classification, and SIEM dispatching.
"""

import time
import pytest
import numpy as np

from src.stream.events import NetworkPacket, FlowMetrics, FlowKey
from src.stream.decoder import PacketStreamDecoder
from src.stream.aggregator import StreamFlowAggregator
from src.detector.isolation_forest import StreamingIsolationForest
from src.detector.autoencoder import StreamingAutoencoder
from src.detector.ensemble import StreamingEnsembleDetector
from src.alerts.threat_intel import ThreatClassifier, AttackCategory, ThreatSeverity
from src.alerts.dispatcher import SiemWebhookDispatcher, AlertEvent
from src.detector.base import AnomalyScore
from src.engine.pipeline import StreamIDSEngine


def generate_normal_packet(timestamp: float, seq: int) -> dict:
    """Generate typical HTTP/TLS client-server normal packet."""
    return {
        "timestamp": timestamp,
        "src_ip": "192.168.1.50",
        "dst_ip": "104.244.42.1",
        "src_port": 49152 + (seq % 10),
        "dst_port": 443,
        "protocol": "TCP",
        "packet_size": 200 + (seq * 7) % 800,
        "tcp_flags": {"ack": True, "psh": (seq % 3 == 0)},
        "payload_entropy": 4.5 + ((seq % 5) * 0.1),
    }


def generate_syn_flood_packet(timestamp: float, seq: int) -> dict:
    """Generate high-velocity SYN flood attack packet."""
    return {
        "timestamp": timestamp,
        "src_ip": f"10.0.{seq % 254}.{seq % 250 + 1}",
        "dst_ip": "192.168.1.10",
        "src_port": 10000 + seq,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_size": 64,
        "tcp_flags": {"syn": True, "ack": False},
        "payload_entropy": 1.0,
    }


def generate_exfiltration_packet(timestamp: float, seq: int) -> dict:
    """Generate high-entropy data exfiltration traffic packet."""
    return {
        "timestamp": timestamp,
        "src_ip": "192.168.1.99",
        "dst_ip": "198.51.100.77",
        "src_port": 52000,
        "dst_port": 9001,
        "protocol": "TCP",
        "packet_size": 1460,
        "tcp_flags": {"ack": True, "psh": True},
        "payload_entropy": 7.95,
    }


class TestStreamDecoder:
    """Tests for packet stream decoder and entropy computation."""

    def test_shannon_entropy(self):
        # Uniform distribution bytes should have high entropy near 8.0
        uniform_bytes = bytes(range(256))
        entropy = PacketStreamDecoder.calculate_entropy(uniform_bytes)
        assert 7.9 < entropy <= 8.0

        # Monotonous zero bytes should have 0 entropy
        zero_bytes = bytes([0] * 256)
        assert PacketStreamDecoder.calculate_entropy(zero_bytes) == 0.0

    def test_decode_dict_event(self):
        event = generate_normal_packet(100.0, 1)
        pkt = PacketStreamDecoder.decode_dict_event(event)
        assert pkt.src_ip == "192.168.1.50"
        assert pkt.dst_port == 443
        assert pkt.tcp_flags["ack"] is True
        assert pkt.payload_entropy > 4.0


class TestFlowAggregator:
    """Tests for flow state tracking and metrics computation."""

    def test_flow_aggregation(self):
        agg = StreamFlowAggregator(window_seconds=5.0)
        t = 1000.0
        metrics = None
        for i in range(10):
            event = generate_normal_packet(t + (i * 0.1), 0)
            pkt = PacketStreamDecoder.decode_dict_event(event)
            metrics = agg.ingest_packet(pkt)

        assert metrics is not None
        assert metrics.packet_count == 10
        assert metrics.byte_count > 0
        assert metrics.packet_rate > 5.0
        vec = metrics.to_feature_vector()
        assert len(vec) == 17


class TestStreamingDetectors:
    """Tests for Isolation Forest and Autoencoder detectors."""

    @pytest.fixture
    def baseline_data(self):
        np.random.seed(42)
        # 100 normal flow vectors
        return np.random.normal(loc=10.0, scale=1.5, size=(100, 17))

    def test_streaming_isolation_forest(self, baseline_data):
        detector = StreamingIsolationForest()
        detector.fit_batch(baseline_data)

        # Normal sample
        normal_x = np.random.normal(loc=10.0, scale=1.0, size=17)
        score_normal = detector.score_one(normal_x)
        assert score_normal.anomaly_score < 0.65

        # Extreme anomalous outlier
        anomaly_x = np.ones(17) * 100.0
        score_anomaly = detector.score_one(anomaly_x)
        assert score_anomaly.is_anomaly is True
        assert score_anomaly.anomaly_score > 0.65
        assert len(score_anomaly.feature_contributions) > 0

    def test_streaming_autoencoder(self, baseline_data):
        ae = StreamingAutoencoder(input_dim=17, hidden_dim=8, latent_dim=4)
        ae.fit_batch(baseline_data, epochs=20)

        # Normal sample
        normal_x = np.random.normal(loc=10.0, scale=1.0, size=17)
        score_normal = ae.score_one(normal_x)

        # Outlier sample
        anomaly_x = np.ones(17) * 150.0
        score_anomaly = ae.score_one(anomaly_x)
        assert score_anomaly.raw_score > score_normal.raw_score

    def test_streaming_ensemble(self, baseline_data):
        ensemble = StreamingEnsembleDetector()
        ensemble.fit_batch(baseline_data)

        normal_x = np.random.normal(loc=10.0, scale=1.0, size=17)
        score_normal = ensemble.score_one(normal_x)
        assert score_normal.anomaly_score < 0.70

        anomaly_x = np.ones(17) * 200.0
        score_anomaly = ensemble.score_one(anomaly_x)
        assert score_anomaly.is_anomaly is True


class TestThreatClassificationAndSIEM:
    """Tests for MITRE taxonomy mapping and dispatcher."""

    def test_syn_flood_classification(self):
        metrics = FlowMetrics(
            flow_id="attacker->victim/TCP",
            src_ip="192.168.1.200",
            dst_ip="10.0.0.1",
            src_port=44444,
            dst_port=80,
            protocol="TCP",
            start_time=100.0,
            duration=1.0,
            packet_count=300,
            byte_count=19200,
            packet_rate=300.0,
            byte_rate=19200.0,
            avg_packet_size=64.0,
            std_packet_size=0.0,
            min_packet_size=64.0,
            max_packet_size=64.0,
            avg_iat=0.003,
            std_iat=0.001,
            syn_count=290,
            ack_count=0,
            fin_count=0,
            rst_count=0,
            psh_count=0,
            avg_entropy=1.2,
        )
        fake_score = AnomalyScore(
            flow_id=metrics.flow_id,
            is_anomaly=True,
            anomaly_score=0.95,
            threshold=0.6,
            detector_name="Ensemble",
            feature_contributions={"packet_rate": 300.0, "syn_count": 290.0},
            raw_score=0.95,
            timestamp=101.0,
        )

        threat = ThreatClassifier.classify(metrics, fake_score)
        assert threat.category == AttackCategory.SYN_FLOOD
        assert threat.severity == ThreatSeverity.CRITICAL
        assert threat.mitre_technique_id == "T1498.001"

    def test_exfiltration_classification(self):
        metrics = FlowMetrics(
            flow_id="compromised->c2/TCP",
            src_ip="192.168.1.99",
            dst_ip="203.0.113.5",
            src_port=55123,
            dst_port=8888,
            protocol="TCP",
            start_time=100.0,
            duration=5.0,
            packet_count=50,
            byte_count=73000,
            packet_rate=10.0,
            byte_rate=14600.0,
            avg_packet_size=1460.0,
            std_packet_size=0.0,
            min_packet_size=1460.0,
            max_packet_size=1460.0,
            avg_iat=0.1,
            std_iat=0.01,
            syn_count=1,
            ack_count=49,
            fin_count=0,
            rst_count=0,
            psh_count=40,
            avg_entropy=7.85,
        )
        fake_score = AnomalyScore(
            flow_id=metrics.flow_id,
            is_anomaly=True,
            anomaly_score=0.98,
            threshold=0.6,
            detector_name="Ensemble",
            feature_contributions={"avg_entropy": 7.85},
            raw_score=0.98,
            timestamp=105.0,
        )

        threat = ThreatClassifier.classify(metrics, fake_score)
        assert threat.category == AttackCategory.DATA_EXFILTRATION
        assert threat.mitre_technique_id == "T1048"

    def test_siem_dispatcher(self):
        dispatcher = SiemWebhookDispatcher(webhook_urls=[], enable_audit_log=True)
        assert len(dispatcher.dispatched_alerts) == 0


class TestEndToEndPipeline:
    """Full synthetic stream simulation through StreamIDSEngine."""

    def test_synthetic_stream_pipeline(self):
        engine = StreamIDSEngine(window_seconds=10.0, warmup_samples=60)

        # 1. Warmup with 70 baseline normal packets
        base_ts = 1700000000.0
        for i in range(70):
            event = generate_normal_packet(base_ts + i * 0.1, i)
            engine.process_event(event)

        assert engine.is_warmed_up is True

        # 2. Stream continued normal packets (should not trigger critical alert)
        for i in range(70, 90):
            event = generate_normal_packet(base_ts + i * 0.1, i)
            engine.process_event(event)

        # 3. Inject sudden attack stream (SYN flood volumetric spike)
        alerts_detected = []
        for i in range(90, 160):
            attack_event = generate_syn_flood_packet(base_ts + 10.0 + (i - 90) * 0.005, i)
            alert = engine.process_event(attack_event)
            if alert:
                alerts_detected.append(alert)

        # Should detect the anomaly and classify it
        assert len(alerts_detected) > 0
        latest_alert = alerts_detected[-1]
        assert latest_alert.threat.category in [
            AttackCategory.SYN_FLOOD,
            AttackCategory.UNKNOWN_ANOMALY,
            AttackCategory.PORT_SCAN,
        ]
        assert latest_alert.anomaly.is_anomaly is True
        assert latest_alert.flow.packet_count >= 1


def test_flow_aggregator_orders_late_packets_within_the_active_window():
    aggregator = StreamFlowAggregator(window_seconds=5.0)

    metrics = None
    for timestamp in (100.0, 104.0, 102.0):
        packet = PacketStreamDecoder.decode_dict_event(generate_normal_packet(timestamp, 0))
        metrics = aggregator.ingest_packet(packet)

    assert metrics is not None
    assert metrics.packet_count == 3
    assert metrics.duration == 4.0
    assert metrics.avg_iat == pytest.approx(2.0)

    state = next(iter(aggregator.flows.values()))
    assert state.first_seen == 100.0
    assert state.last_seen == 104.0
    assert [packet.timestamp for packet in state.packets] == [100.0, 102.0, 104.0]


def test_late_packet_does_not_move_flow_last_seen_backwards_or_expire_it():
    aggregator = StreamFlowAggregator(window_seconds=30.0, max_inactive_seconds=5.0)

    for timestamp in (100.0, 110.0, 101.0):
        packet = PacketStreamDecoder.decode_dict_event(generate_normal_packet(timestamp, 0))
        aggregator.ingest_packet(packet)

    state = next(iter(aggregator.flows.values()))
    assert state.last_seen == 110.0

    expired = aggregator.cleanup_stale_flows(current_time=112.0)
    assert expired == []
    assert len(aggregator.flows) == 1
