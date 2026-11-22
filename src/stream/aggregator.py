"""
Sliding-window flow aggregator for stateful network traffic stream analysis.
"""

import math
from bisect import bisect_right
from collections import defaultdict, deque
from typing import Dict, List, Optional, Iterator
import numpy as np

from src.stream.events import NetworkPacket, FlowKey, FlowMetrics


class FlowState:
    """Internal state for tracking a specific flow's packets within a time window."""

    def __init__(self, key: FlowKey):
        self.key = key
        self.flow_id = f"{key.src_ip}:{key.src_port}->{key.dst_ip}:{key.dst_port}/{key.protocol}"
        self.packets: deque[NetworkPacket] = deque()
        self.first_seen = 0.0
        self.last_seen = 0.0

    def add_packet(self, packet: NetworkPacket):
        if not self.packets:
            self.packets.append(packet)
            self.first_seen = packet.timestamp
            self.last_seen = packet.timestamp
            return

        # Keep the deque timestamp-ordered so pruning and inter-arrival
        # statistics remain correct when capture events arrive out of order.
        if packet.timestamp >= self.packets[-1].timestamp:
            self.packets.append(packet)
        else:
            timestamps = [existing.timestamp for existing in self.packets]
            insert_at = bisect_right(timestamps, packet.timestamp)
            self.packets.insert(insert_at, packet)

        self.first_seen = self.packets[0].timestamp
        self.last_seen = max(self.last_seen, packet.timestamp)

    def prune_older_than(self, cutoff_time: float):
        while self.packets and self.packets[0].timestamp < cutoff_time:
            self.packets.popleft()
        if self.packets:
            self.first_seen = self.packets[0].timestamp

    def get_metrics(self) -> Optional[FlowMetrics]:
        if not self.packets:
            return None

        count = len(self.packets)
        sizes = [p.packet_size for p in self.packets]
        entropies = [p.payload_entropy for p in self.packets]
        timestamps = [p.timestamp for p in self.packets]

        duration = max(1e-6, self.last_seen - self.first_seen)
        byte_count = sum(sizes)

        # Inter-arrival times
        if count > 1:
            iats = [timestamps[i] - timestamps[i - 1] for i in range(1, count)]
            avg_iat = float(np.mean(iats))
            std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0
        else:
            avg_iat = 0.0
            std_iat = 0.0

        # TCP Flags
        syn_count = sum(1 for p in self.packets if p.tcp_flags.get("syn", False))
        ack_count = sum(1 for p in self.packets if p.tcp_flags.get("ack", False))
        fin_count = sum(1 for p in self.packets if p.tcp_flags.get("fin", False))
        rst_count = sum(1 for p in self.packets if p.tcp_flags.get("rst", False))
        psh_count = sum(1 for p in self.packets if p.tcp_flags.get("psh", False))

        return FlowMetrics(
            flow_id=self.flow_id,
            src_ip=self.key.src_ip,
            dst_ip=self.key.dst_ip,
            src_port=self.key.src_port,
            dst_port=self.key.dst_port,
            protocol=self.key.protocol,
            start_time=self.first_seen,
            duration=duration,
            packet_count=count,
            byte_count=byte_count,
            packet_rate=count / duration,
            byte_rate=byte_count / duration,
            avg_packet_size=float(np.mean(sizes)),
            std_packet_size=float(np.std(sizes)) if count > 1 else 0.0,
            min_packet_size=float(np.min(sizes)),
            max_packet_size=float(np.max(sizes)),
            avg_iat=avg_iat,
            std_iat=std_iat,
            syn_count=syn_count,
            ack_count=ack_count,
            fin_count=fin_count,
            rst_count=rst_count,
            psh_count=psh_count,
            avg_entropy=float(np.mean(entropies)),
        )


class StreamFlowAggregator:
    """Aggregates streaming packets into windowed flow statistics."""

    def __init__(self, window_seconds: float = 10.0, max_inactive_seconds: float = 30.0):
        self.window_seconds = window_seconds
        self.max_inactive_seconds = max_inactive_seconds
        self.flows: Dict[FlowKey, FlowState] = {}
        self.latest_timestamp = 0.0

    def ingest_packet(self, packet: NetworkPacket) -> Optional[FlowMetrics]:
        """Ingest a single packet and return current flow metrics if threshold met."""
        self.latest_timestamp = max(self.latest_timestamp, packet.timestamp)
        key = packet.flow_key

        if key not in self.flows:
            self.flows[key] = FlowState(key)

        state = self.flows[key]
        state.add_packet(packet)

        # Evict old packets outside window
        state.prune_older_than(self.latest_timestamp - self.window_seconds)

        # Clean up stale flows periodically
        if len(self.flows) > 500:
            self.cleanup_stale_flows(self.latest_timestamp)

        return state.get_metrics()

    def cleanup_stale_flows(self, current_time: float) -> List[FlowMetrics]:
        """Prune flows inactive for longer than max_inactive_seconds and return finalized metrics."""
        expired_keys = []
        flushed_metrics = []

        for key, state in self.flows.items():
            if current_time - state.last_seen > self.max_inactive_seconds:
                metrics = state.get_metrics()
                if metrics:
                    flushed_metrics.append(metrics)
                expired_keys.append(key)

        for key in expired_keys:
            del self.flows[key]

        return flushed_metrics

    def flush_all(self) -> List[FlowMetrics]:
        """Flush and return metrics for all currently active flows."""
        metrics_list = []
        for state in self.flows.values():
            m = state.get_metrics()
            if m:
                metrics_list.append(m)
        self.flows.clear()
        return metrics_list
