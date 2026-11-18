"""Construct coherent stream/worker publications for epoch load and orchestration fixtures."""

import base64

from kinetum_validation.engine.plan_metadata import PlanIoStreamMetadata, PlanPortMetadata, PlanTopologyMetadata
from kinetum_validation.process.telemetry import StatsResult, StreamStatsResult, WorkerCounterStatsResult
from kinetum_validation.process.epoch_load import EpochLoadPhase


def load_topology(rx_ports=(0, 1)):
    """Declare each RX queue and one TX stream with exact plan direction and storage arms."""
    ports = tuple(
        PlanPortMetadata(port, f"wan{port}", "driver", str(port), "PORT_DIRECTION_RX_ONLY", 0, "")
        for port in sorted(set(rx_ports))
    ) + (PlanPortMetadata(2, "lan0", "driver", "2", "PORT_DIRECTION_TX_ONLY", 0, ""),)
    streams = tuple(
        PlanIoStreamMetadata(f"rx{i}", port, "IO_STREAM_DIRECTION_RX", f"lane{i}", "", i, "pool", ())
        for i, port in enumerate(rx_ports)
    ) + (PlanIoStreamMetadata("tx", 2, "IO_STREAM_DIRECTION_TX", "egress", "", 0, None, ("pool",)),)
    return PlanTopologyMetadata(ports, streams, (), (), (), (), ())


def load_snapshot(step, *, offsets=(0, 450_000_000, 900_000_000), rates=(500, 500), rx_ports=(0, 1), epoch=1,
                  counts=None, generation=None, observation_epoch=None, collected=None, packet_size=64):
    """Publish coherent per-owner vectors at independently phased source times.

    Packet counts follow the supplied synthetic constant rates. These are
    arithmetic fixtures, not observations from a traffic generator.
    """
    times = tuple(int(step * 1_000_000_000) + offset for offset in offsets)
    if counts is None:
        counts = tuple(int(times[i] * rate // 1_000_000_000) for i, rate in enumerate(rates))
    if generation is None:
        generation = int(step)
    if observation_epoch is None:
        observation_epoch = epoch
    total = sum(counts)
    workers = [
        WorkerCounterStatsResult(i, observation_epoch, generation, timestamp, counts[i], 0, 0,
                                 counts[i] * packet_size, 0, 0)
        for i, timestamp in enumerate(times[:-1])
    ]
    workers.append(WorkerCounterStatsResult(
        len(counts), observation_epoch, generation, times[-1], 0, total, 0, 0, total * packet_size, 0,
    ))
    streams = [
        StreamStatsResult(f"rx{i}", port, "rx", i, i, i, times[i], counts[i], counts[i] * packet_size, 0)
        for i, port in enumerate(rx_ports)
    ] + [StreamStatsResult("tx", 2, "tx", len(counts), len(counts), 0, times[-1], total, total * packet_size, 0)]
    return StatsResult(
        success=True, runtime_generation=1, transition_plan_content_hash=base64.b64encode(b"p" * 32).decode("ascii"),
        active_snapshot_id=f"snapshot{epoch}", active_revision=epoch, active_epoch=epoch,
        transition_active_validation_hash=base64.b64encode(f"epoch{epoch}".encode().ljust(32, b"\0")).decode("ascii"),
        allocated_epoch_high_watermark=epoch, transition_state="EPOCH_TRANSITION_STATE_IDLE",
        expected_workers=len(times), execution_participant_count=len(times), region_count=len(times),
        collection_monotonic_ns=max(times) + 10_000_000 if collected is None else collected,
        latest_bank_publication_monotonic_ns=max(times),
        rx_packets=total, tx_packets=total, rx_bytes=total * packet_size, tx_bytes=total * packet_size,
        worker_counters=workers, stream_stats=streams,
    )


def qualified_load_evidence(run_root, target_pps=500):
    """Produce real qualifying phase witnesses for a synthetic advancing transition."""
    arguments = {"rates": (target_pps, target_pps)}
    targets = {0: target_pps, 1: target_pps}
    old = EpochLoadPhase(load_topology(), load_snapshot(10, **arguments), targets)
    for step in (15, 16, 18, 20, 22):
        old.observe(load_snapshot(step, **arguments))
    new = EpochLoadPhase(load_topology(), load_snapshot(23, epoch=2, **arguments), targets)
    for step in (23, 24, 26, 28, 30):
        new.observe(load_snapshot(step, epoch=2, **arguments))
    if not old.complete or not new.complete:
        raise AssertionError("fixture failed actual load qualification")
    return {
        "run_root": str(run_root), "old": old.evidence(), "new": new.evidence(), "load_qualified": True,
        "apply": {"success": True, "snapshot_id": "snapshot2", "revision": 2, "epoch": 2, "diagnostic": ""},
        "failure": "",
    }
