"""Validate built-in QoS causes and convergence with independently published stage totals."""

from .plan_metadata import PlanTopologyMetadata
from ..process.telemetry import StatsResult


_DROP_CAUSES = (
    "qos.unconfigured_drops",
    "qos.rate_limit_drops",
    "qos.flow_capacity_drops",
    "qos.invalid_input_drops",
)
_COUNTERS = frozenset(_DROP_CAUSES + (
    "qos.packets_allowed", "qos.packets_dropped",
    "qos.bytes_allowed", "qos.bytes_dropped", "qos.active_flows",
))


def qos_accounting_complete(stats: StatsResult, topology: PlanTopologyMetadata) -> bool:
    """Require exact causes per QoS context and matching logical-stage totals.

    The canonical gateway calls this after traffic retirement. Missing or
    contradictory context evidence raises RuntimeError immediately. Different
    module and worker publication cadences may temporarily leave totals unequal;
    return False until the existing bounded observation wait sees agreement.
    Other pipelines do not acquire this built-in module requirement.
    """
    domains = [row for row in topology.module_context_domains if row.module_id == "kinetum.qos"]
    if len(domains) != 1 or not domains[0].context_instance_ids:
        raise RuntimeError("QoS accounting requires the gateway's exact context population")
    expected = set(domains[0].context_instance_ids)
    bindings = [row for row in topology.module_contexts if row.context_instance_id in expected]
    stages = {row.context_instance_id: row.logical_stage_id for row in bindings}
    if len(bindings) != len(stages) or set(stages) != expected:
        raise RuntimeError("QoS context-to-stage membership differs from the plan")

    contexts = {identity: {} for identity in expected}
    owners = {}
    indices = set()
    for row in stats.module_counter_stats:
        if row.module_id != "kinetum.qos":
            if row.context_instance_id in expected:
                raise RuntimeError("QoS context carries a foreign module identity")
            continue
        if row.context_instance_id not in contexts:
            raise RuntimeError("QoS counter names a foreign context")
        values = contexts[row.context_instance_id]
        if row.name not in _COUNTERS or row.name in values:
            raise RuntimeError("QoS counter membership is unknown or duplicated")
        if not isinstance(row.value, int) or isinstance(row.value, bool) or not 0 <= row.value <= (1 << 64) - 1:
            raise RuntimeError("QoS counter value is not an unsigned 64-bit integer")
        identity = (row.context_index, row.worker_index, row.epoch)
        if (
            not 0 <= row.context_index < stats.module_context_count
            or not 0 <= row.worker_index < stats.execution_participant_count
            or not 0 < row.epoch <= stats.active_epoch
        ):
            raise RuntimeError("QoS counter owner or epoch is invalid")
        previous = owners.get(row.context_instance_id)
        if previous is None:
            if row.context_index in indices:
                raise RuntimeError("QoS contexts share one context index")
            owners[row.context_instance_id] = identity
            indices.add(row.context_index)
        elif previous != identity:
            raise RuntimeError("QoS context counters do not share one bank identity")
        values[row.name] = row.value

    totals = {}
    for context_id, values in contexts.items():
        if set(values) != _COUNTERS:
            raise RuntimeError(f"QoS context {context_id} omitted required counters")
        classified = sum(values[name] for name in _DROP_CAUSES)
        if classified != values["qos.packets_dropped"]:
            raise RuntimeError(
                f"QoS context {context_id} drop causes disagree: "
                f"causes={classified}, total={values['qos.packets_dropped']}"
            )
        stage = stages[context_id]
        total = totals.setdefault(stage, [0, 0, 0, 0, 0])
        contribution = (
            values["qos.packets_allowed"] + values["qos.packets_dropped"],
            values["qos.packets_allowed"], values["qos.packets_dropped"],
            values["qos.bytes_allowed"] + values["qos.bytes_dropped"], values["qos.bytes_allowed"],
        )
        for index, value in enumerate(contribution):
            total[index] += value

    observed = [row for row in stats.stage_stats if row.stage_id in totals]
    if len(observed) != len(totals) or {row.stage_id for row in observed} != set(totals):
        raise RuntimeError("QoS logical-stage counters are missing or duplicated")
    return all(owner[2] == stats.active_epoch for owner in owners.values()) and all(
        tuple(totals[row.stage_id]) == (
            row.in_packets, row.out_packets, row.dropped_packets, row.in_bytes, row.out_bytes,
        )
        for row in observed
    )
