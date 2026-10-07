"""Verify protobuf scalar presence and bounds in generated plan metadata."""

import tempfile
import unittest
from pathlib import Path
from textwrap import dedent, indent

from kinetum_validation.engine.plan_metadata import (
    PlanTopologyMetadata,
    parse_plan_topology,
)


_RECORD_MEMBERS = {
    "ports": dedent("""\
        logical_name: "lan0"
        io_driver_instance_id: "io_dpdk_0"
        driver_port_id: "lan0"
        direction: PORT_DIRECTION_TX_ONLY
        """),
    "io_streams": dedent("""\
        io_stream_id: "lan0.tx.lane_0"
        direction: IO_STREAM_DIRECTION_TX
        lane_id: "lane_0"
        tx_storage {
          storage_domain_ids: "storage_dpdk_0"
        }
        """),
    "packet_storage_domains": dedent("""\
        storage_domain_id: "storage_dpdk_0"
        """),
}
_UINT32_FIELDS = (
    ("ports", "ports", "logical_port_id"),
    ("io_streams", "io_streams", "logical_port_id"),
    ("io_streams", "io_streams", "driver_queue_id"),
    ("packet_storage_domains", "storage_domains", "buffer_count"),
)


def _record(record_name: str, fields: str = "") -> str:
    """Render one metadata record with the native printer's indentation."""
    members = indent(_RECORD_MEMBERS[record_name] + fields, "  ")
    return f"{record_name} {{\n{members}}}\n"


def _stream_record(direction: str, storage: str) -> str:
    """Render one direction-specific stream with the native printer's indentation."""
    identity = "wan0.rx.lane_0" if direction == "IO_STREAM_DIRECTION_RX" else "lan0.tx.lane_0"
    members = (
        f'io_stream_id: "{identity}"\n'
        f"direction: {direction}\n"
        'lane_id: "lane_0"\n'
        + storage
    )
    return "io_streams {\n" + indent(members, "  ") + "}\n"


class PlanMetadataTest(unittest.TestCase):
    """Keep implicit numeric defaults separate from required and optional facts."""

    def _parse(self, text: str) -> PlanTopologyMetadata:
        """Read supplied generated text through the public metadata parser."""
        with tempfile.TemporaryDirectory() as directory:
            plan_file = Path(directory) / "plan.pbtxt"
            plan_file.write_text(text, encoding="utf-8")
            return parse_plan_topology(plan_file)

    def test_omitted_port_and_queue_ids_decode_as_zero(self) -> None:
        """Native serialization may omit port zero and every queue-zero field."""
        topology = self._parse(_record("ports") + _record("io_streams"))

        self.assertEqual(topology.ports[0].logical_port_id, 0)
        self.assertEqual(topology.io_streams[0].logical_port_id, 0)
        self.assertEqual(topology.io_streams[0].driver_queue_id, 0)

    def test_explicit_and_omitted_zero_ids_agree(self) -> None:
        """Explicit zero and omitted implicit-presence IDs have identical meaning."""
        for record_name, _, field_name in _UINT32_FIELDS[:3]:
            with self.subTest(record=record_name, field=field_name):
                omitted = self._parse(_record(record_name))
                explicit = self._parse(
                    _record(record_name, f"{field_name}: 0\n")
                )
                self.assertEqual(explicit, omitted)

    def test_nonzero_uint32_values_preserve_their_exact_value(self) -> None:
        """Metadata integers retain both one and the inclusive uint32 maximum."""
        for record_name, attribute, field_name in _UINT32_FIELDS:
            for value in (1, (1 << 32) - 1):
                with self.subTest(record=record_name, field=field_name, value=value):
                    topology = self._parse(
                        _record(record_name, f"{field_name}: {value}\n")
                    )
                    row = getattr(topology, attribute)[0]
                    self.assertEqual(getattr(row, field_name), value)

    def test_invalid_uint32_values_reject(self) -> None:
        """Negative, overbound, noninteger, empty, and valueless scalars reject."""
        for record_name, _, field_name in _UINT32_FIELDS:
            for value in ("-1", str(1 << 32), "invalid", "1.5", '""', ""):
                with self.subTest(record=record_name, field=field_name, value=value):
                    with self.assertRaisesRegex(RuntimeError, field_name):
                        self._parse(_record(record_name, f"{field_name}: {value}\n"))

    def test_duplicate_uint32_values_reject(self) -> None:
        """Repeated singular numeric fields reject even when their values agree."""
        for record_name, _, field_name in _UINT32_FIELDS:
            with self.subTest(record=record_name, field=field_name):
                with self.assertRaisesRegex(RuntimeError, field_name):
                    self._parse(
                        _record(record_name, f"{field_name}: 1\n{field_name}: 1\n")
                    )

    def test_required_capacity_cannot_default_to_zero(self) -> None:
        """A storage population remains positive whether zero is explicit or omitted."""
        for fields in ("", "buffer_count: 0\n"):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(RuntimeError, "buffer_count"):
                    self._parse(_record("packet_storage_domains", fields))

    def test_optional_numa_absence_stays_distinct_from_zero(self) -> None:
        """An absent optional NUMA fact remains unknown while explicit zero is retained."""
        unknown = self._parse(
            _record("ports")
            + _record("packet_storage_domains", "buffer_count: 1\n")
        )
        known = self._parse(
            _record("ports", "host_numa_node: 0\n")
            + _record(
                "packet_storage_domains",
                "buffer_count: 1\nhost_numa_node: 0\n",
            )
        )

        self.assertIsNone(unknown.ports[0].host_numa_node)
        self.assertIsNone(unknown.storage_domains[0].host_numa_node)
        self.assertEqual(known.ports[0].host_numa_node, 0)
        self.assertEqual(known.storage_domains[0].host_numa_node, 0)

    def test_rx_and_multi_domain_tx_keep_their_distinct_storage_contracts(self) -> None:
        """RX reads one allocation identity while TX preserves its complete admitted set."""
        text = _stream_record("IO_STREAM_DIRECTION_RX", 'rx_storage_domain_id: "pool_a"\n')
        text += _stream_record(
            "IO_STREAM_DIRECTION_TX",
            'tx_storage {\n  storage_domain_ids: "pool_a"\n  storage_domain_ids: "pool_b"\n}\n',
        )
        rx, tx = self._parse(text).io_streams
        self.assertEqual(rx.rx_storage_domain_id, "pool_a")
        self.assertEqual(rx.tx_storage_domain_ids, ())
        self.assertEqual(rx.storage_domain_ids, ("pool_a",))
        self.assertIsNone(tx.rx_storage_domain_id)
        self.assertEqual(tx.tx_storage_domain_ids, ("pool_a", "pool_b"))
        self.assertEqual(tx.storage_domain_ids, ("pool_a", "pool_b"))

    def test_storage_arms_require_exact_direction_presence_and_canonical_sets(self) -> None:
        """Missing, mixed, wrong-direction, duplicate, empty, and unsorted storage reject."""
        rx = 'rx_storage_domain_id: "pool_a"\n'
        tx = 'tx_storage {\n  storage_domain_ids: "pool_a"\n}\n'
        cases = (
            ("IO_STREAM_DIRECTION_RX", ""),
            ("IO_STREAM_DIRECTION_RX", tx),
            ("IO_STREAM_DIRECTION_RX", rx + tx),
            ("IO_STREAM_DIRECTION_TX", ""),
            ("IO_STREAM_DIRECTION_TX", rx),
            ("IO_STREAM_DIRECTION_TX", rx + tx),
            ("IO_STREAM_DIRECTION_TX", tx + tx),
            ("IO_STREAM_DIRECTION_TX", "tx_storage {\n}\n"),
            ("IO_STREAM_DIRECTION_TX", 'tx_storage {\n  storage_domain_ids: ""\n}\n'),
            (
                "IO_STREAM_DIRECTION_TX",
                'tx_storage {\n  storage_domain_ids: "pool_a"\n  storage_domain_ids: "pool_a"\n}\n',
            ),
            (
                "IO_STREAM_DIRECTION_TX",
                'tx_storage {\n  storage_domain_ids: "pool_b"\n  storage_domain_ids: "pool_a"\n}\n',
            ),
        )
        for direction, storage in cases:
            with self.subTest(direction=direction, storage=storage):
                with self.assertRaises(RuntimeError):
                    self._parse(_stream_record(direction, storage))

    def test_removed_stream_storage_field_is_not_a_compatibility_reader(self) -> None:
        """The retired singular stream field rejects even beside a valid new arm."""
        storage = (
            'rx_storage_domain_id: "pool_a"\n'
            'storage_domain_id: "pool_a"\n'
        )
        with self.assertRaisesRegex(RuntimeError, "removed storage_domain_id"):
            self._parse(_stream_record("IO_STREAM_DIRECTION_RX", storage))

    def test_nested_names_cannot_supply_a_missing_rx_allocation(self) -> None:
        """Nested fields remain scoped and cannot impersonate a required storage arm."""
        storage = 'unrelated {\n  rx_storage_domain_id: "pool_a"\n}\n'
        with self.assertRaisesRegex(RuntimeError, "allocation storage arm"):
            self._parse(_stream_record("IO_STREAM_DIRECTION_RX", storage))


if __name__ == "__main__":
    unittest.main()
