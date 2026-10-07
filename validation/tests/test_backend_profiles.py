"""
Tests for backend-profile selection and backend-neutral run metadata.

These tests guard the plan-first split between TAP-PMD validation and physical
PCI validation. A regression that routes PCI through TAP VDEVs, or silently
falls back to TAP-PMD bindings, should fail here before reaching live hardware.
"""

import asyncio
import copy
import json
import tempfile
import unittest
from unittest import mock
from textwrap import dedent
from pathlib import Path

from kinetum_validation.config.types import (
    BackendConfig,
    BackendType,
    DEPLOYMENT_SPECS,
    DeploymentMode,
    ProcessConfig,
    StreamTopologyProfile,
    StorageProfile,
    TestConfig as ValidationConfig,
    TrafficDriverType,
)
from kinetum_validation.engine.plan_metadata import (
    decode_resolved_mac_address,
    parse_plan_topology,
)
from kinetum_validation.engine.json_contract import (
    JsonContractError,
    validate_run_metadata,
)
from kinetum_validation.orchestrator import TestOrchestrator as ValidationOrchestrator
from kinetum_validation.traffic import (
    NativeTapTrafficDriver,
    TRexTrafficDriver,
    make_traffic_driver,
)


TEST_PROCESS_CONFIG = ProcessConfig(
    runtime_root=Path("/opt/kinetum"),
    validation_root=Path("/var/tmp/kinetum-validation"),
)


class _DryRunOrchestrator(ValidationOrchestrator):
    """Minimal orchestrator that exercises dry-run result handling."""

    async def _setup(self):  # pylint: disable=arguments-differ,protected-access
        """Admit dry-run setup without constructing external resources."""
        return True


class _CancelledCaptureProcess:
    """Synthetic child whose first retirement wait is cancelled."""

    def __init__(self) -> None:
        """Initialize one live child and an empty signal ledger."""
        self.returncode = None
        self.wait_calls = 0
        self.terminate_calls = 0
        self.kill_calls = 0

    async def wait(self) -> int:
        """Cancel once, then publish one terminal signal status."""
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise asyncio.CancelledError
        self.returncode = -15
        return self.returncode

    def terminate(self) -> None:
        """Record one graceful termination request."""
        self.terminate_calls += 1

    def kill(self) -> None:
        """Record one forced termination request."""
        self.kill_calls += 1


def _profile_config(deployment: DeploymentMode, backend_type: BackendType) -> BackendConfig:
    """Build a BackendConfig from a deployment backend profile."""
    profile = DEPLOYMENT_SPECS[deployment].backend_profile(backend_type)
    return BackendConfig(
        backend_type=backend_type,
        ports=profile.ports,
    )


class TestBackendProfiles(unittest.TestCase):
    """Validate backend profile selection for TAP and PCI."""

    def test_fan_in_tap_profile_selects_plan_owned_tap_bindings(self):
        """Fan-in TAP profile should select bindings while keeping traffic IFs only."""
        spec = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY]
        profile = spec.backend_profile(BackendType.DPDK_TAP)

        self.assertEqual(
            profile.bindings_file_for(StreamTopologyProfile.DEFAULT, StorageProfile.SHARED),
            "fan_in_edge_gateway_tap_bindings.pbtxt",
        )
        self.assertEqual(profile.hw_file, "hardware_inventory_tap.pbtxt")
        self.assertEqual(profile.traffic_driver, TrafficDriverType.NATIVE_TAP)
        self.assertEqual(profile.latency_source, "kernel_af_packet_pcap")
        self.assertEqual([port.tap_iface for port in profile.ports],
                         ["neb_rx0", "neb_rx1", "neb_tx"])
        self.assertEqual([port.traffic_iface for port in profile.ports],
                         ["neb_rx0", "neb_rx1", "neb_tx"])

    def test_fan_in_pci_profile_uses_d430_bindings(self):
        """Fan-in PCI profile should select d430 bindings and traffic ports."""
        spec = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY]
        profile = spec.backend_profile(BackendType.DPDK_PCI)

        self.assertEqual(
            profile.bindings_file_for(StreamTopologyProfile.DEFAULT, StorageProfile.SHARED),
            "fan_in_edge_gateway_cloudlab_d430_bindings.pbtxt",
        )
        self.assertEqual(profile.hw_file, "hardware_inventory_cloudlab_d430.pbtxt")
        self.assertEqual(profile.traffic_driver, TrafficDriverType.TREX)
        self.assertEqual(profile.timestamp_source, "trex_port_stats")
        self.assertIsNone(profile.latency_source)
        self.assertEqual([port.peer_iface for port in profile.ports],
                         ["enp6s0f0np0", "enp6s0f2np2", "enp6s0f1np1"])
        self.assertEqual([port.peer_ip for port in profile.ports],
                         ["10.10.1.1", "10.10.2.1", "10.10.3.2"])
        self.assertEqual([port.traffic_role for port in profile.ports],
                         ["rx", "rx", "tx"])
        self.assertEqual([port.traffic_port_id for port in profile.ports], [0, 1, 2])
        self.assertEqual([port.runtime_direction for port in profile.ports],
                         ["", "", ""])
        self.assertEqual([port.runtime_mac for port in profile.ports], ["", "", ""])
        self.assertTrue(all(not port.tap_iface for port in profile.ports))

    def test_fan_in_pci_profile_exposes_rx_rss_2_bindings(self):
        """Fan-in PCI profile should expose the explicit RX RSS topology."""
        spec = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY]
        profile = spec.backend_profile(BackendType.DPDK_PCI)

        self.assertEqual(
            profile.bindings_file_for(StreamTopologyProfile.RX_RSS_2, StorageProfile.SHARED),
            "fan_in_edge_gateway_cloudlab_d430_rx_rss_2_bindings.pbtxt",
        )

    def test_unsupported_stream_topology_fails_closed(self):
        """Profiles must not silently substitute default bindings."""
        spec = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY]
        profile = spec.backend_profile(BackendType.DPDK_TAP)

        with self.assertRaisesRegex(ValueError, "has no bindings for stream topology"):
            profile.bindings_file_for(StreamTopologyProfile.RX_RSS_2, StorageProfile.SHARED)

    def test_separate_storage_profiles_select_complete_d430_bindings(self):
        """Queue topology and storage selection resolve one exact authored file."""
        profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_PCI)
        cases = (
            (
                StreamTopologyProfile.DEFAULT,
                "fan_in_edge_gateway_cloudlab_d430_per_rx_queue_bindings.pbtxt",
            ),
            (
                StreamTopologyProfile.RX_RSS_2,
                "fan_in_edge_gateway_cloudlab_d430_rx_rss_2_per_rx_queue_bindings.pbtxt",
            ),
        )
        for topology, filename in cases:
            with self.subTest(topology=topology):
                self.assertEqual(profile.bindings_file_for(topology, StorageProfile.PER_RX_QUEUE), filename)
                config = ValidationConfig(
                    process=TEST_PROCESS_CONFIG,
                    backend=_profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_PCI),
                    stream_topology=topology,
                    storage_profile=StorageProfile.PER_RX_QUEUE,
                )
                self.assertEqual(config.bindings_file, filename)
                self.assertIn(filename, config.required_example_files)

    def test_missing_storage_profile_never_substitutes_shared_bindings(self):
        """An unavailable profile combination rejects instead of changing storage intent."""
        profile = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY].backend_profile(BackendType.DPDK_TAP)
        with self.assertRaisesRegex(ValueError, "storage profile per_rx_queue"):
            profile.bindings_file_for(StreamTopologyProfile.DEFAULT, StorageProfile.PER_RX_QUEUE)

    def test_unsupported_pci_profile_fails_closed(self):
        """Deployments without a PCI profile should reject dpdk_pci."""
        spec = DEPLOYMENT_SPECS[DeploymentMode.PASSTHROUGH]

        with self.assertRaises(ValueError):
            spec.backend_profile(BackendType.DPDK_PCI)


class TestTrafficDrivers(unittest.TestCase):
    """Validate traffic-driver selection independent of backend setup."""

    def test_native_tap_driver_selected_for_tap_profile(self):
        """TAP profile should select the native local traffic driver."""
        backend = _profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_TAP)
        config = ValidationConfig(
            process=TEST_PROCESS_CONFIG,
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY, backend=backend,
        )

        driver = make_traffic_driver(config)

        self.assertIsInstance(driver, NativeTapTrafficDriver)
        self.assertFalse(driver.requires_sustained_generation_overlap)
        self.assertEqual(
            driver.sender_bin,
            config.process.validation_bin_dir / "kinetum_tap_sender",
        )
        self.assertEqual(
            driver.analyzer_bin,
            config.process.validation_bin_dir / "kinetum_tap_analyzer",
        )
        self.assertEqual(config.backend_profile.traffic_driver, TrafficDriverType.NATIVE_TAP)
        self.assertEqual(config.backend_profile.timestamp_source, "kernel_af_packet")
        self.assertEqual(
            config.backend_profile.rate_control_source,
            "userspace_native_sender",
        )

    def test_trex_driver_selected_for_pci_profile(self):
        """PCI profile should select the hardware traffic-generator driver."""
        backend = _profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_PCI)
        config = ValidationConfig(
            process=TEST_PROCESS_CONFIG,
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY, backend=backend,
        )

        driver = make_traffic_driver(config)

        self.assertIsInstance(driver, TRexTrafficDriver)
        self.assertTrue(driver.requires_sustained_generation_overlap)
        self.assertEqual(config.backend_profile.traffic_driver, TrafficDriverType.TREX)
        self.assertEqual(config.backend_profile.timestamp_source, "trex_port_stats")
        self.assertEqual(
            config.backend_profile.rate_control_source,
            "trex_stl_rate_control",
        )

    def test_native_capture_spawn_failure_leaves_no_session_residue(self):
        """Failed spawn and premature exit cannot masquerade as capture."""
        backend = _profile_config(
            DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_TAP
        )
        config = ValidationConfig(
            process=TEST_PROCESS_CONFIG,
            deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY, backend=backend
        )
        driver = NativeTapTrafficDriver(
            config,
            Path("/var/tmp/kinetum-validation/bin/kinetum_tap_sender"),
            Path("/var/tmp/kinetum-validation/bin/kinetum_tap_analyzer"),
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "kinetum_validation.traffic.native_tap.require_system_executable",
            return_value="/usr/bin/tcpdump",
        ), mock.patch(
            "kinetum_validation.traffic.native_tap.asyncio.create_subprocess_exec",
            side_effect=OSError("injected spawn failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected spawn failure"):
                asyncio.run(
                    driver.start_capture(
                        Path(directory) / "capture.pcap",
                        "udp",
                    )
                )

        self.assertIsNone(driver._capture_proc)  # pylint: disable=protected-access
        self.assertIsNone(driver._capture_task)  # pylint: disable=protected-access
        self.assertIsNone(driver._capture_ready)  # pylint: disable=protected-access
        self.assertIsNone(driver._pcap_file)  # pylint: disable=protected-access

        async def reject_premature_exit() -> None:
            """Prove a zero-status early child still fails lifecycle evidence."""
            process = mock.MagicMock(returncode=0)
            process.wait = mock.AsyncMock(return_value=0)
            driver._capture_proc = process  # pylint: disable=protected-access
            driver._capture_task = asyncio.create_task(  # pylint: disable=protected-access
                asyncio.sleep(0)
            )
            await driver._capture_task  # pylint: disable=protected-access
            with self.assertRaisesRegex(RuntimeError, "before harness-requested"):
                await driver.stop_capture()

        asyncio.run(reject_premature_exit())
        self.assertIsNone(driver._capture_proc)  # pylint: disable=protected-access
        self.assertIsNone(driver._capture_task)  # pylint: disable=protected-access

    def test_native_capture_cancellation_retires_child_and_output_task(self):
        """Cancellation propagates only after exact capture ownership retires."""
        backend = _profile_config(
            DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_TAP
        )
        driver = NativeTapTrafficDriver(
            ValidationConfig(
                process=TEST_PROCESS_CONFIG,
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                backend=backend,
            ),
            Path("/unused/kinetum_tap_sender"),
            Path("/unused/kinetum_tap_analyzer"),
        )

        async def cancel_stop() -> _CancelledCaptureProcess:
            """Inject cancellation into the first graceful wait."""
            process = _CancelledCaptureProcess()
            driver._capture_proc = process  # type: ignore[assignment]  # pylint: disable=protected-access
            driver._capture_task = asyncio.create_task(  # pylint: disable=protected-access
                asyncio.sleep(0)
            )
            await driver._capture_task  # pylint: disable=protected-access
            with self.assertRaises(asyncio.CancelledError):
                await driver.stop_capture()
            return process

        process = asyncio.run(cancel_stop())
        self.assertGreaterEqual(process.terminate_calls, 2)
        self.assertEqual(process.kill_calls, 0)
        self.assertIsNone(driver._capture_proc)  # pylint: disable=protected-access
        self.assertIsNone(driver._capture_task)  # pylint: disable=protected-access
        self.assertIsNone(driver._capture_ready)  # pylint: disable=protected-access
        self.assertIsNone(driver._pcap_file)  # pylint: disable=protected-access


class TestRunMetadata(unittest.TestCase):
    """Validate reproducibility metadata for backend-neutral runs."""

    def test_plan_port_parser_ignores_nested_field_collisions(self):
        """Plan metadata parsing should only read immediate PortConfig fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_file = Path(tmpdir) / "plan.pbtxt"
            plan_file.write_text(
                dedent(
                    """
                    ports {
                      logical_port_id: 1
                      logical_name: "wan0"
                      io_driver_instance_id: "io_udp_0"
                      driver_port_id: "wan0"
                      direction: PORT_DIRECTION_RX_ONLY
                      resolved_mac_address: "<\\375\\376\\005\\304\\200"
                      future_nested {
                        logical_name: "wrong"
                        direction: PORT_DIRECTION_TX_ONLY
                        resolved_mac_address: "\\000\\000\\000\\000\\000\\000"
                      }
                    }
                    """
                ),
                encoding="utf-8",
            )

            topology = parse_plan_topology(plan_file)

            self.assertEqual(len(topology.ports), 1)
            self.assertEqual(topology.ports[0].logical_name, "wan0")
            self.assertEqual(
                topology.ports[0].direction,
                "PORT_DIRECTION_RX_ONLY",
            )
            self.assertEqual(
                topology.ports[0].resolved_mac_address,
                "<\\375\\376\\005\\304\\200",
            )

    def test_plan_port_parser_treats_braces_inside_bytes_as_scalar_data(self):
        """Printable brace bytes must not alter generated pbtxt structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            plan_file = Path(tmpdir) / "plan.pbtxt"
            plan_file.write_text(
                dedent(
                    """
                    ports {
                      logical_port_id: 1
                      logical_name: "close_brace"
                      io_driver_instance_id: "io_udp_0"
                      driver_port_id: "close_brace"
                      direction: PORT_DIRECTION_RX_ONLY
                      resolved_mac_address: "\\002}ABCD"
                    }
                    ports {
                      logical_port_id: 2
                      logical_name: "open_brace"
                      io_driver_instance_id: "io_udp_0"
                      driver_port_id: "open_brace"
                      direction: PORT_DIRECTION_TX_ONLY
                      resolved_mac_address: "\\002{ABCD"
                    }
                    """
                ),
                encoding="utf-8",
            )

            topology = parse_plan_topology(plan_file)
            ports = {port.logical_name: port for port in topology.ports}

            self.assertEqual(
                decode_resolved_mac_address(
                    ports["close_brace"].resolved_mac_address
                ),
                "02:7d:41:42:43:44",
            )
            self.assertEqual(
                decode_resolved_mac_address(
                    ports["open_brace"].resolved_mac_address
                ),
                "02:7b:41:42:43:44",
            )

    def test_run_metadata_records_backend_identity(self):
        """Run metadata should record backend, driver, bindings, and port map."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = _profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_PCI)
            runtime_root = Path(tmpdir) / "runtime"
            validation_root = Path(tmpdir) / "private-kit"
            runtime_root.mkdir()
            validation_root.mkdir()
            release_metadata = {
                "source": str(runtime_root / "bin/kinetum-info"),
                "version": "0.1.0",
                "dpdk_version": "24.11.7",
                "tls_enabled": True,
                "build_features": {
                    "axiom_mlir_frontend": False,
                    "axiom_mlir_dialect": False,
                },
                "platform_capabilities": [
                    "coherent_runtime_telemetry",
                    "commit_confirmed",
                    "durable_guardrails",
                    "exact_bootstrap",
                    "ordered_epoch_transitions",
                    "owner_worker_module_health",
                    "selective_rollback",
                    "synchronous_active_stages",
                    "tracked_async_epoch_work",
                ],
            }
            config = DEPLOYMENT_SPECS[DeploymentMode.FAN_IN_EDGE_GATEWAY]
            test_config = ValidationConfig(
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                backend=backend,
                process=ProcessConfig(
                    runtime_root=runtime_root,
                    validation_root=validation_root,
                ),
                stream_topology=StreamTopologyProfile.RX_RSS_2,
                output_dir=Path(tmpdir),
                dry_run=True,
            )
            self.assertIs(config, test_config.spec)

            orch = ValidationOrchestrator(
                test_config, release_metadata=release_metadata
            )
            bundle_root = Path(tmpdir) / "bundle"
            plan_file = bundle_root / "configs" / "plan.pbtxt"
            plan_file.parent.mkdir(parents=True)
            plan_file.write_text(
                dedent(
                    """
                    ports {
                      logical_port_id: 1
                      logical_name: "wan0"
                      io_driver_instance_id: "io_dpdk_0"
                      driver_port_id: "wan0"
                      direction: PORT_DIRECTION_RX_ONLY
                      resolved_mac_address: "<\\375\\376\\005\\304\\200"
                    }
                    ports {
                      logical_port_id: 2
                      logical_name: "wan1"
                      io_driver_instance_id: "io_dpdk_0"
                      driver_port_id: "wan1"
                      direction: PORT_DIRECTION_RX_ONLY
                      resolved_mac_address: "<\\375\\376\\005\\304\\204"
                    }
                    ports {
                      logical_name: "lan0"
                      io_driver_instance_id: "io_dpdk_0"
                      driver_port_id: "lan0"
                      direction: PORT_DIRECTION_TX_ONLY
                      resolved_mac_address: "<\\375\\376\\005\\304\\202"
                    }
                    """
                ),
                encoding="utf-8",
            )
            orch._apply_resolved_plan_ports(plan_file)  # pylint: disable=protected-access
            orch._save_run_metadata(  # pylint: disable=protected-access
                plan_file, bundle_root, None
            )

            metadata = (Path(tmpdir) / "run_metadata.json").read_text(encoding="utf-8")
            self.assertIn('"backend": "dpdk_pci"', metadata)
            self.assertIn('"traffic_driver": "trex"', metadata)
            self.assertIn('"timestamp_source": "trex_port_stats"', metadata)
            self.assertIn('"rate_control_source": "trex_stl_rate_control"', metadata)
            self.assertIn('"latency_source": null', metadata)
            self.assertIn('"stream_topology": "rx_rss_2"', metadata)
            self.assertIn(f'"bundle_root": "{bundle_root}"', metadata)
            self.assertIn("fan_in_edge_gateway_cloudlab_d430_rx_rss_2_bindings.pbtxt", metadata)
            self.assertIn('"peer_iface": "enp6s0f1np1"', metadata)
            self.assertIn('"traffic_port_id": 2', metadata)
            self.assertIn('"traffic_role": "rx"', metadata)
            self.assertIn('"runtime_direction": "rx"', metadata)
            self.assertIn('"runtime_mac": "3c:fd:fe:05:c4:80"', metadata)
            self.assertIn('"build_features"', metadata)
            self.assertIn('"platform_capabilities"', metadata)
            self.assertIn('"traffic_endpoint"', metadata)
            self.assertIn('"trex_identity": null', metadata)

            payload = json.loads(metadata)
            validate_run_metadata(payload)
            self.assertEqual(payload["storage_profile"], "shared")
            for field, foreign in (
                ("storage_profile", "per_rx_queue"),
                ("stream_topology", "default"),
            ):
                malformed = copy.deepcopy(payload)
                malformed[field] = foreign
                with self.subTest(field=field), self.assertRaisesRegex(
                    JsonContractError, "binding differs"
                ):
                    validate_run_metadata(malformed)
            for overlapping_root in (str(runtime_root), str(runtime_root / "kit"), str(runtime_root.parent)):
                malformed = copy.deepcopy(payload)
                malformed["validation_root"] = overlapping_root
                with self.assertRaisesRegex(JsonContractError, "roots overlap"):
                    validate_run_metadata(malformed)
            live_payload = copy.deepcopy(payload)
            live_payload["dry_run"] = False
            live_payload["traffic_endpoint"]["host"] = "trex.example"
            live_payload["traffic_endpoint"]["trex_identity"] = {
                "version": "v3.06",
                "mode": "STL",
            }
            validate_run_metadata(live_payload)
            for malformed_identity in (
                None,
                {"version": "", "mode": "STL"},
                {"version": "v3.06", "mode": "ASTF"},
            ):
                malformed = copy.deepcopy(live_payload)
                malformed["traffic_endpoint"]["trex_identity"] = malformed_identity
                with self.assertRaises(JsonContractError):
                    validate_run_metadata(malformed)

            malformed = copy.deepcopy(live_payload)
            malformed["traffic_endpoint"]["trex_ports"] = [0]
            with self.assertRaisesRegex(JsonContractError, "override count"):
                validate_run_metadata(malformed)

            payload["ports"][1]["logical_name"] = payload["ports"][0][
                "logical_name"
            ]
            with self.assertRaises(JsonContractError):
                validate_run_metadata(payload)

            payload = json.loads(metadata)
            payload["timestamp_source"] = "kernel_af_packet"
            with self.assertRaisesRegex(JsonContractError, "evidence sources"):
                validate_run_metadata(payload)

            payload = json.loads(metadata)
            payload["latency_source"] = "trex_port_stats"
            with self.assertRaisesRegex(JsonContractError, "evidence sources"):
                validate_run_metadata(payload)

            payload = json.loads(metadata)
            payload["ports"][0]["peer_iface"] = "eth9"
            with self.assertRaisesRegex(JsonContractError, "port identity"):
                validate_run_metadata(payload)

            payload = json.loads(metadata)
            payload["ports"].pop()
            with self.assertRaisesRegex(JsonContractError, "port membership"):
                validate_run_metadata(payload)

            for malformed_root in ("//tmp/bundle", "/tmp/bundle\x00suffix"):
                payload = json.loads(metadata)
                payload["bundle_root"] = malformed_root
                payload["plan_file"] = f"{malformed_root}/configs/plan.pbtxt"
                with self.assertRaisesRegex(JsonContractError, "absolute path"):
                    validate_run_metadata(payload)

    def test_trex_mac_resolution_fails_closed_when_plan_lacks_rx_mac(self):
        """TRex evidence runs require resolved runtime MACs in plan.ports[]."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = _profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_PCI)
            test_config = ValidationConfig(
                process=TEST_PROCESS_CONFIG,
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                backend=backend,
                output_dir=Path(tmpdir),
            )
            plan_file = Path(tmpdir) / "plan.pbtxt"
            plan_file.write_text(
                dedent(
                    """
                    ports {
                      logical_name: "wan0"
                      io_driver_instance_id: "io_dpdk_0"
                      driver_port_id: "wan0"
                      direction: PORT_DIRECTION_RX_ONLY
                    }
                    """
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "missing resolved_mac_address",
            ):
                orch = ValidationOrchestrator(test_config)
                orch._apply_resolved_plan_ports(plan_file)  # pylint: disable=protected-access

    def test_trex_mac_resolution_rejects_non_six_byte_plan_fact(self):
        """The plan's resolved MAC must decode to exactly six bytes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = _profile_config(
                DeploymentMode.FAN_IN_EDGE_GATEWAY,
                BackendType.DPDK_PCI,
            )
            test_config = ValidationConfig(
                process=TEST_PROCESS_CONFIG,
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                backend=backend,
                output_dir=Path(tmpdir),
            )
            plan_file = Path(tmpdir) / "plan.pbtxt"
            plan_file.write_text(
                dedent(
                    """
                    ports {
                      logical_name: "wan0"
                      io_driver_instance_id: "io_dpdk_0"
                      driver_port_id: "wan0"
                      direction: PORT_DIRECTION_RX_ONLY
                      resolved_mac_address: "\\001\\002"
                    }
                    """
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "exactly 6 bytes"):
                orch = ValidationOrchestrator(test_config)
                orch._apply_resolved_plan_ports(plan_file)  # pylint: disable=protected-access

    def test_plan_direction_mismatch_fails_closed(self):
        """Traffic roles must be compatible with plan.ports[] directions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = _profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_PCI)
            test_config = ValidationConfig(
                process=TEST_PROCESS_CONFIG,
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                backend=backend,
                output_dir=Path(tmpdir),
            )
            plan_file = Path(tmpdir) / "plan.pbtxt"
            plan_file.write_text(
                dedent(
                    """
                    ports {
                      logical_name: "wan0"
                      io_driver_instance_id: "io_dpdk_0"
                      driver_port_id: "wan0"
                      direction: PORT_DIRECTION_TX_ONLY
                      resolved_mac_address: "<\\375\\376\\005\\304\\200"
                    }
                    """
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "traffic role does not match"):
                orch = ValidationOrchestrator(test_config)
                orch._apply_resolved_plan_ports(plan_file)  # pylint: disable=protected-access

    def test_dry_run_writes_test_results(self):
        """Dry-run success should still write the top-level result artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = _profile_config(DeploymentMode.FAN_IN_EDGE_GATEWAY, BackendType.DPDK_PCI)
            test_config = ValidationConfig(
                process=TEST_PROCESS_CONFIG,
                deployment=DeploymentMode.FAN_IN_EDGE_GATEWAY,
                backend=backend,
                output_dir=Path(tmpdir),
                dry_run=True,
            )

            result = asyncio.run(_DryRunOrchestrator(test_config).run())

            results_file = Path(tmpdir) / "test_results.json"
            self.assertTrue(result.all_passed)
            self.assertTrue(results_file.exists())
            payload = json.loads(results_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["backend"], "dpdk_pci")
            self.assertTrue(payload["dry_run"])
            self.assertTrue(payload["all_passed"])
