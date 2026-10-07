"""Two-node Kinetum fan-in edge gateway PCI evaluation profile.

Topology only:
  - dut: control plane and data plane under test
  - trex: peer traffic host for fan-in validation

No private source, install service, custom image, or repository is attached.
Use SSH/rsync after instantiation for private setup.

This profile requests three or four experiment links, depending on hardware:
  - fan_in_wan0: trex -> dut ingress candidate
  - fan_in_wan1: trex -> dut ingress candidate
  - fan_in_lan0: dut -> trex egress candidate
  - trex_fixture0: optional spare/fixture link for traffic generators that
    require an even number of ports

The links are symmetric Ethernet links; the names document Kinetum's intended
traffic roles and do not force packet direction.
"""

# CloudLab provides the geni modules inside the profile execution sandbox.
# pylint: disable=consider-using-f-string,import-error,no-name-in-module

from geni import portal
from geni.rspec import emulab as _emulab  # noqa: F401 pylint: disable=unused-import
from geni.rspec import pg


UBUNTU24 = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU24-64-STD"

HARDWARE_CHOICES = [
    (
        "d430",
        "Utah d430: 4-link candidate, 4x Intel X710/XL710 10G on selected nodes",
        [10000000, 10000000, 10000000, 10000000],
    ),
    (
        "d6515",
        "Utah d6515: proven 3-link, 2x100G ConnectX-5 + 1x25G Broadcom 57414",
        [100000000, 100000000, 25000000],
    ),
    (
        "d750",
        "Utah d750: 3x25G Broadcom BCM57504; restricted availability",
        [25000000, 25000000, 25000000],
    ),
    (
        "sm220u",
        "Wisconsin sm220u: empirical 3-link, 2x100G ConnectX-6 DX + CX6 LX present",
        [100000000, 100000000, 100000000],
    ),
    (
        "r7525",
        "Clemson r7525: empirical 3-link, 2x100G BlueField2 + 1x25G ConnectX-5",
        [100000000, 100000000, 25000000],
    ),
]

HARDWARE = {}
for hardware_name, hardware_label, hardware_link_bandwidth_kbps in HARDWARE_CHOICES:
    HARDWARE[hardware_name] = {
        "label": hardware_label,
        "link_bandwidth_kbps": hardware_link_bandwidth_kbps,
    }

LINK_SPECS = [
    {
        "name": "fan_in_wan0",
        "dut_iface": "dut_wan0",
        "trex_iface": "trex_wan0",
        "dut_ip": "10.10.1.2",
        "trex_ip": "10.10.1.1",
    },
    {
        "name": "fan_in_wan1",
        "dut_iface": "dut_wan1",
        "trex_iface": "trex_wan1",
        "dut_ip": "10.10.2.2",
        "trex_ip": "10.10.2.1",
    },
    {
        "name": "fan_in_lan0",
        "dut_iface": "dut_lan0",
        "trex_iface": "trex_lan0",
        "dut_ip": "10.10.3.1",
        "trex_ip": "10.10.3.2",
    },
    {
        "name": "trex_fixture0",
        "dut_iface": "dut_fixture0",
        "trex_iface": "trex_fixture0",
        "dut_ip": "10.10.4.2",
        "trex_ip": "10.10.4.1",
    },
]

NETMASK = "255.255.255.0"
LINK_KIND_CHOICES = [
    ("switched", "Regular CloudLab experiment-network link"),
    ("l1", "Layer-1 link, if supported by the selected hardware/topology"),
]

pc = portal.context

pc.defineParameter(
    "hw_type",
    "Hardware type",
    portal.ParameterType.NODETYPE,
    "d430",
    [
        (hardware_name, hardware_label)
        for hardware_name, hardware_label, hardware_link_bandwidth_kbps in HARDWARE_CHOICES
    ],
)

pc.defineParameter(
    "os_image",
    "OS image",
    portal.ParameterType.IMAGE,
    UBUNTU24,
    [(UBUNTU24, "Ubuntu 24.04 LTS stock CloudLab image")],
)

pc.defineParameter(
    "link_kind",
    "Experiment link type",
    portal.ParameterType.STRING,
    "switched",
    LINK_KIND_CHOICES,
)

params = pc.bindParameters()

if params.hw_type not in HARDWARE:
    pc.reportError(
        portal.ParameterError(
            "Unsupported hardware type: %s" % params.hw_type,
            ["hw_type"],
        )
    )

if params.link_kind not in [choice_name for choice_name, choice_label in LINK_KIND_CHOICES]:
    pc.reportError(
        portal.ParameterError(
            "link_kind must be either 'switched' or 'l1'",
            ["link_kind"],
        )
    )

requested_link_count = len(HARDWARE[params.hw_type]["link_bandwidth_kbps"])
if requested_link_count < 3 or requested_link_count > len(LINK_SPECS):
    pc.reportError(
        portal.ParameterError(
            "Hardware type %s defines an unsupported experiment-link count"
            % params.hw_type,
            ["hw_type"],
        )
    )

pc.verifyParameters()

request = pc.makeRequestRSpec()


def make_experiment_link(link_name, bandwidth_kbps):
    """Create a CloudLab experiment link from the selected link policy."""
    if params.link_kind == "l1":
        return request.L1Link(link_name)

    created_link = request.Link(link_name)
    created_link.setProperties(bandwidth=bandwidth_kbps)
    return created_link


dut = request.RawPC("dut")
trex = request.RawPC("trex")

dut.hardware_type = params.hw_type
trex.hardware_type = params.hw_type

dut.disk_image = params.os_image
trex.disk_image = params.os_image

link_bandwidths = HARDWARE[params.hw_type]["link_bandwidth_kbps"]
active_link_specs = LINK_SPECS[:requested_link_count]

for index, link_spec in enumerate(active_link_specs):
    dut_iface = dut.addInterface(link_spec["dut_iface"])
    dut_iface.addAddress(pg.IPv4Address(link_spec["dut_ip"], NETMASK))

    trex_iface = trex.addInterface(link_spec["trex_iface"])
    trex_iface.addAddress(pg.IPv4Address(link_spec["trex_ip"], NETMASK))

    profile_link = make_experiment_link(link_spec["name"], link_bandwidths[index])
    profile_link.addInterface(trex_iface)
    profile_link.addInterface(dut_iface)

pc.printRequestRSpec(request)
