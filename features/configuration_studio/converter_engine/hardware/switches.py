"""Switch hardware catalog: every switch model found in the sample configuration folders.

Port counts, speeds and stacking limits come from the vendor data sheets linked on each entry.  Anything a data sheet does not state
is left out (``max_members=None``) rather than guessed.
"""

from __future__ import annotations

from .models import HardwareModel, PortGroup, UplinkModule

CAT9300_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html"
CAT9200_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html"
N9K_EX_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-742283.html"
N9K_FX_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-742284.html"
N9K_FX3_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/datasheet-c78-744052.html"
ARUBA_6200_DS = "https://www.hpe.com/psnow/doc/a00097415enw"
HUAWEI_S5735_L_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5735-l-q-v2"
HUAWEI_S5735_S_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5735-s-v2"
HUAWEI_S5755_GE_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5755-h-gigabit"
HUAWEI_S5755_MGE_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5755-h-multi-ge"

# IOS-XE management port: one per box (the active member), flat "0/0" numbering.
_CAT_MGMT = PortGroup("mgmt", "GigabitEthernet", "0/0", 0, 0, "1G", "RJ45", per_member=False, note="Out-of-band management port")

# Huawei VRP names a fixed-port CloudEngine port <type><unit>/0/<port> (unit = stack member).  The project's real drafted devices write
# the abbreviated form (GE1/0/1, 10GE1/0/1); older releases print GigabitEthernet / XGigabitEthernet for the same ports, so those are
# accepted as aliases when a Huawei config is the source.  MEth0/0/0 is the management port named in the V600R025C00 stack guide.
_HUAWEI_MGMT = PortGroup(
    "mgmt", "MEth", "0/0/{n}", 0, 0, "1G", "RJ45", per_member=False,
    note="Management port as named in the Huawei stack guide; the front-panel pictures do not show it, so confirm on the rear panel",
)
_HUAWEI_STACK_NOTE = (
    "The two extra SFP+ cages next to the uplinks are marked 10G[STACK] on the front panel (data sheet: 2 x 12GE dedicated stack ports). "
    "Their interface numbering is not stated in the sources behind this catalog, so no port is mapped onto them."
)

UPLINK_MODULES: dict[str, UplinkModule] = {
    "C9300-NM-8X": UplinkModule("C9300-NM-8X", "8x 10G/1G SFP/SFP+", 8, "10G", ("TenGigabitEthernet", "GigabitEthernet"), "SFP/SFP+"),
    "C9300-NM-4M": UplinkModule(
        "C9300-NM-4M", "4x Multigigabit RJ45", 4, "mGig",
        ("GigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet", "TenGigabitEthernet"), "RJ45 (mGig)",
        note="Ports are named after the negotiated speed; a link-down port is shown as GigabitEthernet",
    ),
    "C9300X-NM-8Y": UplinkModule("C9300X-NM-8Y", "8x 25G/10G/1G SFP28", 8, "25G", ("TwentyFiveGigE", "TenGigabitEthernet", "GigabitEthernet"), "SFP28"),
    "C9300X-NM-8M": UplinkModule(
        "C9300X-NM-8M", "8x 10G/1G Multigigabit RJ45", 8, "mGig",
        ("TenGigabitEthernet", "GigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet"), "RJ45 (mGig)",
    ),
    "C9300X-NM-2C": UplinkModule("C9300X-NM-2C", "2x 100G/40G QSFP28", 2, "100G", ("HundredGigE", "FortyGigabitEthernet"), "QSFP28"),
    "C9300X-NM-4C": UplinkModule("C9300X-NM-4C", "4x 100G/40G QSFP28", 4, "100G", ("HundredGigE", "FortyGigabitEthernet"), "QSFP28"),
}

_CLASSIC_MODULES = ("C9300-NM-8X", "C9300-NM-4M")
_X_MODULES = ("C9300X-NM-8Y", "C9300X-NM-8M", "C9300X-NM-2C", "C9300X-NM-4C")

_SAMPLES_BOTH = ("sample jalin switch router", "sample panin switch router")
_JALIN = ("sample jalin switch router",)
_PANIN = ("sample panin switch router",)
_OJK = ("sample ojk switch",)
CAT9500_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/nb-06-cat9500-ser-data-sheet-cte-en.html"


def _nexus(key: str, ds_url: str, ds_title: str, copper: str, samples: tuple[str, ...]) -> HardwareModel:
    return HardwareModel(
        key=key, vendor="Cisco", kind="switch", platform="Nexus 9300", os_name="NX-OS",
        label=f"{key} (48x {copper} + 6x 40/100G QSFP28)",
        summary="Data-centre top-of-rack leaf. Ports are all named Ethernet1/<n>; the keyword never tells the speed, only the port number does.",
        groups=(
            PortGroup("access", "Ethernet", "1/{n}", 1, 48, "10G", f"RJ45 ({copper})"),
            PortGroup("uplink", "Ethernet", "1/{n}", 49, 54, "100G", "QSFP28 (40G/100G)"),
            PortGroup("mgmt", "mgmt", "{n}", 0, 0, "1G", "RJ45", per_member=False, note="mgmt0, VRF management"),
        ),
        max_members=1,
        detect=(key.replace("N9K-C", "N9K-C"), key.replace("N9K-C", "N")),
        doc_title=ds_title, doc_url=ds_url, target_ok=False, samples=samples,
        notes=("NX-OS syntax is not generated by the converter, so this model is a source/reference only.",),
    )


SWITCH_MODELS: tuple[HardwareModel, ...] = (
    HardwareModel(
        key="C9300X-24Y", vendor="Cisco", kind="switch", platform="Catalyst 9300X", os_name="IOS-XE",
        label="C9300X-24Y (24x 25G SFP28 + uplink module)",
        summary="Fixed 24x 25G/10G/1G SFP28 front ports; uplinks are modular (slot 1). StackWise-480, up to 8 members.",
        groups=(PortGroup("access", "TwentyFiveGigE", "{m}/0/{n}", 1, 24, "25G", "SFP28"), _CAT_MGMT),
        modules=_X_MODULES, default_module="C9300X-NM-8Y", max_members=8,
        detect=("C9300X-24Y",), doc_title="Cisco Catalyst 9300 Series Switches Data Sheet", doc_url=CAT9300_DS,
        target_ok=True, samples=_JALIN,
    ),
    HardwareModel(
        key="C9300X-48TX", vendor="Cisco", kind="switch", platform="Catalyst 9300X", os_name="IOS-XE",
        label="C9300X-48TX (48x mGig RJ45 + uplink module)",
        summary="48 Multigigabit ports (10G/5G/2.5G/1G/100M, named TenGigabitEthernet); uplinks are modular (slot 1).",
        groups=(PortGroup("access", "TenGigabitEthernet", "{m}/0/{n}", 1, 48, "mGig", "RJ45 (mGig)", aliases=()), _CAT_MGMT),
        modules=_X_MODULES, default_module="C9300X-NM-8M", max_members=8,
        detect=("C9300X-48TX",), doc_title="Cisco Catalyst 9300 Series Switches Data Sheet", doc_url=CAT9300_DS,
        target_ok=True, samples=_PANIN,
    ),
    HardwareModel(
        key="C9300-48P", vendor="Cisco", kind="switch", platform="Catalyst 9300", os_name="IOS-XE",
        label="C9300-48P (48x GE PoE+ + uplink module)",
        summary="48x 10/100/1000 PoE+ ports; uplinks are modular (slot 1). StackWise-480, up to 8 members.",
        groups=(PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 48, "1G", "RJ45", poe="PoE+"), _CAT_MGMT),
        modules=_CLASSIC_MODULES, default_module="C9300-NM-8X", max_members=8,
        detect=("C9300-48P",), doc_title="Cisco Catalyst 9300 Series Switches Data Sheet", doc_url=CAT9300_DS,
        target_ok=True, samples=_JALIN,
    ),
    HardwareModel(
        key="C9300-48T", vendor="Cisco", kind="switch", platform="Catalyst 9300", os_name="IOS-XE",
        label="C9300-48T (48x GE + uplink module)",
        summary="48x 10/100/1000 data ports (no PoE); uplinks are modular (slot 1).",
        groups=(PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 48, "1G", "RJ45"), _CAT_MGMT),
        modules=_CLASSIC_MODULES, default_module="C9300-NM-4M", max_members=8,
        detect=("C9300-48T",), doc_title="Cisco Catalyst 9300 Series Switches Data Sheet", doc_url=CAT9300_DS,
        target_ok=True, samples=_PANIN,
    ),
    HardwareModel(
        key="C9300L-48P-4X", vendor="Cisco", kind="switch", platform="Catalyst 9300L", os_name="IOS-XE",
        label="C9300L-48P-4X (48x GE PoE+ + 4x 1/10G SFP+ fixed)",
        summary="Fixed 4x 10G/1G uplinks (slot 1, not modular). StackWise-320 with the C9300L-STACK-KIT, up to 8 members.",
        groups=(
            PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 48, "1G", "RJ45", poe="PoE+"),
            PortGroup("uplink", "TenGigabitEthernet", "{m}/1/{n}", 1, 4, "10G", "SFP/SFP+", aliases=("GigabitEthernet",)),
            _CAT_MGMT,
        ),
        max_members=8, detect=("C9300L-48P-4X",), doc_title="Cisco Catalyst 9300 Series Switches Data Sheet (9300L)", doc_url=CAT9300_DS,
        target_ok=True, samples=_OJK,
    ),
    HardwareModel(
        key="C9300L-48T-4X", vendor="Cisco", kind="switch", platform="Catalyst 9300L", os_name="IOS-XE",
        label="C9300L-48T-4X (48x GE + 4x 1/10G SFP+ fixed)",
        summary="48 data ports (no PoE) and fixed 4x 10G/1G uplinks (slot 1, not modular). StackWise-320, up to 8 members.",
        groups=(
            PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 48, "1G", "RJ45"),
            PortGroup("uplink", "TenGigabitEthernet", "{m}/1/{n}", 1, 4, "10G", "SFP/SFP+", aliases=("GigabitEthernet",)),
            _CAT_MGMT,
        ),
        max_members=8, detect=("C9300L-48T-4X",), doc_title="Cisco Catalyst 9300 Series Switches Data Sheet (9300L)", doc_url=CAT9300_DS,
        target_ok=True, samples=_OJK,
    ),
    HardwareModel(
        key="C9500-48Y4C", vendor="Cisco", kind="switch", platform="Catalyst 9500", os_name="IOS-XE",
        label="C9500-48Y4C (48x 1/10/25G SFP28 + 4x 40/100G)",
        summary=("Fixed 48x 1/10/25G SFP28 and 4x 40/100G uplinks, all in slot 0 (ports 49-52 are the uplinks). Pairs run StackWise Virtual: the OJK sample is a "
                 "two-switch pair, so ports are 1/0/<n> and 2/0/<n>."),
        groups=(
            PortGroup("access", "TwentyFiveGigE", "{m}/0/{n}", 1, 48, "25G", "SFP28", aliases=("TenGigabitEthernet", "GigabitEthernet")),
            PortGroup("uplink", "HundredGigE", "{m}/0/{n}", 49, 52, "100G", "QSFP28", aliases=("FortyGigabitEthernet",)),
            _CAT_MGMT,
        ),
        max_members=None, detect=("C9500-48Y4C",), doc_title="Cisco Catalyst 9500 Series Switches Data Sheet", doc_url=CAT9500_DS,
        target_ok=False, samples=_OJK,
    ),
    HardwareModel(
        key="C9200L-24P-4X", vendor="Cisco", kind="switch", platform="Catalyst 9200L", os_name="IOS-XE",
        label="C9200L-24P-4X (24x GE PoE+ + 4x 1/10G SFP+)",
        summary="Fixed 4x 1G/10G uplinks (slot 1, not modular). StackWise-80, up to 8 members, C9200L only.",
        groups=(
            PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 24, "1G", "RJ45", poe="PoE+"),
            PortGroup("uplink", "TenGigabitEthernet", "{m}/1/{n}", 1, 4, "10G", "SFP/SFP+", aliases=("GigabitEthernet",)),
            _CAT_MGMT,
        ),
        max_members=8, detect=("C9200L-24P-4X",), doc_title="Cisco Catalyst 9200 Series Switches Data Sheet", doc_url=CAT9200_DS,
        target_ok=True, samples=_JALIN,
    ),
    HardwareModel(
        key="C9200L-48P-4X", vendor="Cisco", kind="switch", platform="Catalyst 9200L", os_name="IOS-XE",
        label="C9200L-48P-4X (48x GE PoE+ + 4x 1/10G SFP+)",
        summary="Fixed 4x 1G/10G uplinks (slot 1, not modular). StackWise-80, up to 8 members, C9200L only.",
        groups=(
            PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 48, "1G", "RJ45", poe="PoE+"),
            PortGroup("uplink", "TenGigabitEthernet", "{m}/1/{n}", 1, 4, "10G", "SFP/SFP+", aliases=("GigabitEthernet",)),
            _CAT_MGMT,
        ),
        max_members=8, detect=("C9200L-48P-4X",), doc_title="Cisco Catalyst 9200 Series Switches Data Sheet", doc_url=CAT9200_DS,
        target_ok=True, samples=_JALIN,
    ),
    _nexus("N9K-C93108TC-EX", N9K_EX_DS, "Cisco N9300-EX Series Switches Data Sheet", "100M/1G/10G BASE-T", _PANIN),
    _nexus("N9K-C93108TC-FX", N9K_FX_DS, "Cisco N9300-FX Series Switches Data Sheet", "100M/1G/10G BASE-T", _PANIN),
    _nexus("N9K-C93108TC-FX3", N9K_FX3_DS, "Cisco N9300-FX3 Series Switches Data Sheet", "100M/1G/10G BASE-T", _PANIN),
    HardwareModel(
        key="JL724B", vendor="Aruba", kind="switch", platform="CX 6200F", os_name="AOS-CX",
        label="JL724B CX 6200F 24G 4SFP+ (24x GE + 4x 1/10G SFP+)",
        summary="Fixed-port access switch. Ports are <member>/1/<port>: 1-24 RJ45, 25-28 SFP+. VSF members share the first number.",
        groups=(
            PortGroup("access", "", "{m}/1/{n}", 1, 24, "1G", "RJ45"),
            PortGroup("uplink", "", "{m}/1/{n}", 25, 28, "10G", "SFP/SFP+"),
        ),
        max_members=None, detect=("JL724B", "6200F 24G 4SFP+"),
        doc_title="HPE Aruba Networking CX 6200 Switch Series data sheet", doc_url=ARUBA_6200_DS,
        target_ok=True, samples=_PANIN,
        notes=("The VSF member limit is not stated in the linked data sheet text this catalog was built from, so it is not enforced.",),
    ),
    HardwareModel(
        key="S5735-L8T4X-QA-V2", vendor="Huawei", kind="switch", platform="CloudEngine S5735-L-Q-V2", os_name="VRP",
        label="S5735-L8T4X-QA-V2 (8x GE + 4x 10GE SFP+)",
        summary="Compact fixed-port access switch: 8 copper GE ports and 4 SFP+ cages (10G/1G), no PoE, console on the front panel.",
        groups=(
            PortGroup("access", "GE", "{m}/0/{n}", 1, 8, "1G", "RJ45", aliases=("GigabitEthernet",)),
            PortGroup("uplink", "10GE", "{m}/0/{n}", 1, 4, "10G", "SFP+ (10G/1G)", aliases=("XGigabitEthernet",)),
            _HUAWEI_MGMT,
        ),
        max_members=None, detect=("S5735-L8T4X-QA-V2",),
        doc_title="Huawei CloudEngine S5735-L-Q-V2 Series Switches", doc_url=HUAWEI_S5735_L_DS,
        target_ok=True,
        notes=("The Huawei brochure states that the series supports iStack but gives no member limit for this model, so none is enforced.",),
    ),
    HardwareModel(
        key="S5735-S24T4XE-V2", vendor="Huawei", kind="switch", platform="CloudEngine S5735-S-V2", os_name="VRP",
        label="S5735-S24T4XE-V2 (24x GE + 4x 10GE SFP+)",
        summary="Fixed-port access switch: 24 copper GE ports, 4 SFP+ uplinks (10G/1G) and 2 dedicated stack ports. iStack, up to 9 members.",
        groups=(
            PortGroup("access", "GE", "{m}/0/{n}", 1, 24, "1G", "RJ45", aliases=("GigabitEthernet",)),
            PortGroup("uplink", "10GE", "{m}/0/{n}", 1, 4, "10G", "SFP+ (10G/1G)", aliases=("XGigabitEthernet",)),
            _HUAWEI_MGMT,
        ),
        max_members=9, detect=("S5735-S24T4XE-V2",),
        doc_title="Huawei CloudEngine S5735-S-V2 Series Switches", doc_url=HUAWEI_S5735_S_DS,
        target_ok=True, notes=(_HUAWEI_STACK_NOTE,),
    ),
    HardwareModel(
        key="S5735-S24P4XE-V2", vendor="Huawei", kind="switch", platform="CloudEngine S5735-S-V2", os_name="VRP",
        label="S5735-S24P4XE-V2 (24x GE PoE+ + 4x 10GE SFP+)",
        summary="PoE+ variant of the S5735-S24T4XE-V2: 24 copper GE PoE+ ports, 4 SFP+ uplinks (10G/1G), 2 dedicated stack ports. iStack, up to 9 members.",
        groups=(
            PortGroup("access", "GE", "{m}/0/{n}", 1, 24, "1G", "RJ45", poe="PoE+", aliases=("GigabitEthernet",)),
            PortGroup("uplink", "10GE", "{m}/0/{n}", 1, 4, "10G", "SFP+ (10G/1G)", aliases=("XGigabitEthernet",)),
            _HUAWEI_MGMT,
        ),
        max_members=9, detect=("S5735-S24P4XE-V2",),
        doc_title="Huawei CloudEngine S5735-S-V2 Series Switches", doc_url=HUAWEI_S5735_S_DS,
        target_ok=True, notes=(_HUAWEI_STACK_NOTE,),
    ),
    HardwareModel(
        key="S5735-S48T4XE-V2", vendor="Huawei", kind="switch", platform="CloudEngine S5735-S-V2", os_name="VRP",
        label="S5735-S48T4XE-V2 (48x GE + 4x 10GE SFP+)",
        summary="Fixed-port access switch: 48 copper GE ports, 4 SFP+ uplinks (10G/1G) and 2 dedicated stack ports. iStack, up to 9 members.",
        groups=(
            PortGroup("access", "GE", "{m}/0/{n}", 1, 48, "1G", "RJ45", aliases=("GigabitEthernet",)),
            PortGroup("uplink", "10GE", "{m}/0/{n}", 1, 4, "10G", "SFP+ (10G/1G)", aliases=("XGigabitEthernet",)),
            _HUAWEI_MGMT,
        ),
        max_members=9, detect=("S5735-S48T4XE-V2",),
        doc_title="Huawei CloudEngine S5735-S-V2 Series Switches", doc_url=HUAWEI_S5735_S_DS,
        target_ok=True, notes=(_HUAWEI_STACK_NOTE,),
    ),
    HardwareModel(
        key="S5755-H24T4Y2CZ", vendor="Huawei", kind="switch", platform="CloudEngine S5755-H", os_name="VRP",
        label="S5755-H24T4Y2CZ (24x GE + 4x 25GE SFP28 + 2x 100GE QSFP28)",
        summary="Fixed-port access/aggregation switch: 24 copper GE ports, 4 SFP28 (1/10/25GE) and 2 QSFP28 (40/100GE). iStack, up to 9 members; every port can serve as a stack port.",
        groups=(
            PortGroup("access", "GE", "{m}/0/{n}", 1, 24, "1G", "RJ45", aliases=("GigabitEthernet",)),
            PortGroup("uplink", "25GE", "{m}/0/{n}", 1, 4, "25G", "SFP28 (1/10/25GE)"),
            PortGroup("uplink", "100GE", "{m}/0/{n}", 1, 2, "100G", "QSFP28 (40/100GE)", aliases=("40GE",)),
            _HUAWEI_MGMT,
        ),
        max_members=9, detect=("S5755-H24T4Y2CZ",),
        doc_title="Huawei CloudEngine S5755-H Series High-Quality Gigabit Switches", doc_url=HUAWEI_S5755_GE_DS,
        target_ok=True,
        notes=("A 40GE port can be split into 4x 10GE and a 100GE port into 4x 25GE (data sheet); split ports are not modelled.",),
    ),
    HardwareModel(
        key="S5755-H48UM4Y2CZ", vendor="Huawei", kind="switch", platform="CloudEngine S5755-H", os_name="VRP",
        label="S5755-H48UM4Y2CZ (48x Multi-GE PoE++ + 4x 25GE SFP28 + 2x 100GE QSFP28)",
        summary="Multi-GE access switch: 48 copper ports (100M/1G/2.5G/5G/10G BASE-T) with 90 W PoE++, 4 SFP28 (1/10/25GE) and 2 QSFP28 (40/100GE). iStack, up to 9 members.",
        groups=(
            PortGroup("access", "MultiGE", "{m}/0/{n}", 1, 48, "mGig", "RJ45 (Multi-GE)", poe="PoE++ (90 W)",
                      note="Every port runs 10M-2.5G by default; 5G/10G needs an RTU licence per 12 ports (data sheet)"),
            PortGroup("uplink", "25GE", "{m}/0/{n}", 1, 4, "25G", "SFP28 (1/10/25GE)"),
            PortGroup("uplink", "100GE", "{m}/0/{n}", 1, 2, "100G", "QSFP28 (40/100GE)", aliases=("40GE",)),
            _HUAWEI_MGMT,
        ),
        max_members=9, detect=("S5755-H48UM4Y2CZ",),
        doc_title="Huawei CloudEngine S5755-H Series High-Quality Multi-GE Switches", doc_url=HUAWEI_S5755_MGE_DS,
        target_ok=True,
        notes=("A 40GE port can be split into 4x 10GE and a 100GE port into 4x 25GE (data sheet); split ports are not modelled.",),
    ),
)
