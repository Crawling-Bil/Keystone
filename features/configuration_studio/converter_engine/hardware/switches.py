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
CAT2960_PB = "https://www3-realm.cisco.com/en/US/prod/collateral/switches/ps5718/ps6406/prod_bulletin0900aecd80322c22.html"
CAT2960_LANBASE_DS = "https://www.cisco.com/c/dam/en_us/solutions/small-business/products/routers-switches/catalyst-2960-series-switches/C78-481303-01_2960-LAN_DS_v1a.pdf"
CAT2960PLUS_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-plus-series-switches/data_sheet_c78-728003.html"
CAT2960X_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/datasheet_c78-728232.html"
CAT3560X_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3560-x-series-switches/data_sheet_c78-584733.html"
CAT3650_DS = "https://www.cisco.com/c/en_in/products/collateral/switches/catalyst-3650-series-switches/datasheet-c78-729449.html"
ARUBA_2540_DS = "https://www.hpe.com/psnow/doc/c05278966"
HUAWEI_S5735_L_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5735-l-q-v2"
HUAWEI_S5735_S_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5735-s-v2"
HUAWEI_S5755_GE_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5755-h-gigabit"
HUAWEI_S5755_MGE_DS = "https://e.huawei.com/en/products/switches/campus-switches/s5755-h-multi-ge"
HUAWEI_S6730_25G_DS = "https://e.huawei.com/en/products/switches/campus-switches/s6730-h-v2-25g"

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
_TAM = ("sample tam switch huawei cisco",)
CAT9500_DS = "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/nb-06-cat9500-ser-data-sheet-cte-en.html"


def _nexus(key: str, ds_url: str, ds_title: str, copper: str, samples: tuple[str, ...], *, fibre: bool = False) -> HardwareModel:
    """A Nexus 9300 leaf: 48 access ports (RJ45 10GBASE-T, or SFP28 1/10/25G when ``fibre``) and 6 QSFP28 40/100G uplinks (``show module`` of the real switches
    prints ``48x1/10GT + 6x40G/100G`` for the 93108TC-FX and ``48x10/25G + 6x40/100G`` for the 93180YC-FX3)."""
    access = ("25G", "SFP28 (1/10/25G)") if fibre else ("10G", f"RJ45 ({copper})")
    return HardwareModel(
        key=key, vendor="Cisco", kind="switch", platform="Nexus 9300", os_name="NX-OS",
        label=f"{key} (48x {'1/10/25G SFP28' if fibre else copper} + 6x 40/100G QSFP28)",
        summary="Data-centre top-of-rack leaf. Ports are all named Ethernet1/<n>; the keyword never tells the speed, only the port number does.",
        groups=(
            PortGroup("access", "Ethernet", "1/{n}", 1, 48, access[0], access[1]),
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
    _nexus("N9K-C93180YC-EX", N9K_EX_DS, "Cisco N9300-EX Series Switches Data Sheet", "", _PANIN, fibre=True),
    _nexus("N9K-C93180YC-FX", N9K_FX_DS, "Cisco N9300-FX Series Switches Data Sheet", "", _PANIN, fibre=True),
    _nexus("N9K-C93180YC-FX3", N9K_FX3_DS, "Cisco N9300-FX3 Series Switches Data Sheet", "", ("sample diy nexus",), fibre=True),
    HardwareModel(
        key="WS-C2960-48TC-L", vendor="Cisco", kind="switch", platform="Catalyst 2960", os_name="IOS",
        label="WS-C2960-48TC-L (48x FE + 2x dual-purpose GE uplinks)",
        summary=("Fixed-configuration standalone switch. FastEthernet0/1-48 are the access ports; GigabitEthernet0/1-2 are the two dual-purpose uplinks "
                 "(10/100/1000BASE-T or SFP). The Fa and Gi ports are two separate ranges, so Fa0/1 and Gi0/1 are different ports."),
        groups=(
            PortGroup("access", "FastEthernet", "0/{n}", 1, 48, "100M", "RJ45"),
            PortGroup("uplink", "GigabitEthernet", "0/{n}", 1, 2, "1G", "RJ45 or SFP (dual-purpose)"),
        ),
        max_members=1, detect=("WS-C2960-48TC-L",), doc_title="Cisco Catalyst 2960 Series Switches, Product Bulletin No. 3041", doc_url=CAT2960_PB,
        target_ok=False, samples=_TAM,
        notes=("The bulletin describes the 2960 Series as fixed-configuration standalone switches; the IOS classic syntax of this platform is a source only.",),
    ),
    HardwareModel(
        key="WS-C2960-24TC-L", vendor="Cisco", kind="switch", platform="Catalyst 2960", os_name="IOS",
        label="WS-C2960-24TC-L (24x FE + 2x dual-purpose GE uplinks)",
        summary=("24 FastEthernet access ports FastEthernet0/1-24 and 2 dual-purpose uplinks GigabitEthernet0/1-2: each uplink has one 10/100/1000 copper port and one SFP "
                 "port, one of them active. The Fa and Gi ports are two separate ranges, so Fa0/1 and Gi0/1 are different ports."),
        groups=(
            PortGroup("access", "FastEthernet", "0/{n}", 1, 24, "100M", "RJ45"),
            PortGroup("uplink", "GigabitEthernet", "0/{n}", 1, 2, "1G", "RJ45 or SFP (dual-purpose)"),
        ),
        max_members=None, detect=("WS-C2960-24TC-L",), doc_title="Cisco Catalyst 2960 Series Switches with LAN Base Software (data sheet, Table 8)", doc_url=CAT2960_LANBASE_DS,
        target_ok=False, samples=_TAM,
        notes=("The data sheet does not mention stacking for this model; no stack limit is stated here.",),
    ),
    HardwareModel(
        key="WS-C2960+24TC-L", vendor="Cisco", kind="switch", platform="Catalyst 2960-Plus", os_name="IOS",
        label="WS-C2960+24TC-L (24x FE + 2x GE uplinks, SFP or 1000BASE-T)",
        summary=("24 FastEthernet access ports FastEthernet0/1-24 and 2 uplinks GigabitEthernet0/1-2 (SFP or 1000BASE-T). LAN Base, no PoE. "
                 "The Fa and Gi ports are two separate ranges, so Fa0/1 and Gi0/1 are different ports."),
        groups=(
            PortGroup("access", "FastEthernet", "0/{n}", 1, 24, "100M", "RJ45"),
            PortGroup("uplink", "GigabitEthernet", "0/{n}", 1, 2, "1G", "RJ45 or SFP (dual-purpose)"),
        ),
        max_members=None, detect=("WS-C2960+24TC-L",), doc_title="Cisco Catalyst 2960-Plus Series Switches Data Sheet (Table 14)", doc_url=CAT2960PLUS_DS,
        target_ok=False, samples=_TAM,
        notes=("The data sheet does not mention stacking; no stack limit is stated here.",),
    ),
    HardwareModel(
        key="WS-C2960X-24TS-L", vendor="Cisco", kind="switch", platform="Catalyst 2960-X", os_name="IOS",
        label="WS-C2960X-24TS-L (24x GE + 4x 1G SFP uplinks)",
        summary=("24 10/100/1000 ports and 4 fixed SFP uplinks, all in one numbering run: GigabitEthernet<member>/0/1-24 are copper, /25-28 are the SFP uplinks. "
                 "Optional FlexStack-Plus stacking, up to 8 members. FastEthernet0 is the out-of-band Ethernet management port."),
        groups=(
            PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 24, "1G", "RJ45"),
            PortGroup("uplink", "GigabitEthernet", "{m}/0/{n}", 25, 28, "1G", "SFP"),
            PortGroup("mgmt", "FastEthernet", "0", 0, 0, "100M", "RJ45", per_member=False, note="Management Ethernet port (FastEthernet0 stanza in the sample)"),
        ),
        max_members=8, detect=("WS-C2960X-24TS-L",), doc_title="Cisco Catalyst 2960-X and 2960-XR Series Switches Data Sheet", doc_url=CAT2960X_DS,
        target_ok=False, samples=_TAM,
    ),
    HardwareModel(
        key="WS-C3560X-24P", vendor="Cisco", kind="switch", platform="Catalyst 3560-X", os_name="IOS",
        label="WS-C3560X-24P (24x GE PoE+ + uplink network module)",
        summary=("Standalone switch (the 3560-X does not stack). 24 10/100/1000 PoE+ ports GigabitEthernet0/1-24; the uplink network module is slot 1: "
                 "C3KX-NM-1G gives 4 SFP ports (Gi1/1-4), C3KX-NM-10G gives 2 SFP+ and 2 SFP (Te1/1-2 or Gi1/1-2, and Gi1/3-4). FastEthernet0 is the management port."),
        groups=(
            PortGroup("access", "GigabitEthernet", "0/{n}", 1, 24, "1G", "RJ45", poe="PoE+"),
            PortGroup("uplink", "GigabitEthernet", "1/{n}", 1, 4, "1G", "SFP/SFP+ (network module)", aliases=("TenGigabitEthernet",),
                      note="One run of four module ports; with C3KX-NM-10G ports 1-2 are SFP+ and appear as TenGigabitEthernet1/1-2 at 10G"),
            PortGroup("mgmt", "FastEthernet", "0", 0, 0, "100M", "RJ45", per_member=False, note="Management Ethernet port"),
        ),
        max_members=1, detect=("WS-C3560X-24P", "WS-C3560X-24P-S"), doc_title="Cisco Catalyst 3750-X and 3560-X Series Switches Data Sheet", doc_url=CAT3560X_DS,
        target_ok=False, samples=_TAM,
    ),
    HardwareModel(
        key="WS-C3650-24TS", vendor="Cisco", kind="switch", platform="Catalyst 3650", os_name="IOS-XE",
        label="WS-C3650-24TS (24x GE + 4x 1G SFP uplinks)",
        summary="24 10/100/1000 ports (GigabitEthernet<m>/0/1-24) and 4 fixed SFP uplinks (GigabitEthernet<m>/1/1-4). StackWise-160, up to 9 members.",
        groups=(
            PortGroup("access", "GigabitEthernet", "{m}/0/{n}", 1, 24, "1G", "RJ45"),
            PortGroup("uplink", "GigabitEthernet", "{m}/1/{n}", 1, 4, "1G", "SFP"),
            _CAT_MGMT,
        ),
        max_members=9, detect=("WS-C3650-24TS", "WS-C3650-24TS-S", "WS-C3650-24TS-L", "WS-C3650-24TS-E"),
        doc_title="Cisco Catalyst 3650 Series Switches Data Sheet", doc_url=CAT3650_DS, target_ok=False, samples=_TAM,
    ),
    HardwareModel(
        key="JL356A", vendor="Aruba", kind="switch", platform="Switch 2540", os_name="ArubaOS-Switch",
        label="JL356A 2540-24G-PoE+-4SFP+ (24x GE PoE+ + 4x 1/10G SFP+)",
        summary="Fixed-port switch whose ports are plain numbers: 1-24 are 10/100/1000 PoE+, 25-28 are the SFP+ uplinks.",
        groups=(
            PortGroup("access", "", "{n}", 1, 24, "1G", "RJ45", poe="PoE+"),
            PortGroup("uplink", "", "{n}", 25, 28, "10G", "SFP+ (1G/10G)"),
        ),
        max_members=None, detect=("JL356A", "2540-24G-POE+-4SFP+"), doc_title="HPE Aruba Networking 2540 Switch Series", doc_url=ARUBA_2540_DS,
        target_ok=False, samples=_TAM,
        notes=("Stacking is not stated in the sources behind this catalog, so no member limit is enforced.",),
    ),
    HardwareModel(
        key="JL724B", vendor="Aruba", kind="switch", platform="CX 6200F", os_name="AOS-CX",
        label="JL724B CX 6200F 24G 4SFP+ (24x GE + 4x 1/10G SFP+)",
        summary="Fixed-port access switch. Ports are <member>/1/<port>: 1-24 RJ45, 25-28 SFP+. VSF members share the first number.",
        groups=(
            PortGroup("access", "", "{m}/1/{n}", 1, 24, "1G", "RJ45"),
            PortGroup("uplink", "", "{m}/1/{n}", 25, 28, "10G", "SFP/SFP+"),
            PortGroup("mgmt", "mgmt", "", 0, 0, "1G", "RJ45", per_member=False,
                      note="Out-of-band management port (interface mgmt); named for the 6200 series in the Fundamentals guide, confirm on the JL724B front panel"),
        ),
        max_members=8, detect=("JL724B", "6200F 24G 4SFP+"),
        doc_title="HPE Aruba Networking CX 6200 Switch Series data sheet", doc_url=ARUBA_6200_DS,
        target_ok=True, samples=_PANIN,
        notes=("VSF: up to 8 members for 6200F, fixed-port SKUs of the 6200 family can be mixed (AOS-CX Virtual Switching Framework Guide for 6200, 6300 Switch Series, edition 3, April 2023).",),
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
        target_ok=True, stack_ports=("GE{m}/0/21", "GE{m}/0/22"),
        notes=(_HUAWEI_STACK_NOTE,
               "In a real two-member stack of this model `display stack configuration` binds GE<m>/0/21 to Stack-Port<m>/1 and GE<m>/0/22 to Stack-Port<m>/2, with "
               "10GE<m>/0/5 and 10GE<m>/0/6 as the alternative stack media; `display dual-active` lists all four as ports that cannot be configured for detection. "
               "The converter therefore keeps data ports off GE<m>/0/21-22 of a stacked box."),
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
        # Four real 2-member core stacks (GTOPAS Makassar / Manado / Pekanbaru / Semarang, `display stack configuration`): Stack-Port<m>/1 =
        # 25GE<m>/0/3 and Stack-Port<m>/2 = 25GE<m>/0/4, ring, 10G links, every one of the eight ports with `device transceiver 10GBASE-COPPER`.
        stack_ports=("25GE{m}/0/3", "25GE{m}/0/4"), stack_transceiver="10GBASE-COPPER", stack_shares_bank=True,
        notes=(
            "A 40GE port can be split into 4x 10GE and a 100GE port into 4x 25GE (data sheet); split ports are not modelled.",
            "Stacked: the four deployed TAM core stacks bind 25GE<m>/0/3 and 25GE<m>/0/4 to Stack-Port<m>/1 and <m>/2 with 10G copper cables. "
            "The four 25GE cages are one rate bank (Huawei command reference, `port mode`): a GE optic on 25GE<m>/0/1 next to those 10G stack links "
            "cannot use `port mode GE`.",
        ),
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
    HardwareModel(
        key="S6730-H48Y6C-V2", vendor="Huawei", kind="switch", platform="CloudEngine S6730-H-V2", os_name="VRP",
        label="S6730-H48Y6C-V2 (48x 25GE SFP28 + 6x 100GE QSFP28)",
        summary="Fixed-port 25GE aggregation / data-centre-edge switch of the S6730-H-V2 family: 48 SFP28 ports and 6 QSFP28 ports. The closest like-for-like for a Nexus N9K-C93180YC-class switch (48x 25G + 6x 40/100G).",
        groups=(
            PortGroup("access", "25GE", "{m}/0/{n}", 1, 48, "25G", "SFP28 (25GE)"),
            PortGroup("uplink", "100GE", "{m}/0/{n}", 1, 6, "100G", "QSFP28 (100GE)", aliases=("40GE",)),
            _HUAWEI_MGMT,
        ),
        max_members=1, detect=("S6730-H48Y6C",),
        doc_title="Huawei CloudEngine S6730-H-V2 Series 25 GE Switches", doc_url=HUAWEI_S6730_25G_DS,
        target_ok=True,
        notes=(
            "Port counts (48x 25GE, 6x 100GE) are from the Huawei product page; the page does not state the lower speeds. The older S6730-H28Y4C hardware description "
            "lists its SFP28 ports as 1/10/25GE and its QSFP28 ports as 40/100GE, but that is a different model, so 1G/10G and 40G optics here are not assumed.",
            "Stacking is not modelled (not confirmed for this model). The translator emits V600R025C00 syntax; the first conversion for this model has not been run on a deployed device.",
        ),
    ),
)
