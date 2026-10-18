"""Router hardware catalog: every router model found in the sample configuration folders.

Routers are modular: onboard ports are fixed, the rest depends on what sits in each NIM/SPA/HWIC slot.  Only the onboard ports are
listed as port groups; every slot lists its naming pattern and, where a sample config showed a module in it, which module and ports.
"""

from __future__ import annotations

from .models import HardwareModel, ModuleSlot, PortGroup

C8200_DS = "https://www.cisco.com/c/en/us/products/collateral/routers/catalyst-8200-series-edge-platforms/nb-06-cat8200-series-edge-plat-ds-cte-en.html"
C8300_DS = "https://www.cisco.com/c/en/us/products/collateral/routers/catalyst-8300-series-edge-platforms/datasheet-c78-744088.html"
ISR4K_DS = "https://www.cisco.com/c/en/us/products/collateral/routers/4000-series-integrated-services-routers-isr/data_sheet-c78-732542.html"
ASR1K_DS = "https://www.cisco.com/c/en/us/products/collateral/routers/asr-1000-series-aggregation-services-routers/datasheet-c78-731632.html"
ISR3800_DS = "https://www.cisco.com/c/dam/en/us/products/collateral/routers/3800-series-integrated-services-routers-isr/product_data_sheet0900aecd8049beb7.pdf"

_JALIN = ("sample jalin switch router",)
_PANIN = ("sample panin switch router",)
_BOTH = _JALIN + _PANIN

_NIM_GENERIC = "Ethernet, voice, serial, cellular and switching NIMs"


def _gi(first: int, last: int, medium: str, note: str = "") -> PortGroup:
    return PortGroup("onboard", "GigabitEthernet", "0/0/{n}", first, last, "1G", medium, per_member=False, note=note)


_ISR_MGMT = PortGroup("mgmt", "GigabitEthernet", "{n}", 0, 0, "1G", "RJ45", per_member=False, note="Dedicated management port, in its own VRF (Mgmt-intf)")

ROUTER_MODELS: tuple[HardwareModel, ...] = (
    HardwareModel(
        key="C8200-1N-4T", vendor="Cisco", kind="router", platform="Catalyst 8200", os_name="IOS-XE",
        label="C8200-1N-4T (4x GE: 2 RJ45 + 2 SFP, 1 NIM, 1 PIM)",
        summary="Branch SD-WAN/IOS-XE edge, 8-core CPU. Onboard ports are GigabitEthernet0/0/0-3.",
        groups=(_gi(0, 3, "2x RJ45 + 2x SFP"),),
        slots=(
            ModuleSlot("NIM slot", "<type>0/<slot>/<port> (type follows the module; slot number per the hardware guide)", _NIM_GENERIC),
            ModuleSlot("PIM slot", "Cellular0/<slot>/<port>", "Pluggable cellular module"),
        ),
        detect=("C8200-1N-4T",), doc_title="Cisco Catalyst 8200 Series Edge Platforms Data Sheet", doc_url=C8200_DS, samples=_BOTH,
    ),
    HardwareModel(
        key="C8200L-1N-4T", vendor="Cisco", kind="router", platform="Catalyst 8200L", os_name="IOS-XE",
        label="C8200L-1N-4T (4x GE: 2 RJ45 + 2 SFP, 1 NIM, 1 PIM)",
        summary="Same port layout as the C8200, with a 4-core CPU and cloud-delivered security positioning.",
        groups=(_gi(0, 3, "2x RJ45 + 2x SFP"),),
        slots=(
            ModuleSlot("NIM slot", "<type>0/<slot>/<port> (type follows the module; slot number per the hardware guide)", _NIM_GENERIC),
            ModuleSlot("PIM slot", "Cellular0/<slot>/<port>", "Pluggable cellular module"),
        ),
        detect=("C8200L-1N-4T",), doc_title="Cisco Catalyst 8200 Series Edge Platforms Data Sheet", doc_url=C8200_DS, samples=_PANIN,
    ),
    HardwareModel(
        key="C8300-1N1S-6T", vendor="Cisco", kind="router", platform="Catalyst 8300", os_name="IOS-XE",
        label="C8300-1N1S-6T (6x GE onboard, 1 NIM, 1 SM, 1 PIM)",
        summary="1RU edge router: six embedded 1G Layer 3 ports (GigabitEthernet0/0/0-5), one NIM, one SM and one PIM slot.",
        groups=(_gi(0, 5, "RJ45 / SFP (see data sheet for the split)"),),
        slots=(
            ModuleSlot("NIM slot", "<type>0/<slot>/<port> (type follows the module; slot number per the hardware guide)", _NIM_GENERIC),
            ModuleSlot("SM slot", "type follows the module", "Single-wide service/switch modules (for example C-SM-16P4M2X)"),
        ),
        detect=("C8300-1N1S-6T",), doc_title="Cisco Catalyst 8300 Series Edge Platforms Data Sheet", doc_url=C8300_DS, samples=_PANIN,
    ),
    HardwareModel(
        key="ISR4431/K9", vendor="Cisco", kind="router", platform="ISR 4400", os_name="IOS-XE",
        label="ISR4431/K9 (4x GE onboard, 3 NIM slots)",
        summary="Four onboard 10/100/1000 ports (each an RJ-45 or SFP), three NIM slots, no SM-X slot. Management port is GigabitEthernet0.",
        groups=(_gi(0, 3, "4x RJ45 + 4x SFP (pairs share a port number)"), _ISR_MGMT),
        slots=(
            ModuleSlot("NIM slot 1", "GigabitEthernet0/1/<port>", _NIM_GENERIC, "NIM-ES2-4 (4x GE switch) -> GigabitEthernet0/1/0-3"),
            ModuleSlot("NIM slot 2", "GigabitEthernet0/2/<port>", _NIM_GENERIC),
            ModuleSlot("NIM slot 3", "GigabitEthernet0/3/<port>", _NIM_GENERIC),
        ),
        detect=("ISR4431/K9", "ISR4431"), doc_title="Cisco 4000 Family Integrated Services Router Data Sheet", doc_url=ISR4K_DS, samples=_PANIN,
    ),
    HardwareModel(
        key="ISR4331/K9", vendor="Cisco", kind="router", platform="ISR 4300", os_name="IOS-XE",
        label="ISR4331/K9 (3x GE onboard, 2 NIM slots, 1 SM-X slot)",
        summary="Three onboard 10/100/1000 ports (two RJ-45, two SFP, sharing port numbers), two NIM slots, one SM-X slot.",
        groups=(_gi(0, 2, "2x RJ45 + 2x SFP (pairs share a port number)"), _ISR_MGMT),
        slots=(
            ModuleSlot("NIM slot 1", "GigabitEthernet0/1/<port>", _NIM_GENERIC, "NIM-ES2-4 (4x GE switch) -> GigabitEthernet0/1/0-3"),
            ModuleSlot("NIM slot 2", "GigabitEthernet0/2/<port>", _NIM_GENERIC),
            ModuleSlot("SM-X slot", "type follows the module", "Enhanced service modules"),
        ),
        detect=("ISR4331/K9", "ISR4331"), doc_title="Cisco 4000 Family Integrated Services Router Data Sheet", doc_url=ISR4K_DS, samples=_PANIN,
    ),
    HardwareModel(
        key="ASR1002-X", vendor="Cisco", kind="router", platform="ASR 1000", os_name="IOS-XE",
        label="ASR1002-X (6x GE SFP built-in, 3 SPA bays)",
        summary="Six built-in Gigabit Ethernet SFP ports (GigabitEthernet0/0/0-5), three SPA bays on the integrated SIP, GigabitEthernet0 for management.",
        groups=(_gi(0, 5, "SFP"), _ISR_MGMT),
        slots=(
            ModuleSlot("SPA bays", "GigabitEthernet0/<bay>/<port>", "Shared port adapters", "SPA-8X1GE-V2 (8x GE) in bay 1 -> GigabitEthernet0/1/0-7"),
        ),
        detect=("ASR1002-X",), doc_title="Cisco ASR 1000 Series Aggregation Services Routers Data Sheet", doc_url=ASR1K_DS, samples=_PANIN,
    ),
    HardwareModel(
        key="CISCO3825", vendor="Cisco", kind="router", platform="3800 ISR", os_name="IOS",
        label="CISCO3825 (2x GE onboard, HWIC/NM slots)",
        summary="End-of-sale ISR. Onboard ports use two-part numbering (GigabitEthernet0/0, 0/1); HWIC ports use slot/subslot/port.",
        groups=(
            PortGroup("onboard", "GigabitEthernet", "0/{n}", 0, 1, "1G", "RJ45", per_member=False, note="Two-part numbering"),
        ),
        slots=(
            ModuleSlot("Slot 0 subslot 0", "Serial0/0/<port>", "HWIC / WIC / VWIC modules", "HWIC-4A/S (4x sync/async serial) -> Serial0/0/0-3"),
            ModuleSlot("Slot 0 subslot 1", "FastEthernet0/1/<port>", "HWIC / WIC / VWIC modules", "HWIC-4ESW (4-port FE switch) -> FastEthernet0/1/0-3"),
            ModuleSlot("Slot 0 subslot 2", "Serial0/2/<port>", "HWIC / WIC / VWIC modules", "HWIC-2T (2x serial) -> Serial0/2/0-1"),
            ModuleSlot("Slot 0 subslot 3", "Cellular0/3/<port>", "HWIC / WIC / VWIC modules", "HWIC-3G-GSM (3G WWAN) -> Cellular0/3/0"),
            ModuleSlot("Internal AIM", "no interface", "Hardware encryption", "AIM-VPN/SSL-3"),
        ),
        detect=("CISCO3825", "3825 CHASSIS"), doc_title="Cisco 3800 Series Integrated Services Routers Data Sheet", doc_url=ISR3800_DS, samples=_PANIN,
        notes=("Module-to-subslot assignments are read from the sample chassis inventory; your chassis may be populated differently.",),
    ),
)
