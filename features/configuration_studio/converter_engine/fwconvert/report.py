"""The loss report: one line for every construct that was not copied exactly, with the layer, what happened, why and where to read about it."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

STATUS_ORDER = ("converted", "approximated", "review", "not_converted")
STATUS_LABEL = {"converted": "Converted", "approximated": "Approximated", "review": "Needs review", "not_converted": "Not converted"}

DOC = {
    "pan_nat": "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview",
    "pan_ipsec": "https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/vpns/set-up-site-to-site-vpn/set-up-ipsec/set-up-an-ipsec-tunnel",
    "pan_ike": "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/vpns/set-up-site-to-site-vpn/set-up-an-ike-gateway",
    "pan_proxy_id": "https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/get-started-with-ipsec-vpn-site-to-site/site-to-site-vpn-overview/proxy-id-for-ipsec-vpn",
    "pan_admin": "https://docs.paloaltonetworks.com/pan-os",
    "forti_cli": "https://docs.fortinet.com/product/fortigate/",
    "forti_central_snat": "https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/421028",
    "forti_vip": "https://docs.fortinet.com/document/fortigate/6.2.2/cookbook/155333",
    "forti_vip_lookup": "https://community.fortinet.com/fortigate-3/technical-tip-how-fortios-handles-vip-lookup-183426",
    "forti_central_snat_cli": "https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/308620/config-firewall-central-snat-map",
    "forti_phase2": "https://docs.fortinet.com/document/fortigate/6.0.5/cli-reference/487941/vpn-ipsec-phase2-interface-phase2",
}


@dataclass
class Item:
    layer: str
    kind: str
    name: str
    status: str
    message: str
    doc: str = ""


@dataclass
class Report:
    items: list[Item] = field(default_factory=list)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)     # layer -> {"read": n, "written": n}

    def add(self, layer: str, kind: str, name: str, status: str, message: str, doc: str = "") -> None:
        self.items.append(Item(layer, kind, name, status, message, DOC.get(doc, doc)))

    def count(self, layer: str, key: str, n: int = 1) -> None:
        self.counts.setdefault(layer, {"read": 0, "written": 0})[key] += n

    def by_status(self, status: str) -> list[Item]:
        return [i for i in self.items if i.status == status]

    def summary(self) -> dict[str, dict[str, int]]:
        layers: dict[str, dict[str, int]] = {}
        for layer, c in self.counts.items():
            layers[layer] = {"read": c["read"], "written": c["written"], **{s: 0 for s in STATUS_ORDER if s != "converted"}}
        for item in self.items:
            layers.setdefault(item.layer, {"read": 0, "written": 0, **{s: 0 for s in STATUS_ORDER if s != "converted"}})
            if item.status in layers[item.layer]:
                layers[item.layer][item.status] += 1
        return layers

    def to_rows(self) -> list[dict[str, str]]:
        order = {s: n for n, s in enumerate(STATUS_ORDER)}
        return [{"layer": i.layer, "kind": i.kind, "name": i.name, "status": STATUS_LABEL[i.status], "message": i.message, "documentation": i.doc}
                for i in sorted(self.items, key=lambda i: (-order[i.status], i.layer, i.kind, i.name))]

    def to_csv(self) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, ["layer", "kind", "name", "status", "message", "documentation"], lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(self.to_rows())
        return buf.getvalue()

    def to_text(self) -> str:
        lines = ["Conversion report", ""]
        for layer, row in self.summary().items():
            lines.append(f"{layer}: {row['read']} read, {row['written']} written, {row['approximated']} approximated, {row['review']} to review, {row['not_converted']} not converted")
        lines.append("")
        for item in sorted(self.items, key=lambda i: (STATUS_ORDER.index(i.status) * -1, i.layer)):
            lines.append(f"[{STATUS_LABEL[item.status]}] {item.layer} / {item.kind} {item.name}: {item.message}" + (f" ({item.doc})" if item.doc else ""))
        return "\n".join(lines) + "\n"
