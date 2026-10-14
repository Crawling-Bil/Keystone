"""FortiOS configuration tree.

FortiOS prints its configuration as nested ``config`` / ``edit`` / ``set`` /
``next`` / ``end`` blocks::

    config firewall policy
        edit 1
            set name "LAN-to-WAN"
            set srcintf "lan"
            ...
        next
    end

``parse_forti`` turns that into a tree of :class:`FNode` objects.  Two
details matter for a security tool:

* **Secrets never enter the tree.**  Values of password-like keys
  (``password``, ``psksecret``, ``secret`` ...), SNMP community names, private
  keys and certificates are replaced with ``<hidden>`` at parse time; only the
  *kind* is kept in ``node.secrets`` (``ENC`` = stored encrypted by FortiOS,
  ``clear`` = readable text, ``guessable`` / ``custom`` for SNMP communities,
  ``blob`` for key/certificate material with its length).
* **Multi-VDOM exports** list every VDOM twice (an empty declaration, then
  the content) and put the system-wide settings under ``config global``.  The
  tree merges those so ``cfg.find("firewall policy")`` returns one node per
  VDOM that has the table.

Format reference: FortiOS CLI Reference (https://docs.fortinet.com/product/fortigate/).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from ..analyzer_core.redaction import HIDDEN

# keys whose value is always a credential, wherever they appear
SECRET_KEYS = {
    "password", "passwd", "psksecret", "psksecret-remote", "secret", "key", "auth-pwd", "priv-pwd", "passphrase",
    "ppk-secret", "auth-password", "privatekey", "pre-shared-key", "radius-secret", "ldap-password",
    "bind-password", "sso-psk", "api-key", "token", "authkey", "authentication-key",
}
# multi-line key / certificate material: keep only its length
BLOB_KEYS = {"private-key", "certificate", "ca", "csr", "ca-cert", "peer-cert", "cert"}
GUESSABLE_COMMUNITIES = {"public", "private", "community", "snmp", "admin", "monitor", "read", "write", "secret", "default", "cisco", "fortinet", "fortigate"}

_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')


def tokenize(rest: str) -> list[str]:
    out: list[str] = []
    for match in _TOKEN.finditer(rest):
        quoted, bare = match.groups()
        out.append(quoted.replace('\\"', '"').replace("\\\\", "\\") if quoted is not None else bare)
    return out


def _unbalanced(line: str) -> bool:
    """True when the line opens a quoted string that is not closed (multi-line values)."""
    count = 0
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            count += 1
        index += 1
    return count % 2 == 1


@dataclass
class FNode:
    kind: str                      # "root" | "config" | "edit"
    name: str                      # config path ("system interface") or entry key ("lan")
    line: int = 0
    settings: dict[str, list[str]] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    children: list["FNode"] = field(default_factory=list)
    parent: "FNode | None" = field(default=None, repr=False)

    # ---- reading helpers
    def get(self, key: str, default: str = "") -> str:
        values = self.settings.get(key)
        return values[0] if values else default

    def values(self, key: str) -> list[str]:
        return list(self.settings.get(key, []))

    def has(self, key: str) -> bool:
        return key in self.settings

    def enabled(self, key: str, default: bool | None = None) -> bool | None:
        value = self.get(key).lower()
        if value in ("enable", "enabled", "on", "yes", "true"):
            return True
        if value in ("disable", "disabled", "off", "no", "false"):
            return False
        return default

    def config(self, path: str) -> "FNode | None":
        for child in self.children:
            if child.kind == "config" and child.name.lower() == path.lower():
                return child
        return None

    def configs(self, path: str) -> list["FNode"]:
        return [child for child in self.children if child.kind == "config" and child.name.lower() == path.lower()]

    def entries(self) -> list["FNode"]:
        return [child for child in self.children if child.kind == "edit"]

    def entry(self, name: str) -> "FNode | None":
        for child in self.children:
            if child.kind == "edit" and child.name == name:
                return child
        return None

    def walk(self) -> Iterator["FNode"]:
        yield self
        for child in self.children:
            yield from child.walk()


@dataclass
class FortiTree:
    root: FNode
    header: dict[str, str] = field(default_factory=dict)
    vdoms: dict[str, FNode] = field(default_factory=dict)    # vdom name -> merged node
    global_node: FNode | None = None                          # `config global` (multi-VDOM) or the top level
    lines: int = 0

    @property
    def multi_vdom(self) -> bool:
        return self.header.get("vdom") == "1" or len(self.vdoms) > 1 or (self.global_node is not None and self.global_node is not self.root)

    def scopes(self) -> list[tuple[str, FNode]]:
        """(vdom name, node) for every VDOM; a single-VDOM export is one scope called 'root'."""
        if self.vdoms:
            return list(self.vdoms.items())
        return [("root", self.root)]

    def find(self, path: str) -> list[tuple[str, FNode]]:
        """Every ``config <path>`` block with the VDOM (or ``global``) it belongs to."""
        if not self.vdoms and self.global_node is self.root:
            node = self.root.config(path)           # single-VDOM export: everything is at the top level
            return [("root", node)] if node is not None else []
        found: list[tuple[str, FNode]] = []
        if self.global_node is not None and self.global_node is not self.root:
            node = self.global_node.config(path)
            if node is not None:
                found.append(("global", node))
        for name, scope in self.scopes():
            node = scope.config(path)
            if node is not None:
                found.append((name, node))
        if not found:
            node = self.root.config(path)
            if node is not None:
                found.append(("root", node))
        return found

    def first(self, path: str) -> FNode | None:
        hits = self.find(path)
        return hits[0][1] if hits else None

    def entries(self, path: str) -> list[tuple[str, FNode]]:
        out: list[tuple[str, FNode]] = []
        for scope, node in self.find(path):
            out.extend((scope, entry) for entry in node.entries())
        return out


def _secret_kind(path: str, key: str, values: list[str]) -> str | None:
    """Return the secret kind for a ``set`` line, or None when the value is harmless."""
    low = key.lower()
    if low == "private-key":
        return "blob"
    if low in BLOB_KEYS:
        joined = " ".join(values)
        # 'set ca-cert "Fortinet_CA_SSL"' is a harmless reference to a certificate by name
        return "blob" if ("-----BEGIN" in joined or "\n" in joined or len(joined) > 120) else None
    if path.endswith("snmp community") and low == "name":
        name = values[0].lower() if values else ""
        return "guessable" if name in GUESSABLE_COMMUNITIES else "custom"
    if low in SECRET_KEYS or low.endswith(("-password", "-secret", "-psk")):
        if values and values[0] == "ENC":
            return "ENC"
        return "clear" if values else "empty"
    return None


def parse_forti(text: str) -> FortiTree:
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    root = FNode("root", "")
    tree = FortiTree(root=root, lines=len(raw))
    stack: list[FNode] = [root]

    index = 0
    while index < len(raw):
        number = index + 1
        line = raw[index].strip()
        index += 1
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#config-version="):
                tree.header.update(_parse_header(line))
            elif "=" in line and line.startswith("#"):
                key, _, value = line[1:].partition("=")
                tree.header.setdefault(key.strip(), value.strip())
            continue
        head, _, rest = line.partition(" ")
        head = head.lower()
        top = stack[-1]
        if head == "config":
            node = FNode("config", rest.strip().lower() if not rest.strip().startswith('"') else rest.strip(), number, parent=top)
            top.children.append(node)
            stack.append(node)
        elif head == "edit":
            name = (tokenize(rest) or [""])[0]
            node = FNode("edit", name, number, parent=top)
            top.children.append(node)
            stack.append(node)
        elif head in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif head in ("set", "append", "select", "unselect", "unset"):
            key, _, value = rest.strip().partition(" ")
            key = key.strip()
            if not key:
                continue
            if head == "unset":
                top.settings.pop(key, None)
                continue
            # multi-line quoted values (certificates, banners)
            while _unbalanced(value) and index < len(raw):
                value += "\n" + raw[index]
                index += 1
            values = tokenize(value)
            path = _config_path(top)
            kind = _secret_kind(path, key, values)
            if kind == "blob":
                top.secrets[key] = f"blob:{sum(len(v) for v in values)}"
                top.settings[key] = [HIDDEN]
            elif kind:
                top.secrets[key] = kind
                top.settings[key] = [HIDDEN]
            elif head == "append" or head == "select":
                top.settings.setdefault(key, []).extend(values)
            elif head == "unselect":
                top.settings[key] = [v for v in top.settings.get(key, []) if v not in values]
            else:
                top.settings[key] = values
    _index_scopes(tree)
    return tree


def _config_path(node: FNode) -> str:
    current: FNode | None = node
    while current is not None and current.kind != "config":
        current = current.parent
    return current.name if current is not None else ""


def _parse_header(line: str) -> dict[str, str]:
    """``#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin``"""
    body = line[len("#config-version="):]
    parts = body.split(":")
    header: dict[str, str] = {"config-version": parts[0]}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        if key:
            header[key] = value
    match = re.match(r"^(?P<model>[A-Za-z0-9]+?)-(?P<version>\d+\.\d+\.\d+)-(?P<train>[A-Za-z]+)-build(?P<build>\d+)-(?P<date>\d+)", parts[0])
    if match:
        header.update({"model": match["model"], "version": match["version"], "train": match["train"], "build": match["build"], "built": match["date"]})
    return header


def _index_scopes(tree: FortiTree) -> None:
    """Merge the duplicate ``config vdom`` blocks and locate ``config global``."""
    root = tree.root
    global_cfg = root.config("global")
    vdoms: dict[str, FNode] = {}
    for block in root.configs("vdom"):
        for entry in block.entries():
            target = vdoms.get(entry.name)
            if target is None:
                vdoms[entry.name] = entry
            else:
                target.children.extend(entry.children)
                for key, value in entry.settings.items():
                    target.settings.setdefault(key, value)
    if global_cfg is not None or vdoms:
        tree.vdoms = vdoms
        tree.global_node = global_cfg
    else:
        tree.global_node = root          # single-VDOM export: everything is at the top level
