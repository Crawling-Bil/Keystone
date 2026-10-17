"""Indentation-based parser for Cisco IOS-style configuration text.

IOS prints a hierarchy purely through indentation (one space per level in
``show running-config``; ``show sdwan running-config`` pads values with
extra spaces).  We rebuild that hierarchy into a tree so extractors can ask
"give me the children of ``interface Gi0/0/1``" instead of re-scanning
lines with fragile regexes.

Handled specially:
  * ``!`` comment lines (kept only for the two "Last configuration change"
    / "NVRAM config last updated" stamps, which are useful change-audit data)
  * ``banner <type> ^C ... ^C`` multi-line banners (content discarded --
    banners may contain anything and are not analyzed)
  * ``end`` terminating the configuration
  * the ``Building configuration...`` / ``Current configuration : N bytes``
    preamble
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator

_BANNER_RE = re.compile(r"^banner\s+(\S+)\s+(.*)$")


@dataclass
class Node:
    text: str
    line: int = 0
    indent: int = 0
    children: list["Node"] = field(default_factory=list)

    # --- navigation helpers -------------------------------------------
    def child_texts(self) -> list[str]:
        return [child.text for child in self.children]

    def find(self, prefix: str) -> list["Node"]:
        """Children whose text equals ``prefix`` or starts with ``prefix `` ."""
        return [child for child in self.children if child.text == prefix or child.text.startswith(prefix + " ")]

    def first(self, prefix: str) -> "Node | None":
        found = self.find(prefix)
        return found[0] if found else None

    def has(self, prefix: str) -> bool:
        return self.first(prefix) is not None

    def get(self, prefix: str, default: str = "") -> str:
        """Text after ``prefix`` of the first matching child."""
        node = self.first(prefix)
        if node is None:
            return default
        return node.text[len(prefix):].strip()

    def all(self, prefix: str) -> list[str]:
        return [child.text[len(prefix):].strip() for child in self.find(prefix)]

    def walk(self) -> Iterator["Node"]:
        for child in self.children:
            yield child
            yield from child.walk()


@dataclass
class ConfigTree:
    root: Node = field(default_factory=lambda: Node(text="", indent=-1))
    comments: list[str] = field(default_factory=list)
    declared_bytes: int | None = None
    line_count: int = 0

    def top(self, prefix: str) -> list[Node]:
        return self.root.find(prefix)

    def top_first(self, prefix: str) -> Node | None:
        return self.root.first(prefix)

    def has(self, prefix: str) -> bool:
        return self.root.has(prefix)

    def get(self, prefix: str, default: str = "") -> str:
        return self.root.get(prefix, default)

    def all(self, prefix: str) -> list[str]:
        return self.root.all(prefix)

    def __iter__(self) -> Iterator[Node]:
        return iter(self.root.children)


def parse_config(lines: Iterable[str]) -> ConfigTree:
    tree = ConfigTree()
    stack: list[Node] = [tree.root]
    raw = list(lines)
    tree.line_count = len(raw)
    i = 0
    while i < len(raw):
        line = raw[i].rstrip("\r\n").rstrip()
        i += 1
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("!"):
            if line.startswith("!"):
                text = stripped.lstrip("! ").strip()
                if text:
                    tree.comments.append(text)
            continue
        if stripped.startswith("Building configuration"):
            continue
        match = re.match(r"^Current configuration\s*:\s*(\d+)\s*bytes", stripped)
        if match:
            tree.declared_bytes = int(match.group(1))
            continue
        if line.startswith("end") and stripped == "end":
            break
        indent = len(line) - len(line.lstrip(" "))
        node = Node(text=stripped, line=i, indent=indent)

        banner = _BANNER_RE.match(stripped) if indent == 0 else None
        if banner:
            rest = banner.group(2)
            delim = "^C" if rest.startswith("^C") else (rest[:1] or "^")
            if rest.count(delim) < 2:
                while i < len(raw) and delim not in raw[i]:
                    i += 1
                i += 1  # closing delimiter line
            node.text = f"banner {banner.group(1)}"

        while len(stack) > 1 and stack[-1].indent >= indent:
            stack.pop()
        stack[-1].children.append(node)
        stack.append(node)
    return tree
