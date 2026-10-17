"""Parser for the TMSH stanza format used by F5 BIG-IP.

The same syntax appears in ``/config/bigip.conf``, ``/config/bigip_base.conf``,
``tmsh list ...`` and ``tmsh show running-config``::

    ltm virtual /Common/vs_web_443 {
        destination /Common/10.10.10.10:443
        pool /Common/pool_web
        profiles {
            /Common/http { }
            /Common/clientssl {
                context clientside
            }
        }
        rules { /Common/redirect_http }
    }

A statement is a line of words; ``{`` after a statement opens a block, and a
brace group written on one line (``options { no-tlsv1 no-tlsv1.1 }``) is a
list of words.  iRule bodies are Tcl, not TMSH, so the text between the braces
of ``ltm rule`` (and a few similar objects) is kept raw and its braces are
counted the way Tcl counts them.

Secrets are replaced while parsing: passwords, passphrases, hashes, SNMP
community names and shared secrets never leave this module (they become
``<hidden>``), but the parser remembers whether an SNMP community was one of
the well-known defaults so the analyzer can still flag it.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import Iterator

from ..analyzer_core.redaction import HIDDEN

SECRET_KEYS = {
    "password", "passphrase", "secret", "encrypted-password", "bind-pw", "community-name", "auth-password", "auth-password-encrypted",
    "privacy-password", "privacy-password-encrypted", "shared-secret", "psk", "pre-shared-key", "cookie-encryption-passphrase", "crypto-passphrase",
    "trap-community", "root-password", "admin-password", "api-key", "token", "secure-password", "bind-password",
}
GUESSABLE_COMMUNITIES = {"public", "private", "community", "snmp", "cisco", "manager", "admin", "secret", "default", "write", "read", "monitor"}
_HASH = re.compile(r"^\$(?:M|1|5|6|2[aby]?)\$")
# objects whose body is code, not TMSH: kept raw
RAW_PREFIXES = (("ltm", "rule"), ("cli", "script"), ("sys", "application", "template"), ("sys", "icall", "script"), ("ilx", "workspace"))
MAX_DEPTH = 40


@dataclass
class TNode:
    tokens: list[str]
    children: list["TNode"] = field(default_factory=list)
    block: bool = False
    inline: bool = False
    raw: str = ""
    line: int = 0
    guess: bool = False

    # ---------------------------------------------------------------- shape
    @property
    def key(self) -> str:
        return self.tokens[0] if self.tokens else ""

    @property
    def args(self) -> list[str]:
        return self.tokens[1:]

    @property
    def value(self) -> str:
        return " ".join(self.tokens[1:])

    @property
    def name(self) -> str:
        return self.tokens[-1] if self.tokens else ""

    # ------------------------------------------------------------- lookups
    def child(self, key: str) -> "TNode | None":
        for item in self.children:
            if item.key == key:
                return item
        return None

    def kids(self, key: str) -> list["TNode"]:
        return [item for item in self.children if item.key == key]

    def has(self, key: str) -> bool:
        return self.child(key) is not None

    def val(self, key: str, default: str = "") -> str:
        item = self.child(key)
        if item is None:
            return default
        if item.args:
            return item.value
        return default

    def names(self, key: str | None = None) -> list[str]:
        """The words of a list-valued setting: ``{ a b c }`` or one word per line,
        or the names of the child blocks (``profiles { /Common/http { } }``)."""
        node = self if key is None else self.child(key)
        if node is None:
            return []
        if node.inline:
            return [token for item in node.children for token in item.tokens]
        out: list[str] = []
        for item in node.children:
            if item.tokens:
                out.append(item.tokens[0])
        return out

    def walk(self) -> Iterator["TNode"]:
        yield self
        for item in self.children:
            yield from item.walk()

    def flat_tokens(self) -> list[str]:
        out: list[str] = []
        for item in self.walk():
            out.extend(item.tokens)
        return out


@dataclass
class TmshTree:
    root: list[TNode] = field(default_factory=list)
    lines: int = 0
    version: str = ""
    warnings: list[str] = field(default_factory=list)

    def named(self, *prefix: str) -> list[TNode]:
        """Top-level objects ``<prefix...> <name> { }`` (one trailing name token)."""
        size = len(prefix)
        return [n for n in self.root if n.block and len(n.tokens) == size + 1 and tuple(n.tokens[:size]) == prefix]

    def single(self, *prefix: str) -> TNode | None:
        """Top-level singleton such as ``sys httpd { }``."""
        size = len(prefix)
        found = None
        for node in self.root:
            if node.block and tuple(node.tokens) == prefix:
                found = node
        return found if size else None

    def has_prefix(self, *prefix: str) -> bool:
        size = len(prefix)
        return any(tuple(n.tokens[:size]) == prefix for n in self.root)

    def all_with_prefix(self, *prefix: str) -> list[TNode]:
        size = len(prefix)
        return [n for n in self.root if tuple(n.tokens[:size]) == prefix]


class _Scanner:
    """Character scanner that hands out TMSH tokens one at a time (so a stray
    quote inside an iRule can never swallow the rest of the file)."""

    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0
        self.n = len(text)
        self.bol = True
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_at(self, index: int) -> int:
        return bisect_right(self.starts, index)

    def next(self) -> tuple[str, str, int]:
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in " \t\r":
                self.i += 1
                continue
            if c == "\n":
                self.i += 1
                self.bol = True
                return "nl", "", self.line_at(self.i - 1)
            if c == "#" and self.bol:
                end = s.find("\n", self.i)
                self.i = n if end < 0 else end
                continue
            self.bol = False
            start = self.i
            if c == "{":
                self.i += 1
                return "lb", "{", self.line_at(start)
            if c == "}":
                self.i += 1
                return "rb", "}", self.line_at(start)
            if c == '"':
                j = self.i + 1
                while j < n:
                    if s[j] == "\\":
                        j += 2
                        continue
                    if s[j] == '"':
                        break
                    j += 1
                value = s[self.i + 1:j]
                self.i = min(j + 1, n)
                return "str", value, self.line_at(start)
            j = self.i
            while j < n and s[j] not in " \t\r\n{}":
                j += 1
            self.i = j
            return "word", s[start:j], self.line_at(start)
        return "eof", "", self.line_at(max(n - 1, 0))

    def read_raw_body(self) -> str:
        """Called right after the opening brace: return everything up to the
        matching close brace, counting braces as Tcl does (a backslash hides
        the next character)."""
        s, n = self.s, self.n
        depth, j, start = 1, self.i, self.i
        while j < n:
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body = s[start:j]
        self.i = min(j + 1, n)
        self.bol = False
        return body.strip("\n")


def _is_raw(tokens: list[str]) -> bool:
    return any(tuple(tokens[: len(prefix)]) == prefix for prefix in RAW_PREFIXES)


def _scrub(tokens: list[str], node_is_block: bool) -> tuple[list[str], bool]:
    guess = False
    if tokens and tokens[0] in SECRET_KEYS and len(tokens) > 1:
        if tokens[0] == "community-name":
            guess = tokens[1].strip('"').lower() in GUESSABLE_COMMUNITIES
        tokens = [tokens[0], HIDDEN]
    else:
        tokens = [HIDDEN if _HASH.match(t) else t for t in tokens]
    return tokens, guess


def _parse_items(scan: _Scanner, top: bool, depth: int, tree: TmshTree) -> list[TNode]:
    items: list[TNode] = []
    while True:
        tokens: list[str] = []
        first_line = 0
        while True:
            kind, value, line = scan.next()
            if kind in ("word", "str"):
                if not tokens:
                    first_line = line
                tokens.append(value)
                continue
            break
        if kind == "lb":
            clean, guess = _scrub(tokens, True)
            node = TNode(tokens=clean, block=True, line=first_line or line, guess=guess)
            if top and _is_raw(tokens):
                node.raw = scan.read_raw_body()
                node.inline = True
            elif depth >= MAX_DEPTH:
                tree.warnings.append(f"Nesting deeper than {MAX_DEPTH} levels near line {line}; the rest of that block was skipped.")
                node.raw = scan.read_raw_body()
            else:
                node.children = _parse_items(scan, False, depth + 1, tree)
                closing_line = scan.line_at(max(scan.i - 1, 0))
                node.inline = bool(node.children) and closing_line == (first_line or line) and all(not c.block for c in node.children)
            items.append(node)
            continue
        if kind == "rb":
            if tokens:
                clean, guess = _scrub(tokens, False)
                items.append(TNode(tokens=clean, line=first_line, guess=guess))
            if top:
                tree.warnings.append(f"Unmatched '}}' near line {line}.")
                continue
            return items
        if kind == "nl":
            if tokens:
                clean, guess = _scrub(tokens, False)
                items.append(TNode(tokens=clean, line=first_line, guess=guess))
            continue
        if tokens:
            clean, guess = _scrub(tokens, False)
            items.append(TNode(tokens=clean, line=first_line, guess=guess))
        if not top:
            tree.warnings.append("The configuration ends inside an open block (a closing brace is missing).")
        return items


def _weight(node: TNode) -> int:
    return sum(1 for _ in node.walk())


def _dedupe(root: list[TNode]) -> list[TNode]:
    """A capture can list the same object twice (``tmsh list`` and then ``... all-properties``).
    Keep one per object: the fuller listing wins, and a tie goes to the later one."""
    best: dict[tuple[str, ...], int] = {}
    for index, node in enumerate(root):
        if not node.block or not node.tokens:
            continue
        key = tuple(node.tokens)
        if key not in best or _weight(node) >= _weight(root[best[key]]):
            best[key] = index
    keep = set(best.values())
    return [node for index, node in enumerate(root) if not node.block or not node.tokens or index in keep]


_ABSOLUTE_MODULES = {"ltm", "gtm", "net", "cm", "security", "apm", "pem", "wom"}
_SINGLETON_WORDS = {"general", "load-balancing", "metrics", "metrics-exclusions", "global-settings", "topology"}


def _absolutize(root: list[TNode]) -> None:
    """``show running-config`` prints objects of /Common without the partition ('ltm pool POOL-1'); ``tmsh list`` and bigip.conf print
    '/Common/POOL-1'.  References are made absolute by the extractor, so give the definitions the same form.  Singletons ('ltm global-settings general',
    'sys httpd') and one- or two-word statements are left alone."""
    for node in root:
        tokens = node.tokens
        if not node.block or len(tokens) < 3 or tokens[-1].startswith("/"):
            continue
        head = tokens[0]
        if head == "sys" and tokens[1] == "file":
            pass
        elif head not in _ABSOLUTE_MODULES:
            continue
        if tokens[1].startswith("global-settings") or tokens[1].endswith("-globals") or tokens[-1] in _SINGLETON_WORDS or tokens[1] in _SINGLETON_WORDS or ":" in "".join(tokens[1:-1]):
            continue
        tokens[-1] = "/Common/" + tokens[-1]


def parse_tmsh(text: str) -> TmshTree:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    tree = TmshTree(lines=text.count("\n") + 1)
    match = re.search(r"^#TMSH-VERSION:\s*(\S+)", text, re.M)
    if match:
        tree.version = match[1]
    scan = _Scanner(text)
    items = _parse_items(scan, True, 0, tree)
    _absolutize(items)
    tree.root = _dedupe(items)
    return tree
