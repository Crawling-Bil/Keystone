"""Split a terminal capture into one block per command.

A "capture" is what an engineer gets from pasting a collect-list into an
SSH/console session and saving the whole terminal buffer: prompts, the
typed commands and their output, in order.  Real captures are messy --
abbreviated commands (``show int desc``), commands the device rejected
(``% Invalid input``), half-typed lines that were never executed
(``show interfaces coun`` followed by the next prompt), ``?`` help
requests -- so this module is deliberately forgiving.

Nothing here knows about a specific vendor except the prompt patterns the
caller passes in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Pattern

# --------------------------------------------------------------------------
# Prompt patterns
# --------------------------------------------------------------------------

# Cisco IOS / IOS-XE / NX-OS style:  host#cmd   host>cmd   host(config)#cmd
CISCO_PROMPT = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9_.\-/]*)"
    r"(?:\((?P<mode>[^)\s]*)\))?"
    r"(?P<char>[#>])[ \t]?(?P<cmd>.*)$"
)

# Huawei VRP:  <host>display ...   [host]display ...
HUAWEI_PROMPT = re.compile(r"^(?:<(?P<host>[^<>\s]+)>|\[(?P<host2>[^\[\]\s]+)\])[ \t]?(?P<cmd>.*)$")

# FortiOS:  host # get system status    host (root) # ...    host (vdom) $ ...
FORTI_PROMPT = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\s+\((?P<mode>[^)]*)\))?\s*(?P<char>[#$])\s?(?P<cmd>.*)$"
)

# PAN-OS:  admin@PA-3220> show system info     admin@PA-3220# set ...
PANOS_PROMPT = re.compile(r"^(?P<user>[A-Za-z0-9_.\-]+)@(?P<host>[A-Za-z0-9_.\-]+)(?:\([^)]*\))?(?P<char>[>#])[ \t]?(?P<cmd>.*)$")

# F5 BIG-IP bash/tmsh:
#   [admin@bigip1:Active:Standalone] ~ # tmsh list ltm virtual
#   root@(bigip1)(cfg-sync Standalone)(Active)(/Common)(tmos)# list ltm pool
#   admin@(bigip1)(cfg-sync Standalone)(Active)(/Common)(tmos)# show ltm virtual
F5_PROMPT = re.compile(
    r"^(?:\[(?P<user1>[^@\]\s]+)@(?P<host1>[^:\]\s]+)(?::[^\]]*)?\]\s*\S*\s*[#$]"
    r"|(?P<user2>[A-Za-z0-9_.\-]+)@\((?P<host2>[^)]+)\)(?:\([^)]*\))*(?:\(tmos\))?[#$])"
    r"[ \t]?(?P<cmd>.*)$"
)

_ERROR_RE = re.compile(
    r"^\s*(?:%\s*(?:Invalid input|Incomplete command|Ambiguous command|Unrecognized command|Unknown command|"
    r"Command authorization failed|Access denied|Error)|"
    r"\^\s*$|Error:|Unknown action|Invalid command|command parse error|syntax error|unknown command|"
    r"Command fail|Item not found|01070)",
    re.IGNORECASE,
)
_PARTIAL_ERROR_RE = re.compile(r"% Invalid input detected|% Incomplete command|% Ambiguous command|Unrecognized command", re.IGNORECASE)


@dataclass
class Block:
    """One command and its output."""

    command: str
    norm: str
    host: str
    lines: list[str]
    start: int  # 1-based line number of the command line in the capture
    error: str = ""
    index: int = 0

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def line_count(self) -> int:
        return len(self.lines)

    @property
    def is_helpful(self) -> bool:
        """False for ``?`` help requests and blocks that errored out."""
        return not self.error and not self.command.rstrip().endswith("?")


@dataclass
class Capture:
    blocks: list[Block] = field(default_factory=list)
    hosts: dict[str, int] = field(default_factory=dict)
    raw_lines: int = 0
    has_prompts: bool = False

    def hostname(self) -> str:
        if not self.hosts:
            return ""
        return max(self.hosts.items(), key=lambda kv: kv[1])[0]

    def find(self, *matchers: "str | Callable[[Block], bool]", usable: bool = True) -> list[Block]:
        """Blocks whose command satisfies any matcher.

        A string matcher is a command *template*: tokens may be abbreviated
        the way Cisco CLIs allow (``show int desc`` == ``show interface
        description``), ``<name>`` tokens match any single word and a
        trailing ``...`` matches any trailing arguments.  See
        :func:`command_matches`.
        """
        found: list[Block] = []
        for block in self.blocks:
            if usable and not block.is_helpful:
                continue
            for matcher in matchers:
                if callable(matcher):
                    if matcher(block):
                        found.append(block)
                        break
                elif command_matches(block.norm, matcher) is not None:
                    found.append(block)
                    break
        return found

    def first(self, *matchers: "str | Callable[[Block], bool]") -> Block | None:
        # Prefer the longest output when a command was run more than once
        # (an engineer re-running after a typo is common).
        blocks = self.find(*matchers)
        if not blocks:
            return None
        return max(blocks, key=lambda block: block.line_count)


# --------------------------------------------------------------------------
# Command matching
# --------------------------------------------------------------------------


def normalize_command(command: str) -> str:
    text = re.sub(r"\s+", " ", command.strip().lower())
    return text


def command_matches(typed_norm: str, template: str) -> dict[str, str] | None:
    """Match a typed (normalised) command against a template.

    Returns the captured ``<name>`` arguments (possibly empty dict) on a
    match, ``None`` otherwise.  Rules, applied token by token:

    * ``<name>``  -> any single token, captured under ``name``
    * ``...``     -> must be the last template token; swallows the rest
    * other       -> the typed token must be a prefix of the template token
                     (Cisco abbreviation) and at least 2 characters long,
                     except for single-character-safe tokens like ``ip``.
    * A pipe filter (``| include``) makes the command a partial view and
      never matches a template that does not itself contain the pipe.
    """
    if "|" in typed_norm and "|" not in template:
        return None
    typed = typed_norm.split()
    tokens = template.lower().split()
    captured: dict[str, str] = {}
    ti = 0
    for position, token in enumerate(tokens):
        if token == "...":
            return captured
        if ti >= len(typed):
            return None
        word = typed[ti]
        if token.startswith("<") and token.endswith(">"):
            captured[token[1:-1]] = word
        else:
            if word == token:
                pass
            elif len(word) >= 2 and token.startswith(word):
                pass
            else:
                return None
        ti += 1
    if ti != len(typed):
        return None
    return captured


# --------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------


def _prompt_parts(line: str, prompt_res: Iterable[Pattern[str]]) -> tuple[str, str] | None:
    for pattern in prompt_res:
        match = pattern.match(line)
        if not match:
            continue
        groups = match.groupdict()
        host = ""
        for key in ("host", "host1", "host2"):
            if groups.get(key):
                host = groups[key]
                break
        mode = groups.get("mode") or ""
        if mode.startswith("config"):
            # config-mode prompt: the "command" is a configuration line, not
            # a show command.  Treat as output of the preceding block.
            return None
        return host, (groups.get("cmd") or "").strip()
    return None


def split_capture(
    text: str,
    prompt_res: Iterable[Pattern[str]] = (CISCO_PROMPT,),
    min_prompt_repeats: int = 2,
) -> Capture:
    """Cut ``text`` into blocks, one per command.

    The prompt host is learned first: a candidate host must appear in at
    least ``min_prompt_repeats`` prompt-looking lines (or be the only one)
    so that stray output lines such as ``Router>`` inside a banner or a
    line like ``Total#`` are not mistaken for prompts.
    """
    prompt_res = tuple(prompt_res)
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    capture = Capture(raw_lines=len(raw))

    counts: dict[str, int] = {}
    candidates: list[tuple[int, str, str]] = []
    for number, line in enumerate(raw, start=1):
        if not line or line[0] in " \t":
            continue
        parts = _prompt_parts(line, prompt_res)
        if parts is None:
            continue
        host, cmd = parts
        candidates.append((number, host, cmd))
        counts[host] = counts.get(host, 0) + 1

    if not counts:
        return capture

    # A host is trusted when it repeats, or when nothing repeats (single
    # command capture).  Prompt lines of untrusted hosts stay as output.
    best = max(counts.values())
    trusted = {host for host, n in counts.items() if n >= min_prompt_repeats or n == best}
    capture.has_prompts = True
    capture.hosts = {host: n for host, n in counts.items() if host in trusted}

    prompt_lines = {number: (host, cmd) for number, host, cmd in candidates if host in trusted}
    current: Block | None = None
    for number, line in enumerate(raw, start=1):
        if number in prompt_lines:
            host, cmd = prompt_lines[number]
            if current is not None:
                _finish(current)
                capture.blocks.append(current)
            current = Block(command=cmd, norm=normalize_command(cmd), host=host, lines=[], start=number, index=len(capture.blocks))
            continue
        if current is not None:
            current.lines.append(line)
    if current is not None:
        _finish(current)
        capture.blocks.append(current)
    # drop empty-command prompts (a bare Enter)
    capture.blocks = [block for block in capture.blocks if block.command]
    for index, block in enumerate(capture.blocks):
        block.index = index
    return capture


def _finish(block: Block) -> None:
    # trim leading/trailing blank lines but keep inner structure
    lines = block.lines
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    for line in lines[:6]:
        if _ERROR_RE.match(line) or _PARTIAL_ERROR_RE.search(line):
            block.error = line.strip()[:160]
            break


def single_block_capture(text: str, command: str = "show running-config") -> Capture:
    """Wrap a prompt-less paste (a bare config export) as one block."""
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    block = Block(command=command, norm=normalize_command(command), host="", lines=raw, start=1)
    _finish(block)
    return Capture(blocks=[block], raw_lines=len(raw), has_prompts=False)
