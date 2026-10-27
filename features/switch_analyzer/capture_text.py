"""Capture-text helpers shared by the Switch Analyzer's live-state parsers.

A real switch capture is almost never a clean ``show`` dump. The captures
this project has seen come from several terminal tools and arrive as:

* plain prompt/command/output (``HOST#show mac address-table``),
* Huawei ``<HOST>display mac-address`` style prompts,
* Aruba sessions that type each command on a bare line with no prompt,
* VT100 sessions where the screen was redrawn (leftover ``[24;44H`` cursor
  moves glued between a command and the header it printed),
* "session log" files where every chunk the terminal saw is wrapped in a
  ``22/07/2026 14:02:44|000000000012|TERM|000000000647|`` record header and
  every typed key is logged on its own line (the command is only complete in
  a ``KEYS`` record, and tab-completion leaves a half-typed ``sh ip arp``
  prompt line *before* the real one),
* repeated runs of the same command (a second pass after a ``?`` help
  screen), where the first occurrence is empty.

``clean_lines`` removes the transport noise without touching content, and
``command_outputs`` returns the output of EVERY occurrence of a command so a
caller can pick the occurrence that actually contains the table, instead of
trusting the first one (which is what the older ``_extract_section`` in
runtime_parser.py does and why it returns nothing on those captures).
"""
from __future__ import annotations

import re
from bisect import bisect_right
from typing import Iterable

# --------------------------------------------------------------------------
# Transport-noise removal
# --------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>MD78]")
# Cursor-position escapes whose ESC byte was stripped by the capture tool,
# e.g. "show interface status[24;44H[24;44H  Port  Name ...". The text after
# the move is drawn at a new screen position, so treat it as a new line.
_BARE_CURSOR_RE = re.compile(r"\[\d{1,3};\d{1,3}[Hf]")
_BACKSPACE_RE = re.compile(r"[^\x08\n]\x08")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MORE_RE = re.compile(r"\s*-{2,4}\s*More\s*-{2,4}\s*", re.IGNORECASE)
# "22/07/2026 14:02:44|000000000012|TERM|000000000647|<payload>"
# Some exports keep only the time and drop the date and the record type,
# e.g. "16:42:21|000000000135|NAME: "Slot 1",  DESCR: ..." (seen on a real
# Nexus capture where half of the `show inventory` entries carried the
# short prefix, so the NAME: line was invisible to the inventory parser
# and Fan 1-3 went missing). Both the date and the "TERM|n|" part are
# therefore optional; the time and the leading "|digits|" are not.
_SESSION_RECORD_RE = re.compile(
    r"^(?:\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}[ T])?\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\|\d+\|(?:[A-Za-z ]{3,5}\|\d+\|)?"
)
# ISO-8601 timestamp that starts a device log message ("2026-10-11T18:05:35.084085+07:00 SW1 ops-switchd[664]: ...")
# when it follows a letter or a dash on the same line, i.e. it is glued to a command echo.
_GLUED_LOG_RE = re.compile(r"(?<=[A-Za-z\-])\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+\S")


def clean_lines(text: str) -> list[str]:
    """Return the capture as a list of lines with terminal/session-log
    transport noise removed. Content is never rewritten."""
    if not text:
        return []
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_RE.sub("", text)
    text = _BARE_CURSOR_RE.sub("\n", text)
    while "\x08" in text:
        shortened = _BACKSPACE_RE.sub("", text)
        if shortened == text:
            break
        text = shortened
    text = _MORE_RE.sub("\n", text)
    text = _CONTROL_RE.sub("", text)
    out: list[str] = []
    for raw in text.split("\n"):
        line = _SESSION_RECORD_RE.sub("", raw).rstrip()
        glued = _GLUED_LOG_RE.search(line) if "T" in line else None
        if glued and split_command(line[:glued.start()]) is not None:
            # A device log message printed while the next typed command was being echoed
            # ("show interface2026-10-11T18:05:35+07:00 sw1 hpe-tsdbd[4007]: Event|..."): two lines, not one command.
            out.append(line[:glued.start()].rstrip())
            line = line[glued.start():]
        out.append(line)
    return _drop_typeahead_echo(_fold_pager_help(expand_command_echoes(out)))


def expand_command_echoes(lines: list[str]) -> list[str]:
    """Spell out abbreviated ``show`` commands (``sh inven``, ``show cdp neig detail``); see :mod:`command_names`."""
    from . import command_names   # command_names imports this module for split_prompt
    return command_names.expand_lines(lines)


_PAGER_HELP_START = re.compile(r"^Most commands optionally preceded by integer argument k\b")
_PAGER_RULE = re.compile(r"^-{40,}$")
PAGER_HELP_MARKER = "...pager help screen removed"


def _fold_pager_help(lines: list[str]) -> list[str]:
    """The help screen of the NX-OS ``more`` pager (a key press after ``--More--``) printed into the middle of a table.

    Its lines (``<space>  Display next k lines``, ``<return> ...``) look like Huawei prompts and cut the command block there, so the screen
    (from "Most commands optionally preceded ..." to the second ruler) is replaced by one marker line; a parser can still count it."""
    out: list[str] = []
    index = 0
    while index < len(lines):
        if _PAGER_HELP_START.match(lines[index]):
            rules, end = 0, index + 1
            while end < min(len(lines), index + 40):
                if _PAGER_RULE.match(lines[end]):
                    rules += 1
                    if rules == 2:
                        break
                end += 1
            if rules == 2:
                out.append(PAGER_HELP_MARKER)
                index = end + 1
                continue
        out.append(lines[index])
        index += 1
    return out


# --------------------------------------------------------------------------
# Prompts and command echoes
# --------------------------------------------------------------------------

# Cisco / Aruba / NX-OS: "HOST#", "HOST(config)#", "HOST>", "HOST# "
# Huawei: "<HOST>", "[HOST]", "[HOST-GigabitEthernet0/0/1]"
_PROMPT_RE = re.compile(
    r"^(?:<[^<>\s]{1,80}>|\[[^\[\]\s]{1,80}\]|[^\s#>\[\]<|\"'\\]{1,80}(?:\([^()\s]{1,40}\))?[#>])"
)
# A host name never holds a quote or a backslash. Without that, the first line of an Aruba ``banner motd "####...\n#`` text parsed as the prompt
# ``"#`` and cut the running-config in half at the banner (every line after it, SNMP, NTP, VLANs, was lost to the checks).
_BARE_SHOW_RE = re.compile(r"^(?:show|sh|display|disp|dis)\s+\S", re.IGNORECASE)


_PLACEHOLDER_VALUES = frozenset({"<none>", "<empty>", "<null>", "<unset>", "<unspecified>", "<unknown>"})


def split_prompt(line: str) -> tuple[str, str] | None:
    """If ``line`` begins with a CLI prompt, return (prompt, rest)."""
    stripped = line.strip()
    match = _PROMPT_RE.match(stripped)
    if not match:
        return None
    if match.group(0).lower() in _PLACEHOLDER_VALUES:
        # "<none>" / "<empty>" are values Cisco prints (Smart Licensing: "Features Authorized: <none>"), not a Huawei prompt;
        # treating them as one cut the output block of the command above them in half.
        return None
    return match.group(0), stripped[match.end():].strip()


def split_command(line: str) -> tuple[str, str] | None:
    """If ``line`` is a command echo return (command, glued_tail).

    The command is lower-cased with whitespace collapsed. A screen redraw can
    leave the first output line glued to the echo after a run of spaces
    ("show interface status  Port  Name  Status ..."); that text is returned
    as ``glued_tail`` so it can be treated as the first output line.
    Handles "HOST#show x", "<HOST>display x" and bare "show x" lines."""
    stripped = line.strip()
    if not stripped:
        return None
    parsed = split_prompt(stripped)
    rest = parsed[1] if parsed else stripped
    if not rest or not _BARE_SHOW_RE.match(rest):
        return None
    tail = ""
    glued = re.match(r"^(.*?\S)\s{2,}(\S.*)$", rest)
    if glued:
        rest, tail = glued.group(1), glued.group(2)
    return re.sub(r"\s+", " ", rest).strip().lower(), tail.strip()


_TYPEAHEAD_WINDOW = 400


def _drop_typeahead_echo(lines: list[str]) -> list[str]:
    """Blank the echo of commands that were typed ahead of the prompt.

    An engineer pastes a whole collect list into the session. The device keeps reading its input buffer
    while it prints the previous command, so a pasted command can be echoed as a bare line (no prompt) in
    the middle of that earlier output, and only later does the normal ``HOST# command`` line appear:

        HOST# show running-config
        show inventory              <- typed-ahead echo of the NEXT command
        !Command: show running-config
        ...
        HOST# show inventory        <- the real prompt line

    Read literally, the bare line starts a block, so the running-config would be filed under ``show
    inventory`` (Nexus 9000 captures lost the whole configuration and ``show version`` this way, and an
    ArubaOS-CX ``show arp`` table was read as ``show cdp neighbors``).

    A bare command line is an echo, not a command, when the same command is typed with a prompt a little
    later in the capture. A bare line with no prompted twin stays: ArubaOS-CX prints its prompt only after
    the last command of a pasted batch, so there the bare lines ARE the command markers, and prompt-less
    sessions (Aruba type-on-a-bare-line, session logs) have no prompted lines at all, so nothing changes.
    """
    prompted_at: list[int] = []
    prompted_cmd: list[str] = []
    bare: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if not line or len(line) > 200:
            continue
        parts = split_command(line)
        if parts is None:
            continue
        if split_prompt(line.strip()) is not None:
            prompted_at.append(index)
            prompted_cmd.append(parts[0])
        else:
            bare.append((index, parts[0]))
    if len(prompted_at) < 3 or not bare:
        return lines
    result = lines
    for index, command in bare:
        position = bisect_right(prompted_at, index)
        if command in prompted_cmd[position:position + _TYPEAHEAD_WINDOW]:
            if result is lines:
                result = list(lines)
            result[index] = ""
    return result


_HOST_CONTEXT_SUFFIX_RE = re.compile(r"\([^()]*\)$")
_HUAWEI_VIEW_SUFFIX_RE = re.compile(
    r"-(?:Ethernet|GigabitEthernet|XGigabitEthernet|10GE|25GE|40GE|100GE|Eth-Trunk|Vlanif|MEth|Stack-Port|LoopBack|NULL|Tunnel)[^\[\]]*$"
)
_COMMANDISH_RE = re.compile(r"^(?:display|disp|dis|show|sh)\b", re.IGNORECASE)


def prompt_host(line: str) -> str | None:
    """Host name in the CLI prompt that starts ``line``, else None.

    Only a prompt followed by a command (full or half typed: ``dis``,
    ``display tra``, ``show``, ``sh``) counts, so table text that happens to
    look like a prompt never yields a host. Config / interface views are
    stripped: ``SW1(config)#`` -> ``SW1``, ``[SW1-GigabitEthernet0/0/1]`` ->
    ``SW1``, ``[~SW1]`` -> ``SW1``."""
    parsed = split_prompt(line)
    if not parsed:
        return None
    prompt, rest = parsed
    if not rest or not _COMMANDISH_RE.match(rest):
        return None
    if prompt[0] == "<":
        host = prompt[1:-1]
    elif prompt[0] == "[":
        host = _HUAWEI_VIEW_SUFFIX_RE.sub("", prompt[1:-1].lstrip("~*"))
    else:
        host = _HOST_CONTEXT_SUFFIX_RE.sub("", prompt[:-1])
    return host or None


def prompt_host_counts(lines: Iterable[str]) -> dict[str, int]:
    """How many command lines each prompt host typed, in first-seen order."""
    counts: dict[str, int] = {}
    for line in lines:
        host = prompt_host(line)
        if host:
            counts[host] = counts.get(host, 0) + 1
    return counts


def dominant_prompt_host(lines: Iterable[str]) -> str | None:
    """The host that typed most commands in the capture (first seen wins a
    tie), None when no line carries a prompt + command."""
    counts = prompt_host_counts(lines)
    if not counts:
        return None
    return max(counts, key=lambda host: counts[host])


def command_text(line: str) -> str | None:
    """The command typed on ``line`` (see split_command), else None."""
    parts = split_command(line)
    return parts[0] if parts else None


def is_prompt_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    parsed = split_prompt(stripped)
    if not parsed:
        return False
    # "Router>" alone, or a prompt followed by a command / partial command.
    # A prompt-looking token followed by ordinary table text must not count,
    # so require the remainder to be empty or to look like a command.
    rest = parsed[1]
    return not rest or bool(_BARE_SHOW_RE.match(rest)) or len(rest.split()) <= 3 and rest.islower()


def _block_after(lines: list[str], start: int, first: list[str]) -> tuple[list[str], int]:
    """Collect output lines from ``start`` until the next prompt/command echo."""
    block = list(first)
    cursor = start
    count = len(lines)
    while cursor < count:
        line = lines[cursor]
        if command_text(line) is not None or is_prompt_line(line):
            break
        if line.strip():
            block.append(line)
        cursor += 1
    return block, cursor


_COMMAND_INDEX_CACHE: list[tuple[list[str], list[tuple[int, tuple[str, str]]]]] = []


def _command_index(lines: list[str]) -> list[tuple[int, tuple[str, str]]]:
    """[(line index, split_command(line))] for every command line of ``lines``, computed once per list object."""
    for cached_lines, index in _COMMAND_INDEX_CACHE:
        if cached_lines is lines and len(cached_lines) == len(lines):
            return index
    index = []
    for position, line in enumerate(lines):
        if line:
            parts = split_command(line)
            if parts is not None:
                index.append((position, parts))
    _COMMAND_INDEX_CACHE.append((lines, index))
    del _COMMAND_INDEX_CACHE[:-4]
    return index


_STRIPPED_CACHE: list[tuple[list[str], list[str]]] = []


def _stripped_lines(lines: list[str]) -> list[str]:
    """``line.strip()`` of every line, computed once per list object (the header tests of the table readers share it)."""
    for cached_lines, stripped in _STRIPPED_CACHE:
        if cached_lines is lines and len(stripped) == len(lines):
            return stripped
    stripped = [line.strip() for line in lines]
    _STRIPPED_CACHE.append((lines, stripped))
    del _STRIPPED_CACHE[:-4]
    return stripped


def find_blocks(lines: list[str], patterns: Iterable[str] = (), headers: Iterable[str] = ()) -> list[tuple[int, list[str]]]:
    """Locate every block of output for a command, in capture order.

    Two independent ways of finding a block are combined so one lost line
    cannot hide a table:

    * ``patterns`` - regexes matched (re.fullmatch) against the normalised
      command echo ("show ip arp" does not match "show ip arp summary"). The
      block runs to the next prompt line or command echo.
    * ``headers`` - regexes matched against the stripped text of a table
      header line ("Protocol  Address  Age (min) ..."). Used when the capture
      lost or reordered the echo (a half-typed ``sh mac address-table `` line
      followed by the previous command's output).

    Returns [(start_line_index, lines)] sorted by position. Blank lines are
    dropped; a header block starts at the header line itself.
    """
    compiled = [re.compile(p) for p in patterns]
    header_list = list(headers)
    header_rx = [re.compile(h, re.IGNORECASE) for h in header_list]
    found: list[tuple[int, list[str]]] = []
    if compiled and not header_rx:
        # Fast path: the command lines are found once per capture and shared by every reader, instead of each of
        # the ~30 readers testing all lines (a 180,000-line capture spent most of its time there).
        resume = 0
        for position, parts in _command_index(lines):
            if position >= resume and any(rx.fullmatch(parts[0]) for rx in compiled):
                block, resume = _block_after(lines, position + 1, [parts[1]] if parts[1] else [])
                found.append((position, block))
        return found
    # Slow path (a header is looked for too): the command lines come from the shared index and the header test is one alternation
    # over the stripped lines, which are also computed once per capture. The scan order and the skip rules are those of a line by line walk.
    commands = dict(_command_index(lines))
    stripped = _stripped_lines(lines) if header_rx else []
    combined = re.compile("|".join(f"(?:{h})" for h in header_list), re.IGNORECASE) if header_list else None
    count = len(lines)
    index = 0
    while index < count:
        parts = commands.get(index)
        if parts is not None:
            if compiled and any(rx.fullmatch(parts[0]) for rx in compiled):
                block, cursor = _block_after(lines, index + 1, [parts[1]] if parts[1] else [])
                found.append((index, block))
                index = cursor
                continue
        elif combined is not None and combined.match(stripped[index]):
            block, cursor = _block_after(lines, index + 1, [lines[index]])
            found.append((index, block))
            index = cursor
            continue
        index += 1
    return found


def command_outputs(lines: list[str], patterns: Iterable[str]) -> list[list[str]]:
    """Output of every occurrence of a command (see find_blocks)."""
    return [block for _index, block in find_blocks(lines, patterns)]


def best_output(sections: list[list[str]], row_counter) -> list[str]:
    """From several occurrences of the same command, return the one that
    yields the most parsed rows (ties go to the later, i.e. most recent,
    run). ``row_counter`` is a callable lines -> int."""
    best: list[str] = []
    best_count = -1
    for section in sections:
        count = row_counter(section)
        if count >= best_count and (count > 0 or best_count < 0):
            best, best_count = section, count
    return best
