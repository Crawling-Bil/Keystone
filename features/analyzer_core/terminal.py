"""Replay a raw terminal log (PuTTY / SecureCRT / ``script``) into the text the engineer actually saw.

A saved session log is not text, it is the byte stream the device sent to the terminal.  Network CLIs lean on terminal
control codes for line editing, tab completion and paging, so the same words appear several times in the raw file:

* tab completion / history redraw -- ``show \\x1b[K<prompt> show system \\x1b[K<prompt> show system info`` (a PAN-OS prompt
  repaints itself after every completed word, with or without a ``\\r`` before it);
* the pager's status line -- ``\\x1b[7mlines 1-53\\x1b[27m\\x1b[K\\r\\x1b[K`` printed *inside* the output (PAN-OS ``less``);
* wrapped table cells -- a long CIDR such as ``103.164.100.2`` + `` `` + ``\\x08`` + ``43/28`` where the backspace makes the
  last two cells overwrite the wrap padding;
* ``--More--`` prompts erased with backspaces (Cisco ``\\x08 \\x08``), keypad mode switches (``\\x1b[?1h\\x1b=``).

Removing escape sequences with a regex and keeping "the text after the last carriage return" gets most of this right and a few
lines wrong -- which is how a table row ends up with a second address glued to the first.  Replaying the stream through a tiny
terminal model (a line buffer, a cursor, carriage return, backspace, erase-to-end-of-line) gives what was on the screen.

Only the control codes that appear in CLI logs are modelled: CR, LF, BS (tabs are kept as they are), ``CSI K`` (erase in line), ``CSI C/D`` (cursor
forward/back) and ``CSI P`` (delete characters).  Every other escape sequence is dropped.
"""

from __future__ import annotations

import re

_CSI = re.compile(r"\x1b\[([0-9;?]*)([ -/]*)([@-~])")
_OTHER_ESC = re.compile(r"\x1b[()][A-Za-z0-9]|\x1b[=>78DEHMNOZc]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
# `less` status line: reverse video, erase, carriage return, erase.  It is printed wherever the page happened to end -- often in the
# middle of a table row -- and the rest of that row follows the erase.  Cut it out so the two halves of the row join again.
_PAGER_PROMPT = re.compile(r"\x1b\[7m(?:lines? \d+-\d+(?:/\d+)?(?: \(END\))?|\(END\)|--More--[^\x1b]*)\x1b\[27m(?:\x1b\[K)?(?:\r?\x1b\[K)?")


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f]")


def render(raw: str) -> str:
    """Return the visible text of ``raw`` -- one string, ``\\n`` between lines, no control codes left.

    The terminal state (cursor, buffer) never survives a line feed, so the log is replayed line by line and lines without a
    control character -- almost all of a configuration file -- are passed through untouched."""
    if "\x1b[7m" in raw:
        raw = _PAGER_PROMPT.sub("", raw)
    out = []
    for line in raw.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]                                           # CRLF: the CR only returns the cursor, nothing is overwritten
        out.append(_render_line(line) if _CONTROL.search(line) else line)
    return "\n".join(out)


def _render_line(raw: str) -> str:
    buf: list[str] = []
    col = 0
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "\x1b":
            match = _CSI.match(raw, i)
            if match:
                params, _, final = match.groups()
                arg = int(params.split(";")[0]) if params and params.split(";")[0].isdigit() else None
                if final == "K":                                       # erase in line: 0 = cursor..end, 1 = start..cursor, 2 = whole line
                    mode = arg or 0
                    if mode == 0:
                        del buf[col:]
                    elif mode == 1:
                        for k in range(min(col + 1, len(buf))):
                            buf[k] = " "
                    else:
                        buf.clear()
                        col = 0
                elif final == "D":
                    col = max(0, col - (arg or 1))
                elif final == "C":
                    col += arg or 1
                    if col > len(buf):
                        buf.extend(" " * (col - len(buf)))
                elif final == "P":
                    del buf[col:col + (arg or 1)]
                i = match.end()
                continue
            other = _OTHER_ESC.match(raw, i)
            i = other.end() if other else i + 1
            continue
        if ch == "\r":
            col = 0
        elif ch == "\x08":
            col = max(0, col - 1)
        elif ch == "\x07" or ch < " ":
            pass                                                        # bell and other C0 controls carry nothing
        else:
            if col < len(buf):
                buf[col] = ch
            else:
                buf.extend(" " * (col - len(buf)))
                buf.append(ch)
            col += 1
        i += 1
    line = "".join(buf)
    return line if line.strip() else ""
