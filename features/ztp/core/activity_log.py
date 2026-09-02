"""Thread-safe, bounded, in-memory activity feed for the ZTP tab.

WHY THIS EXISTS: every previous real-hardware ZTP test session in
this project required SSH/console-ing into the switch and manually
running `more flash:/ztp_*.log | include ...` to find out what
actually happened -- Keystone itself was blind to everything past
"a file got requested over SFTP". That's the gap this module closes:
every ZTP-related event Keystone CAN observe on its own -- SFTP file
requests from the switch (sftp_server.py), switch-pushed syslog
lines (syslog_server.py, if the device's SYSLOG_INFO is wired up and
working -- see that module's docstring for what's still unverified
there), and the DHCP/SFTP/generate lifecycle events routes.py already
logs to the app log -- gets funneled through record() here so the ZTP
tab has ONE feed to poll instead of a person having to go find a
console cable.

Deliberately NOT a replacement for the switch's own onboard ZTP log:
this can only ever show what Keystone itself observes, or what the
switch is configured to forward. If SYSLOG_INFO turns out to need a
different format than syslog_server.py currently assumes, the feed
will show SFTP-transfer events (still useful -- "which file is it
downloading right now") but nothing about what happens after the
switch finishes downloading and starts applying the config, exactly
like tonight's testing kept getting stuck on.
"""

from __future__ import annotations

import itertools
import threading
import time
from collections import deque

_MAX_EVENTS = 1000

_lock = threading.Lock()
_events = deque(maxlen=_MAX_EVENTS)
_next_id = itertools.count(1)


def record(source, message, esn=None, level="info"):
    """Append one event to the shared feed.

    source: short tag for where this came from -- "sftp", "syslog",
        "dhcp", "generate", "app" -- so the UI can style/filter by it.
    esn: the device this event is about, when known (syslog events
        are keyed by source IP, not ESN -- callers that only have an
        IP should leave this None rather than guess).
    level: "info" | "warning" | "error" -- mirrors the switch's own
        log levels where the source is the switch (syslog), otherwise
        just a normal severity hint for the UI.
    """
    # id assignment AND the append must happen atomically together --
    # multiple threads call record() concurrently (SFTP/syslog server
    # background threads, Flask request threads), and computing the id
    # outside the lock could let two threads interleave such that a
    # higher id gets appended to the deque before a lower one, breaking
    # the "deque order == id order" invariant recent()'s since_id
    # filtering relies on (a client polling with since_id could then
    # miss an event whose id it had already passed).
    with _lock:
        event = {
            "id": next(_next_id),
            "ts": time.time(),
            "source": source,
            "esn": esn,
            "level": level,
            "message": str(message),
        }
        _events.append(event)
    return event


def recent(since_id=0, limit=200):
    """Events with id > since_id, oldest-first, capped at `limit` --
    the frontend polls this with the last id it saw so it only ever
    gets what's new. limit=None returns everything past since_id
    (still bounded by _MAX_EVENTS overall)."""
    with _lock:
        snapshot = list(_events)
    filtered = [e for e in snapshot if e["id"] > since_id]
    if limit:
        filtered = filtered[-limit:]
    return filtered


def clear():
    """Wipe the feed. Call this when a fresh ZTP generate/deploy cycle
    is clearly starting, so a brand new test run doesn't open with a
    screen full of the previous cycle's events."""
    with _lock:
        _events.clear()
