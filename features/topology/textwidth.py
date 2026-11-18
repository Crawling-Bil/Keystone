"""How wide a piece of text is on the picture, from the real letter widths of the bold sans-serif the pages use (Arial / Helvetica Bold / Liberation Sans Bold).

The old estimate was a flat 7 px per letter at 12 px: close for lower case, too small for hostnames in capitals and digits (``HQ-DC-CORE1`` measures 8.3 px a letter), which is how two
neighbouring names ended up overlapping.  The table holds the advance width of each printable ASCII letter in 1/1000 of the font size (the AFM widths of Helvetica Bold, the same in Arial
Bold and Liberation Sans Bold): https://www.adobe.com/devnet/font/pdfs/5004.AFM_Spec.pdf (AFM file format) ; https://learn.microsoft.com/en-us/typography/font-list/arial (Arial).
"""

from __future__ import annotations

_BOLD = {
    238: "'", 278: " ,./I\\ijl", 280: "|", 333: "!()-:;[]`ft", 389: "*r{}", 474: '"', 500: "z", 556: "#$0123456789J_aceksvxy", 584: "+<=>^~",
    611: "?FLTZbdghnopqu", 667: "EPSVXY", 722: "&ABCDHKNRU", 778: "GOQw", 833: "M", 889: "%m", 944: "W", 975: "@",
}
WIDTH = {ch: units for units, chars in _BOLD.items() for ch in chars}
FALLBACK = 611                      # a letter outside printable ASCII (an accent, a symbol): about the width of an average capital


def text_width(text: str, size: float = 12.0) -> float:
    """Width in px of ``text`` set in bold at ``size`` px."""
    return sum(WIDTH.get(ch, FALLBACK) for ch in text) * size / 1000.0


def widest(lines, size: float = 12.0, limit: int = 34) -> float:
    """The widest of several lines, each cut to ``limit`` letters like the picture does (``svg``): the room one icon's caption asks for."""
    return max((text_width(line[:limit], size) for line in lines if line), default=0.0)
