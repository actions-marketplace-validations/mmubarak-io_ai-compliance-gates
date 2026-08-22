#!/usr/bin/env python3
"""Make a draw.io SVG export safe to embed in a GitHub README.

draw.io's "Text Settings: HTML" export wraps every label in a
<switch><foreignObject>…</foreignObject><text>…</text></switch>. Browsers
render the foreignObject; GitHub sanitises SVG in markdown and drops it,
falling back to the <text> element, which draw.io writes as a clipped
single line ("UAE PDPL..."). The diagram then loses exactly the detail it
exists to show.

This rewrites each switch into a plain <text> with one <tspan> per line,
taking the full text from the foreignObject and the position, colour and
font from the fallback. The result renders identically everywhere and keeps
draw.io's light-dark() fills, so it still adapts to GitHub's dark mode.

Usage:
    python tools/fix_drawio_svg.py docs/architecture.svg
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

SVG = "http://www.w3.org/2000/svg"
XHTML = "http://www.w3.org/1999/xhtml"
LINE_HEIGHT = 1.2


def _innermost_divs(el):
    """Divs that contain text but no nested div, i.e. the real label."""
    divs = [d for d in el.iter(f"{{{XHTML}}}div")]
    return [d for d in divs if not any(c.tag == f"{{{XHTML}}}div" for c in d.iter() if c is not d)]


def _lines(el) -> list[str]:
    """Text of an element, split on <br>."""
    out = [""]

    def walk(node):
        for child in node:
            if child.tag == f"{{{XHTML}}}br":
                out.append("")
            else:
                if child.text:
                    out[-1] += child.text
                walk(child)
            if child.tail:
                out[-1] += child.tail

    if el.text:
        out[-1] += el.text
    walk(el)
    return [ln.strip() for ln in out if ln.strip()]


def convert(path: str) -> int:
    ET.register_namespace("", SVG)
    tree = ET.parse(path)
    root = tree.getroot()

    # ElementTree cannot reach a parent, so map children back to parents first.
    parents = {child: parent for parent in root.iter() for child in parent}
    rewritten = 0

    for sw in list(root.iter(f"{{{SVG}}}switch")):
        fo = sw.find(f"{{{SVG}}}foreignObject")
        fallback = sw.find(f"{{{SVG}}}text")
        if fo is None or fallback is None:
            continue

        candidates = _innermost_divs(fo)
        lines: list[str] = []
        for div in candidates:
            lines = _lines(div)
            if lines:
                break
        if not lines:
            continue

        size = float(str(fallback.get("font-size", "12px")).rstrip("px") or 12)
        step = size * LINE_HEIGHT
        x = fallback.get("x", "0")
        y = float(fallback.get("y", "0"))
        start = y - (len(lines) - 1) * step / 2

        text = ET.Element(f"{{{SVG}}}text")
        for key, value in fallback.attrib.items():
            if key not in ("x", "y"):
                text.set(key, value)
        text.set("x", x)
        text.set("y", f"{start:g}")
        for i, line in enumerate(lines):
            tspan = ET.SubElement(text, f"{{{SVG}}}tspan")
            tspan.set("x", x)
            tspan.set("y", f"{start + i * step:g}")
            tspan.text = line

        parent = parents[sw]
        parent[list(parent).index(sw)] = text
        rewritten += 1

    tree.write(path, encoding="utf-8", xml_declaration=False)
    return rewritten


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    n = convert(sys.argv[1])
    print(f"rewrote {n} label(s) from foreignObject to tspan text")
