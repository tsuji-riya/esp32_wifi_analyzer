#!/usr/bin/env python3
"""Bundle the Primer CSS subset the web UI uses into firmware/web/primer.css.gz.

The Mac reaches the ESP32 over its own access point (no internet), so the CSS is served
from flash instead of a CDN. Only the light/dark themes and the used modules are kept.

    npm pack @primer/css@21.5.1 && tar -xzf primer-css-21.5.1.tgz
    python3 tools/build_primer.py package/dist
"""
import gzip
import pathlib
import re
import sys

MODULES = "primitives base utilities layout box buttons labels forms navigation header alerts progress".split()
# color-modes.css holds 18 theme blocks; keep light, dark, and auto(dark) only.
THEMES = (
    "[data-color-mode=light][data-light-theme=light]",
    "[data-color-mode=dark][data-dark-theme=dark]",
    "@media(prefers-color-scheme: dark){[data-color-mode=auto][data-dark-theme=dark]",
)


def top_level_blocks(css):
    depth, start = 0, 0
    for i, c in enumerate(css):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                yield css[start : i + 1]
                start = i + 1


def main(dist):
    dist = pathlib.Path(dist)
    themes = [b for b in top_level_blocks((dist / "color-modes.css").read_text()) if b.startswith(THEMES)]
    assert len(themes) == len(THEMES), f"expected {len(THEMES)} theme blocks, got {len(themes)}"
    css = "".join(themes) + "".join((dist / f"{m}.css").read_text() for m in MODULES)
    css = re.sub(r"/\*# sourceMappingURL=[^*]*\*/", "", css)
    out = pathlib.Path(__file__).resolve().parent.parent / "firmware/web/primer.css.gz"
    out.write_bytes(gzip.compress(css.encode(), compresslevel=9, mtime=0))
    print(f"{out}: {len(css)} -> {out.stat().st_size} bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "package/dist")
