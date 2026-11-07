"""Renders the Mermaid sources in docs/diagrams/*.mmd to light and dark PNGs for the README.

The README embeds the images instead of Mermaid blocks so the diagrams show the same everywhere, without
depending on a Markdown viewer's Mermaid support. Needs Playwright, a local Chrome or Edge, and network access
to load Mermaid from jsDelivr:

    uv run --with playwright python ../scripts/render_diagrams.py
"""

from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

DIAGRAMS = Path(__file__).resolve().parents[1] / "docs" / "diagrams"
MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"
THEMES = {"": "default", "-dark": "dark"}
SCALE = 2

PAGE = f"""<!doctype html>
<html><head><meta charset="utf-8"><script src="{MERMAID}"></script>
<style>html, body {{ margin: 0; background: transparent; }} #out {{ display: inline-block; padding: 8px; }}</style>
</head><body><div id="out"></div></body></html>"""

RENDER = """async ([source, theme]) => {
  mermaid.initialize({
    startOnLoad: false,
    theme,
    fontFamily: 'Segoe UI, Helvetica, Arial, sans-serif',
    flowchart: { useMaxWidth: false },
    sequence: { useMaxWidth: false },
    state: { useMaxWidth: false },
  });
  const { svg } = await mermaid.render('diagram' + Date.now(), source);
  const out = document.getElementById('out');
  out.innerHTML = svg;
  const box = out.getBoundingClientRect();
  return Math.ceil(box.width);
}"""


def main() -> None:
    sources = sorted(DIAGRAMS.glob("*.mmd"))
    widths: dict[str, int] = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome")
        page = browser.new_page(device_scale_factor=SCALE, viewport={"width": 1600, "height": 1200})
        page.set_content(PAGE)
        page.wait_for_function("() => window.mermaid !== undefined")
        for src in sources:
            for suffix, theme in THEMES.items():
                width = page.evaluate(RENDER, [src.read_text(encoding="utf-8"), theme])
                target = DIAGRAMS / f"{src.stem}{suffix}.png"
                page.locator("#out").screenshot(path=str(target), omit_background=True)
                widths[src.stem] = width
                print(f"{target.relative_to(DIAGRAMS.parents[1])}  {width}px")
        browser.close()
    print("README widths: " + json.dumps(widths))


if __name__ == "__main__":
    main()
