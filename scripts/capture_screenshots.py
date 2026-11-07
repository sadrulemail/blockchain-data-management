"""Captures the console screenshots used in the README (needs Playwright and a local Chrome or Edge).

    uv run --with playwright python ../scripts/capture_screenshots.py [edited.csv] [proof.json]
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
OUT = Path(__file__).resolve().parents[1] / "docs" / "screenshots"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    edited = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    proof = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome")
        page = browser.new_page(viewport={"width": 1440, "height": 900}, color_scheme="light")

        def shot(route: str, name: str, ready: str, full: bool = False) -> None:
            page.goto(f"{BASE}/#/{route}")
            page.wait_for_selector(ready)
            page.wait_for_timeout(400)
            page.screenshot(path=OUT / f"{name}.png", full_page=full)
            print(f"{name}.png")

        shot("overview", "overview", ".kpi")
        shot("datasets", "datasets", "tbody tr")
        shot("datasets/2", "dataset-versions", ".version")
        shot("lineage", "lineage", "svg .node")
        shot("access", "access", "tbody tr")
        shot("audit", "audit-trail", "#audit-rows tr")

        page.goto(f"{BASE}/#/datasets/1")
        page.wait_for_selector(".version")
        page.click("button[data-tab=access]")
        page.wait_for_timeout(300)
        page.screenshot(path=OUT / "dataset-access.png")
        page.evaluate("sessionStorage.removeItem('ds-tab')")
        print("dataset-access.png")

        if edited:
            page.goto(f"{BASE}/#/verify")
            page.wait_for_selector("#verify-file")
            page.set_input_files("#verify-file input[type=file]", str(edited))
            page.select_option("#verify-file select", label="sales_orders v2 (Active)")
            page.click("#verify-file button")
            page.wait_for_selector("#file-result .result")
            if proof:
                page.fill("#verify-record textarea", proof.read_text(encoding="utf-8"))
                page.click("#verify-record button")
                page.wait_for_selector("#record-result .result")
            page.wait_for_timeout(300)
            page.screenshot(path=OUT / "verify.png")
            print("verify.png")
        browser.close()


if __name__ == "__main__":
    main()
