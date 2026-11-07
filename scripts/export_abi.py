"""Copies contract ABIs from the Foundry build into the service package.

Run after `forge build`; CI fails when the committed ABIs drift from the contracts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "contracts" / "out"
TARGET = ROOT / "service" / "src" / "dataledger" / "abi"
CONTRACTS = ("DataRegistry", "AccessLedger", "QualityLedger")


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    for name in CONTRACTS:
        artifact = OUT / f"{name}.sol" / f"{name}.json"
        if not artifact.exists():
            print(f"missing {artifact}; run `forge build` in contracts/ first", file=sys.stderr)
            return 1
        abi = json.loads(artifact.read_text(encoding="utf-8"))["abi"]
        (TARGET / f"{name}.json").write_text(json.dumps(abi, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {name}.json ({len(abi)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
