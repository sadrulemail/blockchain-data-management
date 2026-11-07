"""Loads the reference datasets through the running API and chain, acting as each team in turn.

Run from service/ after `anvil`, the deploy script and `dataledger serve` are up:

    uv run python ../scripts/load_reference_data.py

It plays out a full data-governance cycle: registration, stewardship, versioning with a quality failure and a
fix, access requests (approved and rejected), a derived dataset with lineage, independent quality attestations,
a partner share, and a right-to-erasure request that withdraws and crypto-shreds a version.
"""

from __future__ import annotations

import csv
import io
import sys
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

from eth_account import Account

from dataledger.canonical import Schema
from dataledger.chain import Chain, Classification, Deployment, VersionStatus
from dataledger.client import ApiClient
from dataledger.config import get_settings
from dataledger.workflows import audit_quality, publish_version, register_dataset

DATASETS = Path(__file__).resolve().parents[1] / "datasets"
DAY = 86_400

# Default anvil development accounts; these keys only exist on a local chain.
KEYS = {
    "admin": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "gateway": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "auditor": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "sales": "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "finance": "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "partner": "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "engineer": "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
}
ERASED_CUSTOMER = "5017"


def step(text: str) -> None:
    print(f"\n== {text}")


def schema(name: str) -> Schema:
    return Schema.from_file(DATASETS / "schemas" / f"{name}.json")


def read(name: str) -> bytes:
    return (DATASETS / name).read_bytes()


def rows(data: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(data.decode("utf-8"), newline="")))


def to_csv(header: list[str], records: list[dict[str, object]]) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return buf.getvalue().encode("utf-8")


def revenue_by_region(orders: bytes, customers: bytes, catalog: bytes) -> bytes:
    """The finance transformation: join orders to customers and catalog, keep billable lines, aggregate."""
    region = {c["customer_id"]: c["region"] for c in rows(customers)}
    category = {p["sku"]: p["category"] for p in rows(catalog)}
    groups: dict[tuple[str, str, str], dict] = defaultdict(lambda: {"orders": set(), "units": 0, "revenue": Decimal()})
    for o in rows(orders):
        if o["status"] not in ("delivered", "shipped") or o["customer_id"] not in region:
            continue
        key = (o["order_date"][:7], region[o["customer_id"]], category[o["sku"]])
        g = groups[key]
        g["orders"].add(o["order_id"])
        g["units"] += int(o["quantity"])
        g["revenue"] += Decimal(o["unit_price"]) * int(o["quantity"])
    out = [
        {
            "month": k[0],
            "region": k[1],
            "category": k[2],
            "orders": len(g["orders"]),
            "units": g["units"],
            "net_revenue": f"{g['revenue']:.2f}",
        }
        for k, g in sorted(groups.items())
    ]
    return to_csv(["month", "region", "category", "orders", "units", "net_revenue"], out)


def main() -> int:
    settings = get_settings()
    chain = Chain(settings.rpc_url, Deployment.load(settings.deployment_file))
    api = ApiClient(settings.api_url)
    print(f"API {settings.api_url} on chain {api.health()['chain_id']}")
    if chain.dataset_count() > 0:
        print("datasets already registered on this deployment; redeploy for a clean load", file=sys.stderr)
        return 1
    acct = {role: Account.from_key(key) for role, key in KEYS.items()}
    sales, finance, auditor, partner, engineer = (acct[r] for r in ("sales", "finance", "auditor", "partner", "engineer"))

    step("Platform admin grants publisher, gateway and auditor roles")
    for team in (sales, finance):
        chain.grant_role(acct["admin"], "DataRegistry", "PUBLISHER_ROLE", team.address)
    chain.grant_role(acct["admin"], "AccessLedger", "GATEWAY_ROLE", acct["gateway"].address)
    chain.grant_role(acct["admin"], "QualityLedger", "AUDITOR_ROLE", auditor.address)

    step("Sales operations registers its datasets")
    customers_id = register_dataset(chain, api, sales, schema("crm_customers"), Classification.CONFIDENTIAL)
    orders_id = register_dataset(chain, api, sales, schema("sales_orders"), Classification.INTERNAL)
    catalog_id = register_dataset(chain, api, sales, schema("product_catalog"), Classification.PUBLIC)
    chain.set_steward(sales, orders_id, engineer.address, True)
    print(f"crm_customers={customers_id} sales_orders={orders_id} product_catalog={catalog_id}")

    step("Publishing September extracts (orders published by the data engineer as steward)")
    customers_v1 = publish_version(chain, api, sales, customers_id, read("crm_customers_2026-09.csv"), "crm_customers_2026-09.csv")
    catalog_v1 = publish_version(chain, api, sales, catalog_id, read("product_catalog_2026-09.csv"), "product_catalog_2026-09.csv")
    orders_v1 = publish_version(chain, api, engineer, orders_id, read("sales_orders_2026-09.csv"), "sales_orders_2026-09.csv")
    print(f"orders v{orders_v1.version}: {orders_v1.staged['record_count']} records, root {orders_v1.staged['merkle_root'][:18]}...")

    step("Publishing the corrected October extract and deprecating September")
    orders_v2 = publish_version(chain, api, engineer, orders_id, read("sales_orders_2026-10.csv"), "sales_orders_2026-10.csv")
    chain.set_version_status(
        engineer, orders_id, orders_v1.version, VersionStatus.DEPRECATED, "Superseded by the corrected October extract"
    )

    step("Finance analytics requests access to orders and customers")
    purpose = "Monthly revenue reporting for the finance close"
    for dataset_id in (orders_id, customers_id):
        request_id = chain.request_access(finance, dataset_id, purpose)
        chain.approve_request(sales, request_id, 90 * DAY)
        print(f"request #{request_id} on dataset {dataset_id} approved for 90 days")

    step("Finance reads the inputs through the gateway (each read logged on-chain)")
    fin = api.as_account(finance)
    orders, _ = fin.download(orders_id, orders_v2.version)
    customers, _ = fin.download(customers_id, customers_v1.version)
    catalog, _ = fin.download(catalog_id, catalog_v1.version)

    step("Finance publishes revenue_by_region with lineage to its three inputs")
    revenue_id = register_dataset(chain, api, finance, schema("revenue_by_region"), Classification.INTERNAL)
    revenue_v1 = publish_version(
        chain,
        api,
        finance,
        revenue_id,
        revenue_by_region(orders, customers, catalog),
        "revenue_by_region_2026-10.csv",
        parents=[(orders_id, orders_v2.version), (customers_id, customers_v1.version), (catalog_id, catalog_v1.version)],
    )
    print(f"revenue_by_region={revenue_id} v{revenue_v1.version}: {revenue_v1.staged['record_count']} rows")

    step("Independent quality audit")
    review = "Independent data-quality review"
    for dataset_id in (orders_id, customers_id):
        chain.grant_access(sales, dataset_id, auditor.address, 14 * DAY, review)
    chain.grant_access(finance, revenue_id, auditor.address, 14 * DAY, review)
    for dataset_id, version in (
        (orders_id, orders_v1.version),
        (orders_id, orders_v2.version),
        (customers_id, customers_v1.version),
        (catalog_id, catalog_v1.version),
        (revenue_id, revenue_v1.version),
    ):
        report = audit_quality(chain, api, auditor, dataset_id, version)
        verdict = "passed" if report["passed"] else "FAILED"
        print(f"dataset {dataset_id} v{version}: {report['score_bps'] / 100:.1f}% {verdict}")

    step("Partner access: aggregate shared, customer contacts refused")
    request_id = chain.request_access(partner, revenue_id, "Joint regional go-to-market planning")
    chain.approve_request(finance, request_id, 30 * DAY)
    api.as_account(partner).download(revenue_id, revenue_v1.version)
    request_id = chain.request_access(partner, customers_id, "Lead enrichment for partner campaigns")
    chain.reject_request(sales, request_id, "Customer contact data is not shared outside the company")

    step(f"Right-to-erasure request from customer {ERASED_CUSTOMER}")
    remaining = [r for r in rows(customers) if r["customer_id"] != ERASED_CUSTOMER]
    customers_v2 = publish_version(
        chain,
        api,
        sales,
        customers_id,
        to_csv(list(remaining[0].keys()), remaining),
        "crm_customers_2026-11.csv",
    )
    chain.set_version_status(
        sales, customers_id, customers_v1.version, VersionStatus.WITHDRAWN, f"Erasure request: customer {ERASED_CUSTOMER}"
    )
    shredded = api.as_account(sales).shred(customers_id, customers_v1.version)
    print(f"customers v{customers_v2.version} published; v{customers_v1.version} withdrawn and {shredded['state']}")

    head = chain.block_number
    api.wait_for_block(head, timeout=60)
    stats = api.overview()["stats"]
    print(f"\nIndexed to block {head}: " + ", ".join(f"{k}={v}" for k, v in stats.items()))
    print(f"Console: {settings.api_url}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
