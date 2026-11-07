"""Generates the reference datasets in datasets/ (deterministic, fixed seed).

The September orders extract carries real-world defects on purpose (missing customer ids and a double-booked
order) so the quality ledger has something to catch; the October extract is the corrected, extended version.
"""

from __future__ import annotations

import csv
import io
import random
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "datasets"
RNG = random.Random(2026)

COUNTRIES = {
    "United States": "North America",
    "Canada": "North America",
    "Germany": "EMEA",
    "United Kingdom": "EMEA",
    "France": "EMEA",
    "Netherlands": "EMEA",
    "Bangladesh": "APAC",
    "India": "APAC",
    "Singapore": "APAC",
    "Australia": "APAC",
    "Brazil": "LATAM",
    "Mexico": "LATAM",
}
PREFIX = ["North", "Blue", "Summit", "Iron", "Green", "Bright", "Atlas", "Delta", "Harbor", "Nova", "Silver", "Prime"]
CORE = ["River", "Peak", "Field", "Stone", "Wave", "Bridge", "Forge", "Grove", "Point", "Gate", "Ridge", "Lake"]
SUFFIX = ["Logistics", "Health", "Foods", "Retail", "Energy", "Labs", "Systems", "Clinics", "Motors", "Supply"]
FIRST = ["amira", "ben", "chen", "dana", "elif", "farid", "grace", "hiro", "isha", "jonas", "kemal", "lena", "maya"]
LAST = ["rahman", "okafor", "silva", "novak", "hughes", "tanaka", "khan", "meyer", "ortiz", "lindqvist", "das"]
SEGMENTS = ["Enterprise", "Mid-market", "SMB"]
CATEGORIES = {
    "Sensors": (35, 180),
    "Gateways": (220, 640),
    "Storage": (90, 420),
    "Software": (49, 899),
    "Services": (150, 1200),
    "Accessories": (9, 60),
}
PRODUCT_NAMES = {
    "Sensors": "Sensor",
    "Gateways": "Gateway",
    "Storage": "Storage array",
    "Software": "Software licence",
    "Services": "Service plan",
    "Accessories": "Accessory kit",
}
STATUSES = ["delivered"] * 14 + ["shipped"] * 4 + ["returned", "cancelled"]


def write_csv(name: str, header: list[str], rows: list[list[object]]) -> None:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    (ROOT / name).write_text(buf.getvalue(), encoding="utf-8", newline="\n")
    print(f"{name}: {len(rows)} rows")


def customers() -> list[list[object]]:
    rows, names = [], set()
    while len(rows) < 240:
        company = f"{RNG.choice(PREFIX)} {RNG.choice(CORE)} {RNG.choice(SUFFIX)}"
        if company in names:
            continue
        names.add(company)
        country = RNG.choice(list(COUNTRIES))
        domain = company.lower().replace(" ", "") + ".example"
        email = f"{RNG.choice(FIRST)}.{RNG.choice(LAST)}@{domain}"
        signup = date(2023, 1, 1) + timedelta(days=RNG.randint(0, 990))
        segment = RNG.choices(SEGMENTS, weights=[2, 3, 5])[0]
        rows.append([5000 + len(rows) + 1, company, email, country, COUNTRIES[country], segment, signup.isoformat()])
    return rows


def catalog() -> list[list[object]]:
    rows = []
    for category, (low, high) in CATEGORIES.items():
        for i in range(1, 7):
            sku = f"{category[:3].upper()}-{100 + i * 7}"
            price = round(RNG.uniform(low, high), 2)
            rows.append([sku, f"{PRODUCT_NAMES[category]} {chr(64 + i)}{i * 10}", category, price, "true"])
    return rows


def orders(customer_rows, catalog_rows, start: date, days: int, first_id: int, count: int) -> list[list[object]]:
    rows = []
    for n in range(count):
        customer = RNG.choice(customer_rows)
        product = RNG.choice(catalog_rows)
        weight = {"Enterprise": 6, "Mid-market": 3, "SMB": 1}[customer[5]]
        quantity = RNG.randint(1, 4 * weight)
        discount = RNG.choice([1, 1, 1, 0.95, 0.9, 0.85])
        unit_price = round(float(product[3]) * discount, 2)
        order_date = start + timedelta(days=RNG.randint(0, days - 1))
        rows.append([first_id + n, customer[0], order_date.isoformat(), product[0], quantity, f"{unit_price:.2f}",
                     "USD", RNG.choice(STATUSES)])
    rows.sort(key=lambda r: (r[2], r[0]))
    return rows


def main() -> None:
    ROOT.mkdir(exist_ok=True)
    cust = customers()
    cat = catalog()
    write_csv(
        "crm_customers_2026-09.csv",
        ["customer_id", "company_name", "contact_email", "country", "region", "segment", "signup_date"],
        cust,
    )
    write_csv("product_catalog_2026-09.csv", ["sku", "product_name", "category", "list_price", "active"], cat)

    header = ["order_id", "customer_id", "order_date", "sku", "quantity", "unit_price", "currency", "status"]
    september = orders(cust, cat, date(2026, 9, 1), 30, 700_001, 720)
    october = orders(cust, cat, date(2026, 10, 1), 31, 700_721, 780)

    flawed = [list(r) for r in september]
    for i in (41, 233, 518):
        flawed[i][1] = ""
    flawed.insert(300, list(flawed[299]))
    write_csv("sales_orders_2026-09.csv", header, flawed)
    write_csv("sales_orders_2026-10.csv", header, september + october)


if __name__ == "__main__":
    main()
