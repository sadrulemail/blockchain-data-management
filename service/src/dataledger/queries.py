"""Read-side queries over the indexed tables, shaped for the API and console."""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from typing import Any

from sqlalchemy import Engine, func, select

from . import db
from .chain import Classification, VersionStatus


def _now() -> int:
    return int(time.time())


def _dataset_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    d["classification_label"] = Classification(d["classification"]).label
    return d


def _version_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    d["status_label"] = VersionStatus(d["status"]).label
    return d


def _quality_by_version(conn, dataset_id: int | None = None) -> dict[tuple[int, int], dict[str, Any]]:
    stmt = select(db.attestations)
    if dataset_id is not None:
        stmt = stmt.where(db.attestations.c.dataset_id == dataset_id)
    grouped: dict[tuple[int, int], list[dict]] = defaultdict(list)
    for row in conn.execute(stmt).mappings():
        grouped[(row["dataset_id"], row["version"])].append(dict(row))
    out = {}
    for key, items in grouped.items():
        out[key] = {
            "count": len(items),
            "passed": sum(1 for i in items if i["passed"]),
            "min_score_bps": min(i["score_bps"] for i in items),
            "attestations": sorted(items, key=lambda i: i["attested_at"]),
        }
    return out


def overview(engine: Engine) -> dict[str, Any]:
    now = _now()
    with engine.connect() as conn:
        scalar = conn.execute
        stats = {
            "datasets": scalar(select(func.count()).select_from(db.datasets)).scalar_one(),
            "versions": scalar(select(func.count()).select_from(db.versions)).scalar_one(),
            "records_anchored": scalar(select(func.coalesce(func.sum(db.versions.c.record_count), 0))).scalar_one(),
            "active_grants": scalar(
                select(func.count())
                .select_from(db.grants)
                .where((db.grants.c.revoked.is_(False)) & (db.grants.c.expires_at > now))
            ).scalar_one(),
            "pending_requests": scalar(
                select(func.count()).select_from(db.access_requests).where(db.access_requests.c.status == "pending")
            ).scalar_one(),
            "attestations": scalar(select(func.count()).select_from(db.attestations)).scalar_one(),
            "reads_logged": scalar(select(func.count()).select_from(db.access_log)).scalar_one(),
            "lineage_edges": scalar(select(func.count()).select_from(db.lineage)).scalar_one(),
            "shredded_objects": scalar(
                select(func.count()).select_from(db.objects).where(db.objects.c.state == "shredded")
            ).scalar_one(),
        }
        by_class = {
            Classification(row.classification).label: row.n
            for row in conn.execute(
                select(db.datasets.c.classification, func.count().label("n")).group_by(db.datasets.c.classification)
            )
        }
    return {"stats": stats, "by_classification": by_class, "recent_activity": audit(engine, limit=8)}


def list_datasets(engine: Engine) -> list[dict[str, Any]]:
    now = _now()
    with engine.connect() as conn:
        datasets = [
            _dataset_dict(r) for r in conn.execute(select(db.datasets).order_by(db.datasets.c.dataset_id)).mappings()
        ]
        latest: dict[int, dict] = {}
        for row in conn.execute(select(db.versions).order_by(db.versions.c.version)).mappings():
            latest[row["dataset_id"]] = _version_dict(row)
        grants = defaultdict(int)
        for row in conn.execute(
            select(db.grants.c.dataset_id, func.count().label("n"))
            .where((db.grants.c.revoked.is_(False)) & (db.grants.c.expires_at > now))
            .group_by(db.grants.c.dataset_id)
        ):
            grants[row.dataset_id] = row.n
        quality = _quality_by_version(conn)
    for d in datasets:
        v = latest.get(d["dataset_id"])
        d["latest_version"] = v
        d["active_grants"] = grants[d["dataset_id"]]
        q = quality.get((d["dataset_id"], v["version"])) if v else None
        d["latest_quality"] = {k: q[k] for k in ("count", "passed", "min_score_bps")} if q else None
    return datasets


def dataset_detail(engine: Engine, dataset_id: int) -> dict[str, Any] | None:
    now = _now()
    with engine.connect() as conn:
        row = conn.execute(select(db.datasets).where(db.datasets.c.dataset_id == dataset_id)).mappings().first()
        if row is None:
            return None
        ds = _dataset_dict(row)
        versions = [
            _version_dict(r)
            for r in conn.execute(
                select(db.versions).where(db.versions.c.dataset_id == dataset_id).order_by(db.versions.c.version.desc())
            ).mappings()
        ]
        parents = defaultdict(list)
        for r in conn.execute(select(db.lineage).where(db.lineage.c.dataset_id == dataset_id)).mappings():
            parents[r["version"]].append({"dataset_id": r["parent_dataset_id"], "version": r["parent_version"]})
        children = defaultdict(list)
        for r in conn.execute(select(db.lineage).where(db.lineage.c.parent_dataset_id == dataset_id)).mappings():
            children[r["parent_version"]].append({"dataset_id": r["dataset_id"], "version": r["version"]})
        names = {r.dataset_id: r.name for r in conn.execute(select(db.datasets.c.dataset_id, db.datasets.c.name))}
        objects = {
            r["anchored_version"]: {
                "state": r["state"],
                "size_bytes": r["size_bytes"],
                "file_name": r["file_name"],
            }
            for r in conn.execute(
                select(db.objects).where(
                    (db.objects.c.dataset_id == dataset_id) & db.objects.c.anchored_version.is_not(None)
                )
            ).mappings()
        }
        quality = _quality_by_version(conn, dataset_id)
        stewards = [
            r.account
            for r in conn.execute(
                select(db.stewards.c.account).where(
                    (db.stewards.c.dataset_id == dataset_id) & db.stewards.c.enabled.is_(True)
                )
            )
        ]
        grants = []
        for r in conn.execute(select(db.grants).where(db.grants.c.dataset_id == dataset_id)).mappings():
            g = dict(r)
            g["active"] = (not g["revoked"]) and g["expires_at"] > now
            grants.append(g)
        requests = [
            dict(r)
            for r in conn.execute(
                select(db.access_requests)
                .where(db.access_requests.c.dataset_id == dataset_id)
                .order_by(db.access_requests.c.request_id.desc())
            ).mappings()
        ]
        reads = [
            dict(r)
            for r in conn.execute(
                select(db.access_log)
                .where(db.access_log.c.dataset_id == dataset_id)
                .order_by(db.access_log.c.id.desc())
                .limit(25)
            ).mappings()
        ]

    def ref(item: dict) -> dict:
        return {**item, "name": names.get(item["dataset_id"], f"dataset {item['dataset_id']}")}

    for v in versions:
        v["parents"] = [ref(p) for p in parents[v["version"]]]
        v["children"] = [ref(c) for c in children[v["version"]]]
        v["object"] = objects.get(v["version"])
        v["quality"] = quality.get((dataset_id, v["version"]))
    ds.update(
        versions=versions,
        stewards=stewards,
        grants=sorted(grants, key=lambda g: (not g["active"], -g["granted_at"])),
        access_requests=requests,
        recent_reads=reads,
        activity=audit(engine, dataset_id=dataset_id, limit=30),
    )
    return ds


def lineage_graph(engine: Engine, dataset_id: int | None = None, version: int | None = None) -> dict[str, Any]:
    with engine.connect() as conn:
        datasets = {r["dataset_id"]: dict(r) for r in conn.execute(select(db.datasets)).mappings()}
        versions = {(r["dataset_id"], r["version"]): dict(r) for r in conn.execute(select(db.versions)).mappings()}
        edges = [
            ((r.parent_dataset_id, r.parent_version), (r.dataset_id, r.version))
            for r in conn.execute(select(db.lineage))
        ]
        quality = _quality_by_version(conn)

    selected = set(versions)
    if dataset_id is not None:
        starts = [k for k in versions if k[0] == dataset_id and (version is None or k[1] == version)]
        up, down = defaultdict(list), defaultdict(list)
        for parent, child in edges:
            up[child].append(parent)
            down[parent].append(child)
        selected = set(starts)
        for graph in (up, down):
            queue = deque(starts)
            while queue:
                node = queue.popleft()
                for nxt in graph[node]:
                    if nxt not in selected:
                        selected.add(nxt)
                        queue.append(nxt)

    nodes = []
    for key in sorted(selected):
        v = versions.get(key)
        ds = datasets.get(key[0], {})
        q = quality.get(key)
        nodes.append(
            {
                "id": f"{key[0]}:{key[1]}",
                "dataset_id": key[0],
                "version": key[1],
                "name": ds.get("name", f"dataset {key[0]}"),
                "classification": Classification(ds.get("classification", 1)).label,
                "status": VersionStatus(v["status"]).label if v else "Unknown",
                "record_count": v["record_count"] if v else None,
                "quality": {"passed": q["passed"], "count": q["count"], "min_score_bps": q["min_score_bps"]}
                if q
                else None,
            }
        )
    links = [{"from": f"{p[0]}:{p[1]}", "to": f"{c[0]}:{c[1]}"} for p, c in edges if p in selected and c in selected]
    return {"nodes": nodes, "edges": links}


def audit(
    engine: Engine, *, dataset_id: int | None = None, limit: int = 100, before_id: int | None = None
) -> list[dict[str, Any]]:
    stmt = select(db.audit_events).order_by(db.audit_events.c.id.desc()).limit(max(1, min(limit, 500)))
    if dataset_id is not None:
        stmt = stmt.where(db.audit_events.c.dataset_id == dataset_id)
    if before_id is not None:
        stmt = stmt.where(db.audit_events.c.id < before_id)
    with engine.connect() as conn:
        rows = []
        for r in conn.execute(stmt).mappings():
            item = dict(r)
            item["details"] = json.loads(item["details"])
            rows.append(item)
    return rows


def access_requests(engine: Engine, status: str | None = None) -> list[dict[str, Any]]:
    stmt = select(db.access_requests, db.datasets.c.name).join(
        db.datasets, db.datasets.c.dataset_id == db.access_requests.c.dataset_id
    )
    if status:
        stmt = stmt.where(db.access_requests.c.status == status)
    with engine.connect() as conn:
        return [dict(r) for r in conn.execute(stmt.order_by(db.access_requests.c.request_id.desc())).mappings()]
