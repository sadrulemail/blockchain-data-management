"""Secondary indexes for the catalogue, audit trail and access filters.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-16
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

INDEXES = (
    ("ix_lineage_parent", "lineage", ["parent_dataset_id", "parent_version"]),
    ("ix_access_requests_dataset", "access_requests", ["dataset_id"]),
    ("ix_access_requests_status", "access_requests", ["status"]),
    ("ix_access_log_dataset", "access_log", ["dataset_id"]),
    ("ix_audit_events_dataset", "audit_events", ["dataset_id"]),
    ("ix_objects_dataset", "objects", ["dataset_id"]),
)


def upgrade() -> None:
    for name, table, columns in INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _ in reversed(INDEXES):
        op.drop_index(name, table_name=table)
