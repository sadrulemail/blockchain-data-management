"""Baseline schema: the read models and service tables of release 1.0.0.

Revision ID: 0001
Revises:
Create Date: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "access_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("accessor", sa.String(length=42), nullable=False),
        sa.Column("receipt_hash", sa.String(length=66), nullable=False),
        sa.Column("accessed_at", sa.BigInteger(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("tx_hash", sa.String(length=66), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "access_requests",
        sa.Column("request_id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("requester", sa.String(length=42), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("purpose_hash", sa.String(length=66), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_at", sa.BigInteger(), nullable=False),
        sa.Column("decided_by", sa.String(length=42), nullable=True),
        sa.Column("decided_at", sa.BigInteger(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("request_id"),
    )
    op.create_table(
        "attestations",
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("auditor", sa.String(length=42), nullable=False),
        sa.Column("score_bps", sa.Integer(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("report_hash", sa.String(length=66), nullable=False),
        sa.Column("report_uri", sa.Text(), nullable=False),
        sa.Column("attested_at", sa.BigInteger(), nullable=False),
        sa.Column("tx_hash", sa.String(length=66), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id", "version", "auditor"),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("contract", sa.String(length=32), nullable=True),
        sa.Column("event", sa.String(length=48), nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(length=42), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.BigInteger(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=True),
        sa.Column("tx_hash", sa.String(length=66), nullable=True),
        sa.Column("log_index", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tx_hash", "log_index", name="uq_audit_log_position"),
    )
    op.create_table(
        "datasets",
        sa.Column("dataset_id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("owner", sa.String(length=42), nullable=False),
        sa.Column("pending_owner", sa.String(length=42), nullable=True),
        sa.Column("classification", sa.Integer(), nullable=False),
        sa.Column("schema_hash", sa.String(length=66), nullable=False),
        sa.Column("metadata_uri", sa.Text(), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False),
        sa.Column("version_count", sa.Integer(), nullable=False),
        sa.Column("access_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("created_block", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id"),
    )
    op.create_table(
        "documents",
        sa.Column("doc_hash", sa.String(length=66), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=42), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("doc_hash"),
    )
    op.create_table(
        "grants",
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("grantee", sa.String(length=42), nullable=False),
        sa.Column("granted_by", sa.String(length=42), nullable=False),
        sa.Column("purpose_hash", sa.String(length=66), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=True),
        sa.Column("granted_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id", "grantee"),
    )
    op.create_table(
        "indexer_state",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "lineage",
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("parent_dataset_id", sa.Integer(), nullable=False),
        sa.Column("parent_version", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id", "version", "parent_dataset_id", "parent_version"),
    )
    op.create_table(
        "objects",
        sa.Column("object_id", sa.String(length=64), nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=66), nullable=False),
        sa.Column("merkle_root", sa.String(length=66), nullable=False),
        sa.Column("schema_hash", sa.String(length=66), nullable=False),
        sa.Column("schema_document", sa.String(length=66), nullable=False),
        sa.Column("record_count", sa.BigInteger(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=False),
        sa.Column("kek_id", sa.String(length=32), nullable=True),
        sa.Column("wrapped_key", sa.LargeBinary(), nullable=True),
        sa.Column("uploaded_by", sa.String(length=42), nullable=False),
        sa.Column("uploaded_at", sa.BigInteger(), nullable=False),
        sa.Column("anchored_version", sa.Integer(), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("shredded_at", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("object_id"),
    )
    op.create_table(
        "stewards",
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("account", sa.String(length=42), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id", "account"),
    )
    op.create_table(
        "versions",
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("merkle_root", sa.String(length=66), nullable=False),
        sa.Column("content_hash", sa.String(length=66), nullable=False),
        sa.Column("schema_hash", sa.String(length=66), nullable=True),
        sa.Column("record_count", sa.BigInteger(), nullable=False),
        sa.Column("storage_uri", sa.Text(), nullable=False),
        sa.Column("committer", sa.String(length=42), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("committed_at", sa.BigInteger(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("tx_hash", sa.String(length=66), nullable=False),
        sa.PrimaryKeyConstraint("dataset_id", "version"),
    )


def downgrade() -> None:
    op.drop_table("versions")
    op.drop_table("stewards")
    op.drop_table("objects")
    op.drop_table("lineage")
    op.drop_table("indexer_state")
    op.drop_table("grants")
    op.drop_table("documents")
    op.drop_table("datasets")
    op.drop_table("audit_events")
    op.drop_table("attestations")
    op.drop_table("access_requests")
    op.drop_table("access_log")
