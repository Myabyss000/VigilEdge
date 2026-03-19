"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-03-17 00:00:00.000000

This migration captures the schema that was previously created by
Base.metadata.create_all() at startup.  It is the baseline from which all
future schema changes will be tracked via Alembic.

Upgrade path from an existing SQLite database
----------------------------------------------
If you already have a threatloom.db from create_all() and are migrating to
PostgreSQL for the first time:

  1. Dump data from SQLite:
       python -c "
       import sqlite3, json
       conn = sqlite3.connect('threatloom.db')
       for tbl in conn.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall():
           rows = conn.execute(f'SELECT * FROM {tbl[0]}').fetchall()
           cols = [d[0] for d in conn.execute(f'PRAGMA table_info({tbl[0]})').fetchall()]
           print(json.dumps({'table': tbl[0], 'columns': cols, 'rows': [list(r) for r in rows]}))
       " > sqlite_export.jsonl

  2. Create the PostgreSQL schema:
       APP_ENV=production DATABASE_URL=postgresql+asyncpg://... alembic upgrade head

  3. Load data using your preferred ETL tool (pgloader, custom script, etc.)

  4. Stamp the database so Alembic knows it is at the current revision:
       Already done by step 2 above.

If you have a BRAND NEW empty PostgreSQL database just run:
       APP_ENV=production DATABASE_URL=postgresql+asyncpg://... alembic upgrade head
"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column(
            "role",
            sa.Enum("VIEWER", "SOC_ANALYST", "ADMIN", name="userrole"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean, nullable=True),
        sa.Column("full_name", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("last_login", sa.DateTime, nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── playbooks ─────────────────────────────────────────────────────────────
    op.create_table(
        "playbooks",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "status",
            sa.Enum("ACTIVE", "DISABLED", "DRAFT", name="playbookstatus"),
            nullable=True,
        ),
        sa.Column("trigger_conditions", sa.Text, nullable=False),
        sa.Column("actions", sa.Text, nullable=False),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("updated_at", sa.DateTime, nullable=True),
        sa.Column("cooldown_seconds", sa.Integer, nullable=True),
        sa.Column("max_auto_executions", sa.Integer, nullable=True),
    )
    op.create_index("ix_playbooks_name", "playbooks", ["name"], unique=True)

    # ── incidents ─────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("incident_uid", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "status",
            sa.Enum("NEW", "INVESTIGATING", "MITIGATED", "CLOSED", "REOPENED", name="incidentstatus"),
            nullable=False,
        ),
        sa.Column(
            "priority",
            sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="incidentpriority"),
            nullable=False,
        ),
        sa.Column("affected_ips", sa.Text, nullable=True),
        sa.Column("affected_paths", sa.Text, nullable=True),
        sa.Column("attack_types", sa.Text, nullable=True),
        sa.Column("mitre_tactics", sa.Text, nullable=True),
        sa.Column("mitre_techniques", sa.Text, nullable=True),
        sa.Column("assigned_to", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
        sa.Column("closed_at", sa.DateTime, nullable=True),
        sa.Column("response_summary", sa.Text, nullable=True),
        sa.Column("playbook_id", sa.Integer, sa.ForeignKey("playbooks.id"), nullable=True),
    )
    op.create_index("ix_incidents_incident_uid", "incidents", ["incident_uid"], unique=True)
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_status_priority", "incidents", ["status", "priority"])

    # ── firewall_logs ─────────────────────────────────────────────────────────
    op.create_table(
        "firewall_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("timestamp", sa.DateTime, nullable=False),
        sa.Column("received_at", sa.DateTime, nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer, nullable=True),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("dst_port", sa.Integer, nullable=True),
        sa.Column(
            "protocol",
            sa.Enum("HTTP", "HTTPS", "TCP", "UDP", "DNS", "ICMP", "OTHER", name="logprotocol"),
            nullable=False,
        ),
        sa.Column(
            "action",
            sa.Enum("ALLOWED", "BLOCKED", "RATE_LIMITED", "DROPPED", "FLAGGED", name="logaction"),
            nullable=False,
        ),
        sa.Column("http_method", sa.String(10), nullable=True),
        sa.Column("http_path", sa.Text, nullable=True),
        sa.Column("http_status", sa.Integer, nullable=True),
        sa.Column("http_user_agent", sa.Text, nullable=True),
        sa.Column("http_host", sa.String(255), nullable=True),
        sa.Column("http_referer", sa.Text, nullable=True),
        sa.Column(
            "attack_type",
            sa.Enum(
                "NONE", "SQLI", "XSS", "RCE", "LFI", "RFI", "BRUTE_FORCE", "PORT_SCAN",
                "DDOS", "DIRECTORY_TRAVERSAL", "COMMAND_INJECTION", "SSRF", "XXE", "CSRF",
                "BOT", "OTHER",
                name="attacktype",
            ),
            nullable=False,
        ),
        sa.Column("attack_signature", sa.String(255), nullable=True),
        sa.Column(
            "severity",
            sa.Enum("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="logseverity"),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("matched_rule", sa.String(255), nullable=True),
        sa.Column("payload_snippet", sa.Text, nullable=True),
        sa.Column("geo_country", sa.String(2), nullable=True),
        sa.Column("geo_city", sa.String(128), nullable=True),
        sa.Column("geo_lat", sa.Float, nullable=True),
        sa.Column("geo_lon", sa.Float, nullable=True),
        sa.Column("geo_asn", sa.String(128), nullable=True),
        sa.Column("session_id", sa.String(64), nullable=True),
        sa.Column("mitre_tactic", sa.String(64), nullable=True),
        sa.Column("mitre_technique", sa.String(64), nullable=True),
        sa.Column("raw_log", sa.Text, nullable=True),
        sa.Column("source_format", sa.String(16), nullable=True),
        sa.Column("ingestion_pipeline", sa.String(64), nullable=True),
        sa.Column("tier", sa.String(8), nullable=True),
        sa.Column("dns_query", sa.String(255), nullable=True),
        sa.Column("dns_response", sa.String(255), nullable=True),
        sa.Column("sys_cpu", sa.Float, nullable=True),
        sa.Column("sys_memory", sa.Float, nullable=True),
        sa.Column("sys_latency_ms", sa.Float, nullable=True),
    )
    op.create_index("ix_firewall_logs_timestamp", "firewall_logs", ["timestamp"])
    op.create_index("ix_firewall_logs_src_ip", "firewall_logs", ["src_ip"])
    op.create_index("ix_firewall_logs_action", "firewall_logs", ["action"])
    op.create_index("ix_firewall_logs_attack_type", "firewall_logs", ["attack_type"])
    op.create_index("ix_firewall_logs_severity", "firewall_logs", ["severity"])
    op.create_index("ix_firewall_logs_session_id", "firewall_logs", ["session_id"])
    op.create_index("ix_logs_src_ip_timestamp", "firewall_logs", ["src_ip", "timestamp"])
    op.create_index("ix_logs_attack_timestamp", "firewall_logs", ["attack_type", "timestamp"])
    op.create_index("ix_logs_severity_timestamp", "firewall_logs", ["severity", "timestamp"])

    # ── alerts ────────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("alert_uid", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "severity",
            sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="alertseverity"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "NEW", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE", "ESCALATED",
                name="alertstatus",
            ),
            nullable=False,
        ),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("detection_source", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=True),
        sa.Column("attack_type", sa.String(64), nullable=True),
        sa.Column("src_ip", sa.String(45), nullable=True),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("http_path", sa.Text, nullable=True),
        sa.Column("session_id", sa.String(64), nullable=True),
        sa.Column("geo_country", sa.String(2), nullable=True),
        sa.Column("mitre_tactic", sa.String(64), nullable=True),
        sa.Column("mitre_technique", sa.String(64), nullable=True),
        sa.Column("correlated_log_ids", sa.Text, nullable=True),
        sa.Column("event_count", sa.Integer, nullable=True),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column("resolved_at", sa.DateTime, nullable=True),
        sa.Column("assigned_to", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("auto_response_taken", sa.Boolean, nullable=True),
        sa.Column("response_action", sa.String(64), nullable=True),
    )
    op.create_index("ix_alerts_alert_uid", "alerts", ["alert_uid"], unique=True)
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_src_ip", "alerts", ["src_ip"])
    op.create_index("ix_alerts_severity_status", "alerts", ["severity", "status"])
    op.create_index("ix_alerts_created", "alerts", ["created_at"])

    # ── incident_notes ────────────────────────────────────────────────────────
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("author_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("note_type", sa.String(32), nullable=True),
        sa.Column("attachment_path", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # ── playbook_executions ───────────────────────────────────────────────────
    op.create_table(
        "playbook_executions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("playbook_id", sa.Integer, sa.ForeignKey("playbooks.id"), nullable=False),
        sa.Column("alert_id", sa.Integer, sa.ForeignKey("alerts.id"), nullable=True),
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id"), nullable=True),
        sa.Column("triggered_by", sa.String(32), nullable=True),
        sa.Column("status", sa.String(32), nullable=True),
        sa.Column("result_detail", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=True),
        sa.Column("resource_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.Text, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # ── automated_responses ───────────────────────────────────────────────────
    op.create_table(
        "automated_responses",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "action",
            sa.Enum("IP_BLOCK", "RATE_LIMIT", "TEMP_BAN", "CAPTCHA", "GEO_BLOCK", "CUSTOM", name="responseaction"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("ACTIVE", "EXPIRED", "REVOKED", name="responsestatus"),
            nullable=True,
        ),
        sa.Column("target_ip", sa.String(45), nullable=True),
        sa.Column("target_cidr", sa.String(50), nullable=True),
        sa.Column("target_country", sa.String(2), nullable=True),
        sa.Column("target_path", sa.String(512), nullable=True),
        sa.Column("alert_id", sa.Integer, sa.ForeignKey("alerts.id"), nullable=True),
        sa.Column("playbook_id", sa.Integer, sa.ForeignKey("playbooks.id"), nullable=True),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("duration_seconds", sa.Integer, nullable=True),
        sa.Column("rate_limit_rps", sa.Integer, nullable=True),
        sa.Column("triggered_by", sa.String(32), nullable=True),
        sa.Column("revoked_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_automated_responses_target_ip", "automated_responses", ["target_ip"])
    op.create_index("ix_automated_responses_created_at", "automated_responses", ["created_at"])


def downgrade() -> None:
    op.drop_table("automated_responses")
    op.drop_table("audit_logs")
    op.drop_table("playbook_executions")
    op.drop_table("incident_notes")
    op.drop_table("alerts")
    op.drop_table("firewall_logs")
    op.drop_table("incidents")
    op.drop_table("playbooks")
    op.drop_table("users")

    # Drop PostgreSQL ENUM types (no-op on SQLite)
    for enum_name in (
        "userrole", "playbookstatus", "incidentstatus", "incidentpriority",
        "logprotocol", "logaction", "attacktype", "logseverity",
        "alertseverity", "alertstatus", "responseaction", "responsestatus",
    ):
        sa.Enum(name=enum_name).drop(op.get_bind(), checkfirst=True)
