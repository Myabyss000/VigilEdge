"""
Alembic environment for ThreatLoom.

Supports both online (live DB) and offline (SQL script) migration modes.
The database URL is read from threatloom.config.settings so the same .env
file is used whether running the app or migrations.
"""
import asyncio
import os
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# ── make sure the ThreatLoom package is importable when running migrations
# from the ThreatLoom/ directory with `alembic upgrade head`
_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)           # …/ThreatLoom/
if _root not in sys.path:
    sys.path.insert(0, _root)

from threatloom.config import settings   # noqa: E402 — import after path fix
from threatloom.database import Base     # noqa: E402

# Import every model so SQLAlchemy registers their tables on Base.metadata
import threatloom.models  # noqa: F401, E402

# ── Alembic config object ─────────────────────────────────────────────────────
config = context.config

# Honour the [loggers] section of alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_url() -> str:
    """Return the async database URL from settings (env overrides alembic.ini)."""
    return settings.DATABASE_URL


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting to the DB (--sql mode)."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Connect to the live DB and run migrations."""
    connectable = create_async_engine(
        _get_url(),
        poolclass=pool.NullPool,   # Don't keep connections alive during migration
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
