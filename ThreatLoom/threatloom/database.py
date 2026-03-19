"""
Database engine, session factory, and base model.

Development:  sqlite+aiosqlite:///./threatloom.db
Production:   postgresql+asyncpg://user:pass@host:5432/threatloom
"""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from threatloom.config import settings


def _engine_kwargs() -> dict:
    """Return engine kwargs appropriate for the configured database backend."""
    url = settings.DATABASE_URL
    if url.startswith("postgresql"):
        return {
            "pool_size": 10,
            "max_overflow": 20,
            "pool_pre_ping": True,
        }
    # SQLite — no connection pool options available for the async driver
    return {}


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.APP_DEBUG,
    future=True,
    **_engine_kwargs(),
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """Dependency: yields a DB session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_db_connection() -> bool:
    """Return True if the database is reachable, False otherwise."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
