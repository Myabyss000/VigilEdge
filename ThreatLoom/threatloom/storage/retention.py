"""
Data retention manager - hot / warm / cold tiering and cleanup.

Retention strategy:
  HOT  (0-7 days):    Full detail, fast queries, primary table
  WARM (7-30 days):   Full detail, indexed but lower priority
  COLD (30-365 days): Archived, aggregated summaries retained
  PURGE (>365 days):  Deleted

Implemented via tier column on FirewallLog and periodic background task.
"""
import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from threatloom.config import settings
from threatloom.database import async_session
from threatloom.models.logs import FirewallLog

logger = logging.getLogger("threatloom.storage.retention")


class RetentionManager:
    """Background task that manages log retention tiers."""

    def __init__(self):
        self.hot_days = settings.RETENTION_HOT_DAYS
        self.warm_days = settings.RETENTION_WARM_DAYS
        self.cold_days = settings.RETENTION_COLD_DAYS

    async def run_schedule(self):
        """Run retention management on a schedule."""
        logger.info(
            f"Retention manager started: hot={self.hot_days}d, "
            f"warm={self.warm_days}d, cold={self.cold_days}d"
        )
        while True:
            try:
                await self.run_retention_cycle()
            except asyncio.CancelledError:
                logger.info("Retention manager stopped.")
                return
            except Exception as e:
                logger.error(f"Retention cycle error: {e}", exc_info=True)
            # Run daily
            await asyncio.sleep(86400)

    async def run_retention_cycle(self):
        """Execute one retention cycle."""
        async with async_session() as db:
            now = datetime.utcnow()

            # Move hot → warm
            hot_cutoff = now - timedelta(days=self.hot_days)
            moved_warm = await self._move_tier(db, "hot", "warm", hot_cutoff)

            # Move warm → cold
            warm_cutoff = now - timedelta(days=self.warm_days)
            moved_cold = await self._move_tier(db, "warm", "cold", warm_cutoff)

            # Purge cold beyond retention
            cold_cutoff = now - timedelta(days=self.cold_days)
            purged = await self._purge_old(db, cold_cutoff)

            await db.commit()

            logger.info(
                f"Retention cycle complete: "
                f"hot→warm={moved_warm}, warm→cold={moved_cold}, purged={purged}"
            )

    async def _move_tier(
        self, db: AsyncSession, from_tier: str, to_tier: str, cutoff: datetime
    ) -> int:
        """Move logs from one tier to another based on age."""
        result = await db.execute(
            update(FirewallLog)
            .where(
                and_(
                    FirewallLog.tier == from_tier,
                    FirewallLog.timestamp < cutoff,
                )
            )
            .values(tier=to_tier)
        )
        return result.rowcount

    async def _purge_old(self, db: AsyncSession, cutoff: datetime) -> int:
        """Delete logs older than the cold retention period."""
        result = await db.execute(
            delete(FirewallLog).where(
                and_(
                    FirewallLog.tier == "cold",
                    FirewallLog.timestamp < cutoff,
                )
            )
        )
        return result.rowcount

    async def get_tier_stats(self, db: AsyncSession) -> dict:
        """Get count of logs per tier."""
        result = await db.execute(
            select(FirewallLog.tier, func.count(FirewallLog.id))
            .group_by(FirewallLog.tier)
        )
        stats = {row[0]: row[1] for row in result.all()}
        return {
            "hot": stats.get("hot", 0),
            "warm": stats.get("warm", 0),
            "cold": stats.get("cold", 0),
            "total": sum(stats.values()),
        }
