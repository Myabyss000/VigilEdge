"""
Tests for ThreatLoom API endpoints.
Uses httpx AsyncClient + pytest-asyncio for async FastAPI testing.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

# We need to set up the database before importing the app
import os
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_threatloom.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpassword123")


@pytest_asyncio.fixture
async def client():
    """Create a test client with a fresh database."""
    from main import app
    from threatloom.database import engine, Base

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient):
    """Get auth headers by logging in as admin."""
    # Create admin user first (the lifespan may not run in test mode)
    from threatloom.database import async_session
    from threatloom.models.users import User, UserRole
    from threatloom.auth.jwt import hash_password

    async with async_session() as db:
        from sqlalchemy import select
        result = await db.execute(select(User).where(User.username == "admin"))
        admin = result.scalar_one_or_none()
        if not admin:
            admin = User(
                username="admin",
                email="admin@threatloom.local",
                hashed_password=hash_password("testpassword123"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            await db.commit()

    resp = await client.post("/api/v1/users/login", json={
        "username": "admin",
        "password": "testpassword123",
    })
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return {}


# ---------------------------------------------------------------------------
# Health & Root Tests
# ---------------------------------------------------------------------------
class TestRootEndpoints:
    @pytest.mark.asyncio
    async def test_dashboard_page(self, client: AsyncClient):
        resp = await client.get("/")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_login_page(self, client: AsyncClient):
        resp = await client.get("/login")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth Tests
# ---------------------------------------------------------------------------
class TestAuth:
    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient, auth_headers):
        assert "Authorization" in auth_headers

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient):
        resp = await client.post("/api/v1/users/login", json={
            "username": "admin",
            "password": "wrong_password",
        })
        assert resp.status_code in [401, 400]

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        resp = await client.post("/api/v1/users/login", json={
            "username": "nobody",
            "password": "nopass",
        })
        assert resp.status_code in [401, 400]

    @pytest.mark.asyncio
    async def test_protected_endpoint_without_token(self, client: AsyncClient):
        resp = await client.get("/api/v1/alerts/")
        assert resp.status_code in [401, 403]


# ---------------------------------------------------------------------------
# Log Ingestion Tests
# ---------------------------------------------------------------------------
class TestLogIngestion:
    @pytest.mark.asyncio
    async def test_ingest_json_log(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        log_data = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "action": "BLOCKED",
            "attack_type": "SQLI",
            "http_method": "POST",
            "http_path": "/api/data",
            "http_status": 403,
            "severity": "HIGH",
        }
        resp = await client.post(
            "/api/v1/logs/ingest/json",
            json=log_data,
            headers=auth_headers,
        )
        assert resp.status_code in [200, 201]

    @pytest.mark.asyncio
    async def test_ingest_syslog(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.post(
            "/api/v1/logs/ingest/syslog",
            json={"raw": "<134>Jan  5 14:23:01 fw1 WAF: src_ip=1.2.3.4 action=BLOCKED"},
            headers=auth_headers,
        )
        assert resp.status_code in [200, 201]

    @pytest.mark.asyncio
    async def test_ingest_raw(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.post(
            "/api/v1/logs/ingest/raw",
            json={"raw": "10.0.0.1 BLOCKED request to /admin"},
            headers=auth_headers,
        )
        assert resp.status_code in [200, 201]

    @pytest.mark.asyncio
    async def test_query_logs(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.get("/api/v1/logs/", headers=auth_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Alert Tests
# ---------------------------------------------------------------------------
class TestAlerts:
    @pytest.mark.asyncio
    async def test_list_alerts(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.get("/api/v1/alerts/", headers=auth_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_alert_stats(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.get("/api/v1/alerts/stats", headers=auth_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Incident Tests
# ---------------------------------------------------------------------------
class TestIncidents:
    @pytest.mark.asyncio
    async def test_list_incidents(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.get("/api/v1/incidents/", headers=auth_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_create_incident(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.post("/api/v1/incidents/", json={
            "title": "Test Incident",
            "description": "This is a test incident",
            "priority": "HIGH",
        }, headers=auth_headers)
        assert resp.status_code in [200, 201]


# ---------------------------------------------------------------------------
# Response Tests
# ---------------------------------------------------------------------------
class TestResponses:
    @pytest.mark.asyncio
    async def test_list_responses(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.get("/api/v1/responses/", headers=auth_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Playbook Tests
# ---------------------------------------------------------------------------
class TestPlaybooks:
    @pytest.mark.asyncio
    async def test_list_playbooks(self, client: AsyncClient, auth_headers):
        if not auth_headers:
            pytest.skip("Auth not available")
        resp = await client.get("/api/v1/playbooks/", headers=auth_headers)
        assert resp.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
