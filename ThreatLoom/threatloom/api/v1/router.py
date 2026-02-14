"""
API v1 router - aggregates all sub-routers.
"""
from fastapi import APIRouter

from threatloom.api.v1.logs import router as logs_router
from threatloom.api.v1.alerts import router as alerts_router
from threatloom.api.v1.incidents import router as incidents_router
from threatloom.api.v1.responses import router as responses_router
from threatloom.api.v1.users import router as users_router
from threatloom.api.v1.playbooks import router as playbooks_router
from threatloom.api.v1.firewall import router as firewall_router

api_router = APIRouter()

api_router.include_router(logs_router, prefix="/logs", tags=["Logs"])
api_router.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(responses_router, prefix="/responses", tags=["Responses"])
api_router.include_router(users_router, prefix="/users", tags=["Users"])
api_router.include_router(playbooks_router, prefix="/playbooks", tags=["Playbooks"])
api_router.include_router(firewall_router, prefix="/firewall", tags=["Firewall"])
