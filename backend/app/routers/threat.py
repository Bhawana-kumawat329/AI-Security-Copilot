from fastapi import APIRouter
from pydantic import BaseModel
from app.services.investigation_engine import investigate_ioc

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])


class ThreatRequest(BaseModel):
    ioc: str


@router.post("/threat-intel")
def threat_intel(request: ThreatRequest):
    return investigate_ioc(request.ioc)
