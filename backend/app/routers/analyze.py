from fastapi import APIRouter
from pydantic import BaseModel
from app.services.validator import detect_ioc_type

router = APIRouter(prefix="/api", tags=["IOC Analyzer"])

class IOCRequest(BaseModel):
    ioc: str

@router.post("/analyze")
def analyze_ioc(request: IOCRequest):
    result = detect_ioc_type(request.ioc)

    return {
        "success": result["valid"],
        "ioc": request.ioc,
        "ioc_type": result["type"],
        "message": result.get("message", "IOC detected successfully")
    }
