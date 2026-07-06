from fastapi import APIRouter
from app.database.db import SessionLocal
from app.models.scan import Scan

router = APIRouter(prefix="/api/history", tags=["History"])


@router.get("/")
def get_history():
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()

        data = []
        for scan in scans:
            data.append({
                "id": scan.id,
                "ioc": scan.ioc,
                "ioc_type": scan.ioc_type,
                "severity": scan.severity,
                "score": scan.score,
                "created_at": str(scan.created_at)
            })

        return {
            "total": len(data),
            "history": data
        }

    finally:
        db.close()
