from fastapi import APIRouter
from app.database.db import SessionLocal
from app.models.scan import Scan
from app.services.pdf_report import generate_pdf_report

router = APIRouter(prefix="/api/report", tags=["Reports"])


@router.get("/{scan_id}")
def generate_report(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            return {"success": False, "message": "Scan not found"}

        report = generate_pdf_report(scan.result)

        return {
            "success": True,
            "scan_id": scan_id,
            "report": report
        }

    finally:
        db.close()
