from app.database.db import SessionLocal
from app.models.scan import Scan

def save_scan_result(result):
    db = SessionLocal()
    try:
        risk = result.get("risk", {})
        scan = Scan(
            ioc=result.get("ioc"),
            ioc_type=result.get("ioc_type"),
            severity=risk.get("severity"),
            score=risk.get("score"),
            result=result
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan.id
    finally:
        db.close()
