from sqlalchemy import Column, Integer, String, JSON, DateTime
from datetime import datetime
from app.database.db import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String, index=True)
    ioc_type = Column(String)
    severity = Column(String)
    score = Column(Integer)
    result = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
