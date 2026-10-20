import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String
from database import Base


class AuthLog(Base):
    __tablename__ = "auth_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    source_ip = Column(String(45), index=True, nullable=False)
    username = Column(String(100), default="unknown", nullable=False)
    service_port = Column(Integer, nullable=False)
    status = Column(String(10), nullable=False)
    country = Column(String(100), nullable=True)


class AuthLogCreate(BaseModel):
    timestamp: datetime
    source_ip: str
    username: Optional[str] = "unknown"
    service_port: int
    status: str
    country: Optional[str] = None


class AuthLogResponse(AuthLogCreate):
    id: int

    class Config:
        from_attributes = True