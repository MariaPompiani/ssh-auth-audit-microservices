import sys
import os

# Ensure the current directory (src) is in Python's search path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime
from typing import List, Optional
from fastapi import Depends, FastAPI, HTTPException, status
import pandas as pd
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import AuthLog, AuthLogCreate, AuthLogResponse

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Authentication Data Service")


@app.post("/logs", response_model=AuthLogResponse, status_code=status.HTTP_201_CREATED)
def create_log(log: AuthLogCreate, db: Session = Depends(get_db)):
    db_log = AuthLog(**log.model_dump())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log


@app.get("/logs", response_model=List[AuthLogResponse])
def get_logs(
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(AuthLog)

    if since:
        query = query.filter(AuthLog.timestamp >= since)
    if until:
        query = query.filter(AuthLog.timestamp <= until)
    if status:
        query = query.filter(AuthLog.status == status.upper())

    return query.order_by(AuthLog.timestamp.asc()).limit(limit).all()


@app.post("/logs/seed", status_code=status.HTTP_200_OK)
def seed_logs(db: Session = Depends(get_db)):
    csv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dataset.csv")

    if not os.path.exists(csv_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Seed file not found at {csv_path}",
        )

    try:
        df = pd.read_csv(csv_path)

        records = []
        for _, row in df.iterrows():
            parsed_time = pd.to_datetime(row["datetime"], errors="coerce")
            if pd.isna(parsed_time):
                continue

            try:
                port = int(row["dpt"]) if pd.notna(row["dpt"]) else 22
            except (ValueError, TypeError):
                port = 22

            source_ip = str(row["srcstr"]) if pd.notna(row["srcstr"]) else str(row["src"])
            country = str(row["country"]) if pd.notna(row["country"]) else None

            records.append(
                AuthLog(
                    timestamp=parsed_time.to_pydatetime(),
                    source_ip=source_ip,
                    username="unknown",
                    service_port=port,
                    status="FAILURE",
                    country=country,
                )
            )

        db.bulk_save_objects(records)
        db.commit()

        return {
            "message": "Dataset successfully seeded",
            "inserted_records": len(records),
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to seed data: {str(e)}",
        )