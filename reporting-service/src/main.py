import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional

# Ensure current directory is in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Query, status
import requests

app = FastAPI(title="Authentication Reporting Service")

# Processing-service endpoint (resolved locally or via Docker internal network)
PROCESSING_SERVICE_URL = os.getenv("PROCESSING_SERVICE_URL", "http://127.0.0.1:5001")


@app.get("/reports/incidents", status_code=status.HTTP_200_OK)
def get_incident_report(
    format: str = Query(default="json", regex="^(json)$"),
    window_minutes: int = Query(default=10, ge=1, le=120),
    failure_threshold: int = Query(default=3, ge=1, le=50),
    limit: int = Query(default=5000, ge=10, le=50000),
):
    # 1. Forward audit parameters to processing-service
    payload = {
        "window_minutes": window_minutes,
        "failure_threshold": failure_threshold,
        "limit": limit,
    }

    try:
        response = requests.post(
            f"{PROCESSING_SERVICE_URL}/analyze",
            json=payload,
            timeout=15,
        )
        response.raise_for_status()
        analysis_data = response.json()
    except requests.exceptions.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach processing-service: {str(exc)}",
        )

    # 2. Build structured executive report
    return {
        "report_id": f"REP-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "service": "ssh-auth-audit-system",
        "parameters": {
            "sliding_window_minutes": window_minutes,
            "failure_threshold": failure_threshold,
            "inspected_records": limit,
        },
        "summary": {
            "total_logs_analyzed": analysis_data.get("analyzed_logs_count", 0),
            "threats_detected": analysis_data.get("detected_attackers_count", 0),
            "severity_level": "HIGH" if analysis_data.get("detected_attackers_count", 0) > 0 else "LOW",
        },
        "top_targeted_accounts": analysis_data.get("most_targeted_accounts", {}),
        "incidents": analysis_data.get("flagged_ips", []),
    }