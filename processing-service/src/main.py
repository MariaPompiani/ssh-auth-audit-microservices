from collections import Counter, defaultdict
from datetime import datetime, timedelta
import os
import sys

# Ensure current directory is in sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, status
import requests

from models import AnalysisRequest, AnalysisResponse, AttackerIPDetail

app = FastAPI(title="Authentication Processing Service")

# Base URL to reach the data-service (locally or via Docker network)
DATA_SERVICE_URL = os.getenv("DATA_SERVICE_URL", "http://127.0.0.1:5000")


@app.post("/analyze", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
def analyze_logs(payload: AnalysisRequest):
    # 1. Fetch logs from data-service via HTTP
    params = {
        "status": "FAILURE",
        "limit": payload.limit,
    }
    if payload.since:
        params["since"] = payload.since.isoformat()
    if payload.until:
        params["until"] = payload.until.isoformat()

    try:
        response = requests.get(
            f"{DATA_SERVICE_URL}/logs",
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        logs = response.json()
    except requests.exceptions.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Unable to reach data-service: {str(exc)}",
        )

    # 2. Group failures by source_ip
    ip_logs = defaultdict(list)
    targeted_users_counter = Counter()

    for item in logs:
        # Convert timestamp string to datetime object
        event_time = datetime.fromisoformat(item["timestamp"])
        ip_logs[item["source_ip"]].append({
            "timestamp": event_time,
            "port": item.get("service_port", 22),
            "username": item.get("username", "unknown"),
            "country": item.get("country"),
        })
        targeted_users_counter[item.get("username", "unknown")] += 1

    # 3. Apply sliding time-window correlation for brute-force detection
    flagged_attackers: List[AttackerIPDetail] = []
    window_delta = timedelta(minutes=payload.window_minutes)

    for ip, events in ip_logs.items():
        # Sort events chronologically
        events.sort(key=lambda x: x["timestamp"])

        is_brute_force = False
        left = 0

        # Two-pointer sliding window to check failures within the time window
        for right in range(len(events)):
            while events[right]["timestamp"] - events[left]["timestamp"] > window_delta:
                left += 1

            if (right - left + 1) >= payload.failure_threshold:
                is_brute_force = True
                break

        if is_brute_force:
            distinct_ports = list({ev["port"] for ev in events})
            distinct_users = list({ev["username"] for ev in events})
            country = next((ev["country"] for ev in events if ev["country"]), None)

            flagged_attackers.append(
                AttackerIPDetail(
                    source_ip=ip,
                    total_failures=len(events),
                    country=country,
                    targeted_ports=distinct_ports,
                    targeted_usernames=distinct_users,
                    first_seen=events[0]["timestamp"],
                    last_seen=events[-1]["timestamp"],
                )
            )

    return AnalysisResponse(
        analysis_timestamp=datetime.utcnow(),
        window_minutes=payload.window_minutes,
        failure_threshold=payload.failure_threshold,
        analyzed_logs_count=len(logs),
        detected_attackers_count=len(flagged_attackers),
        flagged_ips=flagged_attackers,
        most_targeted_accounts=dict(targeted_users_counter.most_common(10)),
    )