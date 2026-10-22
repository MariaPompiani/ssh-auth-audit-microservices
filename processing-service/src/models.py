from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    window_minutes: int = Field(
        default=5,
        description="Time window in minutes to correlate consecutive failures",
    )
    failure_threshold: int = Field(
        default=5,
        description="Minimum number of failures within the window to flag as brute force",
    )
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = Field(
        default=1000,
        description="Maximum number of log events to fetch for analysis",
    )


class AttackerIPDetail(BaseModel):
    source_ip: str
    total_failures: int
    country: Optional[str] = None
    targeted_ports: List[int]
    targeted_usernames: List[str]
    first_seen: datetime
    last_seen: datetime


class AnalysisResponse(BaseModel):
    analysis_timestamp: datetime
    window_minutes: int
    failure_threshold: int
    analyzed_logs_count: int
    detected_attackers_count: int
    flagged_ips: List[AttackerIPDetail]
    most_targeted_accounts: Dict[str, int]