"""Analysis service package for tapm serve (W1.1)."""

from .auth import TokenAuth
from .client import (
    AnalysisClient,
    ClientConnectionError,
    ClientError,
    ClientTimeoutError,
    SubmitClient,
    SubmitResult,
    compute_exit_code,
    detect_git_context,
)
from .logging import LogEvent, ServiceLogger
from .metrics import MetricsCollector
from .models import EnrichmentStatus, GateVerdict, Job, JobStatus
from .queue import JobQueue
from .server import AnalysisServer, create_server

__all__ = [
    "AnalysisServer",
    "create_server",
    "JobQueue",
    "Job",
    "JobStatus",
    "GateVerdict",
    "EnrichmentStatus",
    "TokenAuth",
    "ServiceLogger",
    "LogEvent",
    "MetricsCollector",
    "AnalysisClient",
    "SubmitClient",
    "SubmitResult",
    "compute_exit_code",
    "detect_git_context",
    "ClientError",
    "ClientTimeoutError",
    "ClientConnectionError",
]
