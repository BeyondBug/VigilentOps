import os
from datetime import datetime

from celery import Celery

from fix_engine import RateLimitDeferred, run_ai_fix_engine
from db import get_db_session, ScanRun


app = Celery(
    "secureguard",
    broker=os.getenv("REDIS_URL", "redis://sg-redis:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://sg-redis:6379/0"),
)


def record_task_state(task, scan_run_id, state):
    # Direct unit-test calls and historical messages without an ID have no lease.
    if not task.request.id:
        return
    with get_db_session() as db:
        scan = db.query(ScanRun).filter_by(id=scan_run_id, ai_task_id=task.request.id).first()
        if scan:
            scan.ai_task_status = state
            scan.ai_task_updated_at = datetime.utcnow()
app.conf.update(
    task_track_started=True,
    task_time_limit=60 * 60,
    task_soft_time_limit=55 * 60,
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
)


@app.task(name="secureguard.run_ai_fix", bind=True, max_retries=5)
def run_ai_fix(self, scan_run_id: int, repo_url: str, commit_sha: str, route_offset: int = 0):
    try:
        record_task_state(self, scan_run_id, 'running')
        result = run_ai_fix_engine(scan_run_id, repo_url, commit_sha, route_offset=route_offset)
        record_task_state(self, scan_run_id, 'failed' if result.get('status') == 'error' else 'complete')
        return result
    except RateLimitDeferred as exc:
        record_task_state(self, scan_run_id, 'failed' if self.request.retries >= self.max_retries else 'retry')
        # The position travels with the broker message, so a retry after a
        # cooldown or worker restart can reach the remaining approved models.
        raise self.retry(exc=exc, countdown=exc.retry_after,
                         args=(scan_run_id, repo_url, commit_sha),
                         kwargs={'route_offset': exc.route_offset})
    except Exception as exc:
        record_task_state(self, scan_run_id, 'failed' if self.request.retries >= self.max_retries else 'retry')
        raise self.retry(exc=exc, countdown=min(300, 30 * 2 ** self.request.retries))
