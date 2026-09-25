import os

from celery import Celery

from fix_engine import RateLimitDeferred, run_ai_fix_engine


app = Celery(
    "secureguard",
    broker=os.getenv("REDIS_URL", "redis://sg-redis:6379/0"),
    backend=os.getenv("REDIS_URL", "redis://sg-redis:6379/0"),
)
app.conf.update(
    task_track_started=True,
    task_time_limit=60 * 60,
    task_soft_time_limit=55 * 60,
    broker_connection_retry_on_startup=True,
)


@app.task(name="secureguard.run_ai_fix", bind=True, max_retries=5)
def run_ai_fix(self, scan_run_id: int, repo_url: str, commit_sha: str):
    try:
        return run_ai_fix_engine(scan_run_id, repo_url, commit_sha)
    except RateLimitDeferred as exc:
        raise self.retry(exc=exc, countdown=exc.retry_after)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=min(300, 30 * 2 ** self.request.retries))
