"""Apply ordered SQL migrations before starting application services."""

from pathlib import Path

from sqlalchemy import text

from db import engine


MIGRATIONS = Path(__file__).with_name("migrations")


def migrate() -> list[str]:
    applied_now = []
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(8923671)"))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        applied = set(connection.execute(
            text("SELECT version FROM schema_migrations")
        ).scalars())
        for path in sorted(MIGRATIONS.glob("[0-9][0-9][0-9]_*.sql")):
            if path.name in applied:
                continue
            connection.exec_driver_sql(path.read_text())
            connection.execute(
                text("INSERT INTO schema_migrations (version) VALUES (:version)"),
                {"version": path.name},
            )
            applied_now.append(path.name)
    return applied_now


if __name__ == "__main__":
    for version in migrate():
        print(f"Applied {version}")
