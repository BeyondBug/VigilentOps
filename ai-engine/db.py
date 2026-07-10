import os
import json
from contextlib import contextmanager
from sqlalchemy import create_engine, Column, String, Integer, Float, Text, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql://{os.getenv('POSTGRES_USER','sgadmin')}:{os.getenv('POSTGRES_PASSWORD','sgpassword123')}@postgres:5432/{os.getenv('POSTGRES_DB','secureguard')}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class ScanRun(Base):
    """Maps to scan_runs table created by init.sql"""
    __tablename__ = "scan_runs"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    repo_url     = Column(Text,    nullable=False)
    commit_sha   = Column(Text,    nullable=False)
    branch       = Column(Text,    nullable=False, default="main")
    repo_name    = Column(Text,    default="unknown")
    triggered_by = Column(Text,    default="push")
    status       = Column(Text,    default="pending")
    started_at   = Column(DateTime, default=datetime.utcnow)
    finished_at  = Column(DateTime, nullable=True)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count     = Column(Integer, default=0)
    medium_count   = Column(Integer, default=0)
    low_count      = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id":             self.id,
            "repo_url":       self.repo_url,
            "repo_name":      self.repo_name or self._extract_repo_name(),
            "commit_sha":     self.commit_sha,
            "branch":         self.branch,
            "status":         self.status,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count":     self.high_count,
            "medium_count":   self.medium_count,
            "low_count":      self.low_count,
            "created_at":     self.started_at.isoformat() if self.started_at else None,
            "finished_at":    self.finished_at.isoformat() if self.finished_at else None,
            "findings":       [],   # findings fetched separately if needed
        }

    def _extract_repo_name(self):
        if self.repo_url:
            return self.repo_url.rstrip("/").rstrip(".git").split("/")[-1]
        return "unknown"


class Finding(Base):
    """Maps to findings table created by init.sql"""
    __tablename__ = "findings"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id    = Column(Integer, nullable=False)
    scanner        = Column(Text)
    rule_id        = Column(Text)
    cve_id         = Column(Text)
    cwe_id         = Column(Text)
    severity       = Column(Text)
    cvss_score     = Column(Float)
    title          = Column(Text, nullable=False)
    description    = Column(Text)
    file_path      = Column(Text)
    line_start     = Column(Integer)
    line_end       = Column(Integer)
    vulnerable_code= Column(Text)
    fix_status     = Column(Text, default="open")
    ai_fix_code    = Column(Text)
    pr_url         = Column(Text)
    pr_confidence  = Column(Float)
    created_at     = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":          self.id,
            "scanner":     self.scanner,
            "rule_id":     self.rule_id,
            "cve_id":      self.cve_id,
            "severity":    self.severity,
            "cvss_score":  self.cvss_score,
            "title":       self.title,
            "file_path":   self.file_path,
            "line_start":  self.line_start,
            "fix_status":  self.fix_status,
            "pr_url":      self.pr_url,
        }


# Keep ScanResult as alias for backwards compat with old imports
ScanResult = ScanRun


def init_db():
    """Create tables if they don't exist (idempotent)."""
    Base.metadata.create_all(engine)


@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
