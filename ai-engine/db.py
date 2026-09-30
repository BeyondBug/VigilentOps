import os
import json
from contextlib import contextmanager
from sqlalchemy import create_engine, Column, Integer, Float, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql://{os.getenv('POSTGRES_USER','sgadmin')}:{os.getenv('POSTGRES_PASSWORD','')}@postgres:5432/{os.getenv('POSTGRES_DB','secureguard')}"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class ScanRun(Base):
    """Maps to scan_runs created by migrations/001_initial.sql."""
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
    required_reports = Column(JSON)
    pipeline_commit = Column(Text)

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
            "required_reports": self.required_reports or [],
            "pipeline_commit": self.pipeline_commit,
        }

    def _extract_repo_name(self):
        if self.repo_url:
            return self.repo_url.rstrip("/").removesuffix(".git").split("/")[-1]
        return "unknown"


class Finding(Base):
    """Maps to findings created by migrations/001_initial.sql."""
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
    finding_class   = Column(Text)
    package         = Column(Text)
    installed_version = Column(Text)
    fixed_version   = Column(Text)
    image           = Column(Text)
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
            "description": self.description,
            "file_path":   self.file_path,
            "line_start":  self.line_start,
            "finding_class": self.finding_class,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "image": self.image,
            "fix_status":  self.fix_status,
            "pr_url":      self.pr_url,
            "pr_confidence": self.pr_confidence,
        }


# Keep ScanResult as alias for backwards compat with old imports
ScanResult = ScanRun


class ScanReport(Base):
    __tablename__ = 'scan_reports'
    scan_run_id = Column(Integer, primary_key=True)
    tool = Column(Text, primary_key=True)
    sha256 = Column(Text, nullable=False)
    finding_count = Column(Integer, nullable=False)
    coverage = Column(Text, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'tool': self.tool, 'sha256': self.sha256,
                'finding_count': self.finding_count, 'coverage': self.coverage}


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
