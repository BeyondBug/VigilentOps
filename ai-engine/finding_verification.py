"""Evidence gate for reviewed findings, independent of severity and AI confidence.

A reviewer attests to a controlled reproduction at the scanned commit. This is
not an automatic exploit runner; an AI score or scanner match cannot satisfy it.
"""
from sqlalchemy import and_, func
from db import Finding, ScanRun

SECURITY_CLASSES = {'sast', 'sca', 'secret', 'iac'}
PROOF_FIELDS = {'tested_commit', 'verification_method', 'artifact', 'proof_reference',
                'reproduction_steps', 'observed_impact'}
TEXT_MINIMUMS = {'proof_reference': 10, 'reproduction_steps': 20, 'observed_impact': 10}


def evidence_confirmed(finding, commit):
    details = finding.get('review_details') or {}
    if not isinstance(details, dict):
        return False
    artifact = finding.get('image') or finding.get('file_path') or finding.get('package')
    return bool(
        finding.get('review_status') == 'confirmed'
        and finding.get('finding_class') in SECURITY_CLASSES
        and len((finding.get('review_owner') or '').strip()) >= 2
        and len((finding.get('review_evidence') or '').strip()) >= 10
        and details.get('verification_method') == 'controlled_reproduction'
        and isinstance(commit, str) and len(commit) == 40
        and isinstance(details.get('tested_commit'), str)
        and details['tested_commit'].lower() == commit.lower()
        and artifact and details.get('artifact') == artifact
        and all(isinstance(details.get(key), str) and len(details[key].strip()) >= minimum
                for key, minimum in TEXT_MINIMUMS.items())
    )


def verification_level(finding, commit):
    if evidence_confirmed(finding, commit):
        return 'evidence_confirmed'
    if finding.get('review_status') == 'confirmed':
        return 'review_only'
    return finding.get('review_status') or 'unverified'


def verified_filter():
    """Same gate in SQL so counts and pagination reflect evidence eligibility."""
    details = Finding.review_details
    artifact = func.coalesce(func.nullif(Finding.image, ''),
                             func.nullif(Finding.file_path, ''), func.nullif(Finding.package, ''))
    return and_(
        Finding.review_status == 'confirmed', Finding.finding_class.in_(SECURITY_CLASSES),
        func.length(func.trim(Finding.review_owner)) >= 2,
        func.length(func.trim(Finding.review_evidence)) >= 10,
        details['verification_method'].as_string() == 'controlled_reproduction',
        func.length(ScanRun.commit_sha) == 40,
        func.lower(details['tested_commit'].as_string()) == func.lower(ScanRun.commit_sha),
        artifact.isnot(None), details['artifact'].as_string() == artifact,
        *(func.length(func.trim(details[key].as_string())) >= minimum
          for key, minimum in TEXT_MINIMUMS.items()),
    )
