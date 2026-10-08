"""Validate explicit reviewer evidence; never infer false positives from severity."""
import re
from datetime import date

REVIEW_STATUSES = {'unverified', 'confirmed', 'false_positive', 'accepted_risk', 'fixed'}


def validate_review(body):
    if not isinstance(body, dict) or set(body) - {'status', 'owner', 'evidence', 'version', 'details'}:
        raise ValueError('Review must contain status, owner, evidence, version and optional details')
    status, owner, evidence = (body.get(key) for key in ('status', 'owner', 'evidence'))
    if not isinstance(status, str) or status not in REVIEW_STATUSES:
        raise ValueError('Invalid review status')
    if not isinstance(owner, str) or not 2 <= len(owner.strip()) <= 200:
        raise ValueError('A named owner is required')
    if not isinstance(evidence, str) or not 10 <= len(evidence.strip()) <= 4000:
        raise ValueError('Evidence must contain 10–4000 characters')
    if type(body.get('version')) is not int or body['version'] < 0:
        raise ValueError('Supply the current nonnegative review version')
    details = body.get('details', {})
    allowed = {'tested_commit', 'verification_scan_id', 'review_date', 'impact', 'mitigation'}
    if not isinstance(details, dict) or set(details) - allowed:
        raise ValueError('Invalid review details')
    for key in allowed - {'verification_scan_id'}:
        if key in details and (not isinstance(details[key], str) or len(details[key]) > 2000):
            raise ValueError('Invalid review detail value')
    if status == 'fixed':
        if (not re.fullmatch(r'[a-fA-F0-9]{40}', details.get('tested_commit', ''))
                or type(details.get('verification_scan_id')) is not int or details['verification_scan_id'] < 1):
            raise ValueError('Fixed requires an exact tested commit and verification scan ID')
    if status == 'accepted_risk':
        try:
            current = date.fromisoformat(details.get('review_date', '')) >= date.today()
        except ValueError:
            current = False
        if not current or any(not details.get(key, '').strip() for key in ('impact', 'mitigation')):
            raise ValueError('Accepted risk requires impact, mitigation and a current review date')
    return status, owner.strip(), evidence.strip(), details
