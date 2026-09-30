"""Check private triage completeness; never infer exploitability or accept risks."""

import argparse
import csv
import datetime
import re
from pathlib import Path


def check(directory):
    with (directory / 'findings.csv').open(newline='') as source:
        findings = {row['id']: row for row in csv.DictReader(source)}
    with (directory / 'review-groups.csv').open(newline='') as source:
        groups = list(csv.DictReader(source))
    by_group = {row['group']: row for row in groups}
    errors, seen = [], set()
    if len(by_group) != len(groups):
        errors.append('Duplicate review group identifiers')
    for row in groups:
        group = row['group']
        ids = [value.strip() for value in row.get('finding_ids', '').split(',') if value.strip()]
        if not ids or len(ids) != len(set(ids)) or any(value not in findings or value in seen for value in ids):
            errors.append(f'Group {group}: missing, unknown or repeated finding IDs')
            continue
        seen.update(ids)
        severity = {findings[value].get('severity', 'UNKNOWN') for value in ids}
        secret = any(findings[value].get('finding_class') == 'secret' for value in ids)
        disposition = row.get('disposition') or 'open'
        if disposition == 'duplicate':
            primary = by_group.get(row.get('duplicate_of'))
            if not primary or primary is row or primary.get('disposition') not in {'fixed', 'accepted', 'not_affected'}:
                errors.append(f'Group {group}: duplicate must link to a reviewed primary group')
            if not row.get('evidence'):
                errors.append(f'Group {group}: duplicate needs evidence that it is the same underlying issue')
            continue
        if not row.get('owner'):
            errors.append(f'Group {group}: assign a named owner')
        if disposition == 'fixed':
            if not re.fullmatch(r'[a-fA-F0-9]{40}', row.get('tested_commit', '')) or not row.get('verification_scan_id', '').isdigit() or not row.get('evidence'):
                errors.append(f'Group {group}: fixed needs tested commit, rescan ID and evidence')
        elif disposition in {'accepted', 'not_affected'}:
            if not row.get('evidence'):
                errors.append(f'Group {group}: a disposition needs evidence')
            if disposition == 'accepted':
                try:
                    review = datetime.date.fromisoformat(row.get('review_date', ''))
                    if review < datetime.date.today():
                        raise ValueError('expired')
                except ValueError:
                    errors.append(f'Group {group}: accepted exception needs a current review date')
                if not row.get('impact') or not row.get('mitigation'):
                    errors.append(f'Group {group}: accepted exception needs impact and mitigation')
        elif disposition == 'open':
            if secret or severity & {'CRITICAL', 'HIGH', 'UNKNOWN'}:
                errors.append(f'Group {group}: high/critical/secret/unknown records still need review')
            elif not row.get('planned_fix'):
                errors.append(f'Group {group}: open medium/low records need a plan or backlog entry')
        else:
            errors.append(f'Group {group}: unknown disposition')
    if seen != set(findings):
        errors.append('The review groups do not account for every exported finding exactly once')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    options = parser.parse_args()
    problems = check(options.directory)
    for problem in problems:
        print(problem)
    print('Triage completeness:', 'FAIL' if problems else 'PASS')
    print('Evidence and exception decisions still require human review')
    raise SystemExit(bool(problems))
