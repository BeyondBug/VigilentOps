"""Conservative display grouping; scanner records and dispositions stay intact."""
from sqlalchemy import and_, case
from db import Finding

# Keep artifacts, versions, locations and review decisions separate. Scanner is
# deliberately excluded: agreement is useful provenance, never exploit proof.
GROUP_FIELDS = ('scan_run_id', 'finding_class', 'cve_id', 'package',
                'installed_version', 'fixed_version', 'image', 'file_path',
                'severity', 'review_status')


def grouping_columns():
    eligible = and_(Finding.finding_class == 'sca', Finding.cve_id.isnot(None),
                    Finding.cve_id != '', Finding.package.isnot(None), Finding.package != '',
                    Finding.installed_version.isnot(None), Finding.installed_version != '',
                    # An artifact or manifest is required to establish identity.
                    ((Finding.image.isnot(None) & (Finding.image != '')) |
                     (Finding.file_path.isnot(None) & (Finding.file_path != ''))))
    return [getattr(Finding, field) for field in GROUP_FIELDS] + [
        case((eligible, 0), else_=Finding.id)]


def group_members(query, representative):
    """Find exactly one display group, including incomplete singleton records."""
    if not (representative.finding_class == 'sca' and representative.cve_id
            and representative.package and representative.installed_version
            and (representative.image or representative.file_path)):
        return query.filter(Finding.id == representative.id)
    return query.filter(*(getattr(Finding, field) == getattr(representative, field)
                          for field in GROUP_FIELDS))
