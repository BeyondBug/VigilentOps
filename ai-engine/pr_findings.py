"""Render stored scanner findings for a Gitea pull request conversation."""

from collections import Counter, defaultdict
from html import escape


MAX_COMMENT_BYTES = 23_000  # leave room for the numbered header on each part
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _text(value) -> str:
    if value is None or value == "":
        return "—"
    # Scanner-controlled text must not create HTML or mention users in Gitea.
    return escape(str(value), quote=False).replace("@", "@\u200b")


def _one_line(value) -> str:
    return _text(value).replace("\r", " ").replace("\n", " ")


def _location(finding: dict) -> str:
    path = _one_line(finding.get("file_path"))
    start = finding.get("line_start")
    end = finding.get("line_end")
    if start is None:
        return path
    return f"{path}:{start}" + (f"–{end}" if end and end != start else "")


def _finding_entry(finding: dict, proposed_ids: set[int]) -> str:
    finding_id = finding.get("id")
    finding_class = str(finding.get("finding_class") or "").lower()
    rule_id = str(finding.get("rule_id") or "").upper()
    title = str(finding.get("title") or "")
    display_title = "Potential secret exposure" if finding_class == "secret" else title
    description = finding.get("description")
    if (
        finding_class == "secret"
        or rule_id in {"B105", "B106", "B107"}
        or any(term in title.lower() for term in ("hardcoded password", "hard-coded password",
                                                   "hardcoded secret", "credential", "api key"))
    ):
        description = "Redacted: this finding may contain a credential. Review the restricted scanner report."
    description_lines = _text(description).splitlines() or ["—"]
    description_block = "\n".join(f"> {line}" for line in description_lines)
    proposal = "Proposed file change" if finding_id in proposed_ids else "No proposed change"
    return (
        f"#### Finding #{_one_line(finding_id)} — "
        f"{_one_line(finding.get('severity'))}: {_one_line(display_title)}\n\n"
        f"- **Scanner:** {_one_line(finding.get('scanner'))}\n"
        f"- **Class:** {_one_line(finding.get('finding_class'))}\n"
        f"- **Rule:** {_one_line(finding.get('rule_id'))}\n"
        f"- **Advisory:** {_one_line(finding.get('cve_id'))}\n"
        f"- **CWE:** {_one_line(finding.get('cwe_id'))}\n"
        f"- **CVSS:** {_one_line(finding.get('cvss_score'))}\n"
        f"- **Location:** {_location(finding)}\n"
        f"- **Stored status:** {_one_line(finding.get('fix_status'))}\n"
        f"- **AI proposal:** {proposal}; security and runtime behavior are unverified.\n\n"
        f"**Scanner description**\n\n{description_block}\n\n"
    )


def build_finding_comments(
    scan_run_id: int, findings: list[dict], proposed_ids: set[int]
) -> list[str]:
    """Include every stored finding, split into bounded Gitea comments."""
    by_scanner: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        by_scanner[str(finding.get("scanner") or "unknown")].append(finding)

    severity_counts = Counter(str(f.get("severity") or "UNKNOWN") for f in findings)
    totals = ", ".join(
        f"{_one_line(severity)} {count}"
        for severity, count in sorted(
            severity_counts.items(),
            key=lambda item: (SEVERITY_ORDER.get(item[0], 99), item[0]),
        )
    ) or "none"
    tool_counts = "\n".join(
        f"- {_one_line(scanner)}: {len(items)}"
        for scanner, items in sorted(by_scanner.items())
    ) or "- No findings were stored."
    summary = (
        f"## Complete scanner findings — Scan #{scan_run_id}\n\n"
        f"This scan stored **{len(findings)} finding records** across "
        f"**{len(by_scanner)} tools**. Severity records: {totals}. "
        "Different tools can report the same underlying issue. "
        "Only findings marked \"Proposed file change\" are associated with "
        "this AI patch; no finding is verified fixed.\n\n"
        "**Findings by tool**\n\n"
        f"{tool_counts}\n\n"
        "All stored finding metadata follows in this conversation. Raw source "
        "snippets and descriptions likely to contain credentials are excluded to avoid copying "
        "credentials into pull request comments.\n"
    )

    parts = [summary]
    current = ""
    for scanner, items in sorted(by_scanner.items()):
        heading = f"### {_one_line(scanner)} — {len(items)} findings\n\n"
        if current and len((current + heading).encode("utf-8")) > MAX_COMMENT_BYTES:
            parts.append(current)
            current = ""
        current += heading
        for finding in sorted(
            items,
            key=lambda f: (
                SEVERITY_ORDER.get(str(f.get("severity") or ""), 99),
                str(f.get("file_path") or ""),
                f.get("line_start") or 0,
                f.get("id") or 0,
            ),
        ):
            entry = _finding_entry(finding, proposed_ids)
            if current and len((current + entry).encode("utf-8")) > MAX_COMMENT_BYTES:
                parts.append(current)
                current = f"### {_one_line(scanner)} — continued\n\n"
            current += entry
    if current:
        parts.append(current)

    total = len(parts)
    return [
        f"<!-- secureguard-scan-{scan_run_id}-part-{index} -->\n"
        f"**Scan #{scan_run_id} findings: part {index} of {total}**\n\n{part}"
        for index, part in enumerate(parts, 1)
    ]
