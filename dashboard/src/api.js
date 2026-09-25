export const API = process.env.REACT_APP_API_URL || "";
export const POLL_MS = 15000; // re-fetch every 15s

function normalizeFinding(finding) {
  return {
    ...finding,
    tool: finding.scanner || "unknown",
    message: finding.title || finding.description || "",
    file: finding.file_path || "",
    line: finding.line_start,
  };
}

// ── Top-level fetch helpers ───────────────────────────────────────────────────
export async function fetchScans() {
  const r = await fetch(`${API}/api/scans?limit=100`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const scans = await r.json();
  return scans.map(scan => ({
    ...scan,
    findings: (scan.findings || []).map(normalizeFinding),
  }));
}
export async function fetchHealth() {
  const r = await fetch(`${API}/health`);
  return r.ok;
}

export const CVE_INTEL = process.env.REACT_APP_CVE_INTEL_URL || "/cve-intel";
