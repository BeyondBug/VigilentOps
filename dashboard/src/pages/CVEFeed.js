import { useState, useEffect, useCallback } from "react";
import { T, SEV_COLOR, sevBadge } from "../theme";
import { FilterGroup, EmptyState } from "../components";
import { CVE_INTEL } from "../api";

export default function CVEFeed({ scans }) {
  const [loading, setLoading] = useState(false);
  const [cveData, setCveData] = useState([]);
  const [filter, setFilter] = useState("ALL");
  const [source, setSource] = useState("live");  // "live" | "scan"

  // Fetch live CVE feed from cve-intel service
  const fetchLiveCVEs = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${CVE_INTEL}/cves/recent?limit=100`);
      if (r.ok) {
        const data = await r.json();
        setCveData(
          data.map(c => ({
            id:          c.cve_id,
            severity:    c.severity || "UNKNOWN",
            score:       c.cvss_score || 0,
            title:       (c.description || "").slice(0, 120),
            description: c.description || "",
            cwe_ids:     c.cwe_ids || [],
            is_kev:      c.is_kev || false,
            published:   c.published_at,
            sources:     c.sources || ["nvd"],
            repos:       [],
            count:       0,
            from_live:   true,
          })).sort((a, b) => b.score - a.score)
        );
      }
    } catch (e) {
      // Fall back to scan findings
      setSource("scan");
    } finally {
      setLoading(false);
    }
  }, []);

  // Collect CVEs from scan findings
  const loadScanCVEs = useCallback(() => {
    const cveMap = {};
    scans.forEach(s => {
      (s.findings || []).filter(f => f.cve_id).forEach(f => {
        if (!cveMap[f.cve_id]) {
          cveMap[f.cve_id] = {
            id:       f.cve_id,
            severity: f.severity || "UNKNOWN",
            score:    f.cvss_score || 0,
            title:    f.title || f.rule_id || "",
            repos:    new Set(),
            count:    0,
            from_live: false,
          };
        }
        cveMap[f.cve_id].repos.add(s.repo_name);
        cveMap[f.cve_id].count++;
      });
    });
    setCveData(
      Object.values(cveMap)
        .map(c => ({ ...c, repos: [...c.repos] }))
        .sort((a, b) => b.score - a.score)
    );
  }, [scans]);

  useEffect(() => {
    if (source === "live") {
      fetchLiveCVEs();
    } else {
      loadScanCVEs();
    }
  }, [source, fetchLiveCVEs, loadScanCVEs]);

  const sevs     = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const filtered = filter === "ALL" ? cveData : cveData.filter(c => (c.severity || "").toUpperCase() === filter);

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      {/* Filter + source toggle bar */}
      <div style={{
        background: T.panel, border: `1px solid ${T.border}`,
        borderRadius: 8, padding: "14px 20px", marginBottom: 16,
        display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap",
      }}>
        <FilterGroup label="Severity" options={sevs} value={filter} onChange={setFilter} colorMap={SEV_COLOR} />
        <div style={{ display: "flex", gap: 4, marginLeft: 8 }}>
          {["live", "scan"].map(s => (
            <button key={s} onClick={() => setSource(s)} style={{
              padding: "4px 10px", borderRadius: 4, cursor: "pointer",
              border: `1px solid ${source === s ? T.accent : T.border}`,
              background: source === s ? `${T.accent}18` : "transparent",
              color: source === s ? T.accent : T.textDim,
              fontSize: 10, fontFamily: T.font, fontWeight: source === s ? 700 : 400,
            }}>{s === "live" ? "⬡ LIVE NVD FEED" : "⊟ SCAN FINDINGS"}</button>
          ))}
        </div>
        <span style={{ marginLeft: "auto", fontSize: 11, color: T.textDim, fontFamily: T.font }}>
          {loading ? "Loading..." : `${filtered.length} CVEs`}
        </span>
      </div>

      {filtered.length === 0 ? (
        <EmptyState message={loading ? "Fetching CVE data from NIST NVD..." : "No CVEs found. Run a scan to populate findings."} />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {filtered.map(cve => (
            <div key={cve.id} style={{
              background: T.panel, border: `1px solid ${T.border}`, borderRadius: 7,
              padding: "14px 18px", display: "flex", alignItems: "center", gap: 14,
              borderLeft: `3px solid ${SEV_COLOR[(cve.severity || "").toUpperCase()] || T.border}`,
            }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                  <span style={{ fontFamily: T.font, fontSize: 13, fontWeight: 700, color: T.accent }}>{cve.id}</span>
                  {sevBadge(cve.severity)}
                  {cve.score > 0 && (
                    <span style={{
                      fontSize: 11, padding: "1px 7px", borderRadius: 4,
                      background: `${SEV_COLOR[(cve.severity || "").toUpperCase()]}18`,
                      color: SEV_COLOR[(cve.severity || "").toUpperCase()] || T.textDim,
                      fontFamily: T.font, fontWeight: 700,
                    }}>CVSS {cve.score}</span>
                  )}
                  {cve.is_kev && (
                    <span style={{
                      fontSize: 10, padding: "1px 6px", borderRadius: 3,
                      background: "#ff3b3b22", color: "#ff3b3b",
                      fontFamily: T.font, fontWeight: 700, border: "1px solid #ff3b3b44",
                    }}>⚡ CISA KEV</span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: T.text, marginBottom: 4 }}>{cve.title}</div>
                <div style={{ fontSize: 10, color: T.textDim, fontFamily: T.font }}>
                  {cve.from_live
                    ? `Published: ${cve.published ? new Date(cve.published).toLocaleDateString() : "N/A"} · Source: ${(cve.sources||[]).join(", ")}`
                    : `Found in: ${(cve.repos||[]).join(", ")} · ${cve.count} occurrence${cve.count !== 1 ? "s" : ""}`
                  }
                </div>
              </div>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                target="_blank"
                rel="noreferrer"
                style={{
                  fontSize: 10, color: T.accent, fontFamily: T.font,
                  textDecoration: "none", border: `1px solid ${T.accentDim}`,
                  padding: "4px 10px", borderRadius: 4, whiteSpace: "nowrap",
                }}
              >NVD ↗</a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────
