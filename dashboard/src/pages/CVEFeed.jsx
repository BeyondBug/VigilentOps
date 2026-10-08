import { useState, useEffect, useCallback } from "react";
import { T, SEV_COLOR, sevBadge } from "../theme";
import { FilterGroup, EmptyState } from "../components";
import { API, CVE_INTEL } from "../api";

export default function CVEFeed({ scans }) {
  const [loading, setLoading] = useState(false);
  const [cveData, setCveData] = useState([]);
  const [error, setError] = useState(null);
  const [scanTotal, setScanTotal] = useState(0);
  const [filter, setFilter] = useState("ALL");
  const [source, setSource] = useState("live");  // "live" | "scan"

  // Fetch live CVE feed from cve-intel service
  const fetchLiveCVEs = useCallback(async (signal) => {
    setLoading(true);
    setError(null);
    setCveData([]);
    try {
      const r = await fetch(`${CVE_INTEL}/cves/recent?limit=100`, { signal });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      {
        const data = await r.json();
        if (signal.aborted) return;
        setCveData(
          data.map(c => ({
            id:          c.cve_id,
            severity:    c.severity || "UNKNOWN",
            score:       c.cvss_score ?? null,
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
      if (!signal.aborted) setError(`Live CVE feed unavailable: ${e.message}`);
    } finally {
      if (!signal.aborted) setLoading(false);
    }
  }, []);

  const loadScanCVEs = useCallback(async (signal) => {
    setLoading(true);
    setError(null);
    setCveData([]);
    try {
      const response = await fetch(`${API}/api/cves/summary?limit=200`, { signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (signal.aborted) return;
      setCveData(data.cves);
      setScanTotal(data.total);
    } catch (failure) {
      if (!signal.aborted) setError(`Scan CVEs unavailable: ${failure.message}`);
    } finally {
      if (!signal.aborted) setLoading(false);
    }
  }, [scans]);

  useEffect(() => {
    const controller = new AbortController();
    if (source === "live") {
      fetchLiveCVEs(controller.signal);
    } else {
      loadScanCVEs(controller.signal);
    }
    return () => controller.abort();
  }, [source, fetchLiveCVEs, loadScanCVEs]);

  const sevs     = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
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

      {source === "scan" && <p style={{ color: T.textDim, fontSize: 12 }}>Latest 100 scans · showing {cveData.length} of {scanTotal} distinct CVEs</p>}
      {error ? <EmptyState message={error} /> : filtered.length === 0 ? (
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
                  {(
                    <span style={{
                      fontSize: 11, padding: "1px 7px", borderRadius: 4,
                      background: `${SEV_COLOR[(cve.severity || "").toUpperCase()]}18`,
                      color: SEV_COLOR[(cve.severity || "").toUpperCase()] || T.textDim,
                      fontFamily: T.font, fontWeight: 700,
                    }}>CVSS {cve.score ?? "Not reported"}</span>
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
