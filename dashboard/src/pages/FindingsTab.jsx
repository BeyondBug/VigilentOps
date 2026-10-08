import { useState, useEffect } from "react";
import { T, SEV_COLOR } from "../theme";
import { FilterGroup, FindingCard, EmptyState } from "../components";
import useFindings from "../useFindings";
import FindingPage from "../FindingPage";

export default function FindingsTab({ scans }) {
  const [sevFilter, setSevFilter] = useState("ALL");
  const [toolFilter, setToolFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [reviewFilter, setReviewFilter] = useState("ALL");
  const [page, setPage] = useState(0);
  const result = useFindings({ page, severity: sevFilter === "ALL" ? "" : sevFilter,
    scanner: toolFilter === "ALL" ? "" : toolFilter, search,
    reviewStatus: reviewFilter === "ALL" ? "" : reviewFilter, revision: scans });
  useEffect(() => {
    if (!result.loading && !result.error && page > 0 && page * 50 >= result.total) setPage(0);
  }, [result.loading, result.error, result.total, page]);
  const changeFilter = setter => value => { setter(value); setPage(0); };
  const tools = ["ALL", ...result.scanners];
  const sevs  = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      {/* Filters */}
      <div style={{
        background: T.panel, border: `1px solid ${T.border}`,
        borderRadius: 8, padding: "14px 20px", marginBottom: 16,
        display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap",
      }}>
        <input
          placeholder="Search findings…"
          value={search}
          maxLength={200}
          aria-label="Search findings"
          onChange={e => changeFilter(setSearch)(e.target.value)}
          style={{
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
            padding: "7px 12px", color: T.text, fontFamily: T.font, fontSize: 12,
            outline: "none", flex: "1 1 200px",
          }}
        />
        <FilterGroup label="Severity" options={sevs} value={sevFilter} onChange={changeFilter(setSevFilter)} colorMap={SEV_COLOR} />
        <FilterGroup label="Scanner"  options={tools} value={toolFilter} onChange={changeFilter(setToolFilter)} />
        <label style={{ fontSize: 11, color: T.textDim }}>Review <select aria-label="Review status"
          value={reviewFilter} onChange={e => changeFilter(setReviewFilter)(e.target.value)}>
          {["ALL", "unverified", "confirmed", "false_positive", "accepted_risk", "fixed"].map(status =>
            <option key={status} value={status}>{status.replaceAll("_", " ")}</option>)}
        </select></label>
      </div>

      {/* Count */}
      <div style={{ fontSize: 11, color: T.textDim, fontFamily: T.font, marginBottom: 12, letterSpacing: 1 }}>
        Latest 100 scans · {result.total_in_scope.toLocaleString()} finding records in scope
      </div>

      {/* Findings list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {result.error ? <EmptyState message={`Unable to load findings: ${result.error}`} /> : result.loading ? (
          <EmptyState message="Loading findings…" />
        ) : result.findings.length === 0 ? (
          <EmptyState message="No findings match the current filters." />
        ) : result.findings.map(f => (
          <FindingCard key={f.id} finding={f} showRepo />
        ))}
      </div>
      <FindingPage page={page} total={result.total} loading={result.loading} onChange={setPage} />
    </div>
  );
}
