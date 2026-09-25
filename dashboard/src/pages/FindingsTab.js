import { useState } from "react";
import { T, SEV_COLOR } from "../theme";
import { FilterGroup, FindingCard, EmptyState } from "../components";

export default function FindingsTab({ scans }) {
  const [sevFilter, setSevFilter] = useState("ALL");
  const [toolFilter, setToolFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const allFindings = scans.flatMap(s =>
    (s.findings || []).map(f => ({ ...f, repo: s.repo_name, scan_id: s.id, scan_time: s.created_at }))
  );

  const tools = ["ALL", ...new Set(allFindings.map(f => f.tool || "unknown"))];
  const sevs  = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const filtered = allFindings.filter(f => {
    const sev  = (f.severity || "").toUpperCase();
    const tool = f.tool || "unknown";
    const text = `${f.message || ""} ${f.rule_id || ""} ${f.file || ""}`.toLowerCase();
    return (sevFilter  === "ALL" || sev  === sevFilter) &&
           (toolFilter === "ALL" || tool === toolFilter) &&
           (search === "" || text.includes(search.toLowerCase()));
  });

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
          onChange={e => setSearch(e.target.value)}
          style={{
            background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
            padding: "7px 12px", color: T.text, fontFamily: T.font, fontSize: 12,
            outline: "none", flex: "1 1 200px",
          }}
        />
        <FilterGroup label="Severity" options={sevs} value={sevFilter} onChange={setSevFilter} colorMap={SEV_COLOR} />
        <FilterGroup label="Scanner"  options={tools} value={toolFilter} onChange={setToolFilter} />
      </div>

      {/* Count */}
      <div style={{ fontSize: 11, color: T.textDim, fontFamily: T.font, marginBottom: 12, letterSpacing: 1 }}>
        SHOWING {filtered.length} / {allFindings.length} FINDINGS
      </div>

      {/* Findings list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {filtered.length === 0 ? (
          <EmptyState message="No findings match the current filters." />
        ) : filtered.map((f, i) => (
          <FindingCard key={i} finding={f} showRepo />
        ))}
      </div>
    </div>
  );
}
