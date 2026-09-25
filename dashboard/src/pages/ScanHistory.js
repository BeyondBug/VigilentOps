import { useState } from "react";
import { T, SEV_COLOR } from "../theme";
import { SectionHeader, KVRow, FindingCard, EmptyState } from "../components";

export default function ScanHistory({ scans }) {
  const [selected, setSelected] = useState(null);

  const scan = scans.find(s => s.id === selected);

  return (
    <div style={{ display: "grid", gridTemplateColumns: selected ? "1fr 1fr" : "1fr", gap: 16, animation: "fadeIn 0.3s ease" }}>
      {/* Scan list */}
      <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden" }}>
        <div style={{ padding: "16px 20px", borderBottom: `1px solid ${T.border}` }}>
          <SectionHeader title="ALL SCANS" count={scans.length} />
        </div>
        {scans.length === 0 ? (
          <div style={{ padding: 40 }}><EmptyState message="No scans yet. Push code to Gitea to trigger a scan." /></div>
        ) : (
          <div style={{ overflowY: "auto", maxHeight: "calc(100vh - 200px)" }}>
            {scans.map(s => (
              <div key={s.id} onClick={() => setSelected(s.id === selected ? null : s.id)} style={{
                padding: "14px 20px", borderBottom: `1px solid ${T.border}`,
                cursor: "pointer", background: s.id === selected ? `${T.accent}08` : "transparent",
                borderLeft: s.id === selected ? `2px solid ${T.accent}` : "2px solid transparent",
                transition: "all 0.12s",
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                  <span style={{ fontFamily: T.font, fontSize: 12, color: T.text, fontWeight: 600 }}>
                    {s.repo_name || "unknown"}
                  </span>
                  <span style={{ fontSize: 10, color: T.textDim, fontFamily: T.font }}>
                    {s.created_at ? new Date(s.created_at).toLocaleString() : ""}
                  </span>
                </div>
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <span style={{ fontSize: 10, color: T.textDim, fontFamily: T.font }}>
                    {(s.commit_sha || "").slice(0, 8)}
                  </span>
                  <div style={{ display: "flex", gap: 6 }}>
                    {s.critical_count > 0 && <span style={{ fontSize: 10, color: SEV_COLOR.CRITICAL, fontFamily: T.font }}>{s.critical_count} CRITICAL</span>}
                    {s.high_count     > 0 && <span style={{ fontSize: 10, color: SEV_COLOR.HIGH,     fontFamily: T.font }}>{s.high_count} HIGH</span>}
                    <span style={{ fontSize: 10, color: T.textDim, fontFamily: T.font }}>{s.total_findings} total</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scan detail */}
      {scan && (
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, overflow: "hidden", animation: "fadeIn 0.2s ease" }}>
          <div style={{ padding: "16px 20px", borderBottom: `1px solid ${T.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <SectionHeader title="SCAN DETAIL" />
            <button onClick={() => setSelected(null)} style={{
              background: "none", border: "none", color: T.textDim, cursor: "pointer", fontSize: 18, lineHeight: 1,
            }}>✕</button>
          </div>
          <div style={{ padding: 20, overflowY: "auto", maxHeight: "calc(100vh - 200px)" }}>
            <div style={{ marginBottom: 20 }}>
              <KVRow label="Repo"    value={scan.repo_name} />
              <KVRow label="Commit"  value={(scan.commit_sha || "").slice(0, 16)} mono />
              <KVRow label="Time"    value={scan.created_at ? new Date(scan.created_at).toLocaleString() : "N/A"} />
              <KVRow label="Total"   value={scan.total_findings} />
              <KVRow label="Critical" value={<span style={{ color: SEV_COLOR.CRITICAL, fontWeight: 700 }}>{scan.critical_count}</span>} />
              <KVRow label="High"    value={<span style={{ color: SEV_COLOR.HIGH, fontWeight: 700 }}>{scan.high_count}</span>} />
            </div>
            <div style={{ fontFamily: T.font, fontSize: 11, color: T.textDim, marginBottom: 8, letterSpacing: 1 }}>
              FINDINGS ({(scan.findings || []).length})
            </div>
            {(scan.findings || []).map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
