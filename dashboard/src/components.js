import { useState } from "react";
import { API } from "./api";
import { T, SEV_COLOR, TOOL_ICON, sevBadge } from "./theme";

export function Sidebar({ tab, setTab, online }) {
  const items = [
    { id: "overview",  label: "Overview",    icon: "◈" },
    { id: "scans",     label: "Scan History", icon: "⊟" },
    { id: "findings",  label: "Findings",     icon: "⚠" },
    { id: "cve",       label: "CVE Feed",     icon: "⬡" },
  ];
  return (
    <aside style={{
      width: 220, minHeight: "100vh", background: T.surface,
      borderRight: `1px solid ${T.border}`, display: "flex",
      flexDirection: "column", position: "fixed", top: 0, left: 0, zIndex: 100,
    }}>
      {/* Logo */}
      <div style={{
        padding: "24px 20px 20px", borderBottom: `1px solid ${T.border}`,
      }}>
        <div style={{ fontFamily: T.font, fontWeight: 700, fontSize: 15, color: T.accent, letterSpacing: 2 }}>
          SECURE
        </div>
        <div style={{ fontFamily: T.font, fontWeight: 700, fontSize: 15, color: T.text, letterSpacing: 2 }}>
          GUARD
        </div>
        <div style={{
          marginTop: 8, fontSize: 10, color: T.textDim, fontFamily: T.font, letterSpacing: 1,
        }}>
          SECURITY COPILOT v1.0
        </div>
      </div>

      {/* Status dot */}
      <div style={{
        padding: "10px 20px", borderBottom: `1px solid ${T.border}`,
        display: "flex", alignItems: "center", gap: 8,
      }}>
        <div style={{
          width: 7, height: 7, borderRadius: "50%",
          background: online ? T.green : T.red,
          animation: online ? "pulse 2s infinite" : "none",
          boxShadow: online ? `0 0 6px ${T.green}` : "none",
        }}/>
        <span style={{ fontSize: 11, color: T.textDim, fontFamily: T.font }}>
          {online ? "API ONLINE" : "API OFFLINE"}
        </span>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: "12px 0" }}>
        {items.map(item => (
          <button key={item.id} onClick={() => setTab(item.id)} style={{
            width: "100%", display: "flex", alignItems: "center", gap: 12,
            padding: "11px 20px", background: tab === item.id ? `${T.accent}12` : "transparent",
            border: "none", borderLeft: tab === item.id ? `2px solid ${T.accent}` : "2px solid transparent",
            color: tab === item.id ? T.accent : T.textDim, cursor: "pointer",
            fontFamily: T.fontUI, fontSize: 13, fontWeight: tab === item.id ? 600 : 400,
            transition: "all 0.15s",
            textAlign: "left",
          }}>
            <span style={{ fontFamily: T.font, fontSize: 16, width: 18, textAlign: "center" }}>{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        padding: "16px 20px", borderTop: `1px solid ${T.border}`,
        fontSize: 10, color: T.textFade, fontFamily: T.font, lineHeight: 1.8,
      }}>
        <div>API: {API}</div>
        <div>Refresh: 15s</div>
      </div>
    </aside>
  );
}

export function StatCard({ label, value, sub, color, icon }) {
  return (
    <div style={{
      background: T.panel, border: `1px solid ${T.border}`,
      borderRadius: 8, padding: "20px 24px",
      borderTop: `2px solid ${color || T.accent}`,
      animation: "fadeIn 0.3s ease",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ fontSize: 11, color: T.textDim, fontFamily: T.font, letterSpacing: 1, marginBottom: 8 }}>
            {label}
          </div>
          <div style={{
            fontSize: 32, fontWeight: 700, fontFamily: T.font,
            color: color || T.text, lineHeight: 1,
          }}>
            {value}
          </div>
          {sub && (
            <div style={{ fontSize: 11, color: T.textDim, marginTop: 6 }}>{sub}</div>
          )}
        </div>
        <span style={{ fontSize: 24, opacity: 0.4 }}>{icon}</span>
      </div>
    </div>
  );
}

export function SectionHeader({ title, count }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 12,
      marginBottom: 16, paddingBottom: 12,
      borderBottom: `1px solid ${T.border}`,
    }}>
      <span style={{ fontFamily: T.font, fontWeight: 700, fontSize: 13, color: T.accent, letterSpacing: 2 }}>
        {title}
      </span>
      {count !== undefined && (
        <span style={{
          fontSize: 11, padding: "2px 8px", borderRadius: 10,
          background: `${T.accent}18`, color: T.accent, fontFamily: T.font,
        }}>{count}</span>
      )}
    </div>
  );
}

// ── Overview Tab ──────────────────────────────────────────────────────────────
export function KVRow({ label, value, mono }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: `1px solid ${T.border}18` }}>
      <span style={{ width: 80, fontSize: 11, color: T.textDim, fontFamily: T.font, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 12, color: T.text, fontFamily: mono ? T.font : T.fontUI }}>{value}</span>
    </div>
  );
}

// ── Findings Tab ──────────────────────────────────────────────────────────────
export function FilterGroup({ label, options, value, onChange, colorMap }) {
  return (
    <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
      <span style={{ fontSize: 10, color: T.textDim, fontFamily: T.font, marginRight: 2 }}>{label}:</span>
      {options.map(opt => (
        <button key={opt} onClick={() => onChange(opt)} style={{
          padding: "4px 10px", borderRadius: 4, border: `1px solid ${value === opt ? (colorMap?.[opt] || T.accent) : T.border}`,
          background: value === opt ? `${colorMap?.[opt] || T.accent}18` : "transparent",
          color: value === opt ? (colorMap?.[opt] || T.accent) : T.textDim,
          cursor: "pointer", fontSize: 10, fontFamily: T.font, fontWeight: value === opt ? 700 : 400,
          transition: "all 0.12s",
        }}>{opt}</button>
      ))}
    </div>
  );
}

export function FindingCard({ finding, showRepo }) {
  const [open, setOpen] = useState(false);
  const sev = (finding.severity || "UNKNOWN").toUpperCase();

  return (
    <div style={{
      background: T.surface, border: `1px solid ${T.border}`,
      borderRadius: 7, overflow: "hidden",
      borderLeft: `3px solid ${SEV_COLOR[sev] || SEV_COLOR.UNKNOWN}`,
      animation: "fadeIn 0.2s ease",
    }}>
      <div onClick={() => setOpen(o => !o)} style={{
        padding: "12px 16px", cursor: "pointer", display: "flex",
        justifyContent: "space-between", alignItems: "center",
      }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            {sevBadge(sev)}
            <span style={{ fontSize: 10, color: T.textDim, fontFamily: T.font }}>
              {TOOL_ICON[finding.tool] || "?"} {finding.tool}
            </span>
            {finding.cve_id && (
              <span style={{
                fontSize: 10, padding: "1px 6px", borderRadius: 3,
                background: `${T.accentDim}30`, color: T.accent,
                fontFamily: T.font,
              }}>{finding.cve_id}</span>
            )}
            {(finding.fix_status === 'pr_opened' || finding.pr_url) && (
              <span style={{
                fontSize: 10, padding: "1px 6px", borderRadius: 3,
                background: `${T.green}20`, color: T.green,
                fontFamily: T.font, border: `1px solid ${T.green}40`,
              }}>🤖 REVIEW PR OPEN</span>
            )}
            {finding.fix_status === 'ai_skipped' && (
              <span style={{
                fontSize: 10, padding: "1px 6px", borderRadius: 3,
                background: `${T.textFade}20`, color: T.textDim,
                fontFamily: T.font,
              }}>⊘ UNFIXABLE</span>
            )}
          </div>
          <div style={{ fontSize: 12, color: T.text, fontFamily: T.font, marginBottom: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {finding.message || finding.rule_id || "No message"}
          </div>
          <div style={{ fontSize: 10, color: T.textDim }}>
            {showRepo && <span style={{ marginRight: 8 }}>{finding.repo}</span>}
            {finding.file && <span style={{ fontFamily: T.font }}>{finding.file}{finding.line ? `:${finding.line}` : ""}</span>}
          </div>
        </div>
        <span style={{ color: T.textDim, marginLeft: 16, fontSize: 12 }}>{open ? "▲" : "▼"}</span>
      </div>

      {open && (
        <div style={{
          padding: "0 16px 14px", borderTop: `1px solid ${T.border}18`,
          animation: "fadeIn 0.15s ease",
        }}>
          {finding.cvss_score > 0 && (
            <div style={{ fontSize: 11, color: T.textDim, marginBottom: 8, fontFamily: T.font }}>
              CVSS: <span style={{ color: SEV_COLOR[sev] || T.text, fontWeight: 700 }}>{finding.cvss_score}</span>
              {finding.cwe && <span style={{ marginLeft: 12 }}>CWE: {finding.cwe}</span>}
            </div>
          )}
          {finding.code_snippet && (
            <pre style={{
              background: T.bg, border: `1px solid ${T.border}`, borderRadius: 6,
              padding: 12, fontSize: 11, fontFamily: T.font, color: T.text,
              overflowX: "auto", marginBottom: 8, whiteSpace: "pre-wrap", wordBreak: "break-all",
            }}>{finding.code_snippet}</pre>
          )}
          {finding.pr_url && (
            <div style={{
              marginTop: 10, padding: "10px 14px",
              background: `${T.green}10`, border: `1px solid ${T.green}30`,
              borderRadius: 6,
            }}>
              <div style={{ fontSize: 11, color: T.green, fontFamily: T.font, marginBottom: 6, fontWeight: 700 }}>
                🤖 REMEDIATION PR OPENED — REVIEW REQUIRED
              </div>
              <a href={finding.pr_url} target="_blank" rel="noreferrer" style={{
                fontSize: 12, color: T.accent, textDecoration: "none",
                border: `1px solid ${T.accentDim}`, padding: "4px 12px",
                borderRadius: 4, display: "inline-block",
              }}>
                View Pull Request ↗
              </a>
              <div style={{ fontSize: 10, color: T.textDim, marginTop: 6, fontFamily: T.font }}>
                Review the diff in Gitea, run tests, then merge to apply the fix.
              </div>
            </div>
          )}
          {finding.ai_fix && !finding.pr_url && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: 10, color: T.green, fontFamily: T.font, letterSpacing: 1, marginBottom: 6 }}>
                🤖 AI FIX — CONFIDENCE {Math.round((finding.ai_fix.confidence || 0) * 100)}%
              </div>
              <pre style={{
                background: "#001a0e", border: `1px solid ${T.green}30`, borderRadius: 6,
                padding: 12, fontSize: 11, fontFamily: T.font, color: T.green,
                overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all",
              }}>{finding.ai_fix.fixed_code}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── CVE Feed Tab ──────────────────────────────────────────────────────────────
export function EmptyState({ message }) {
  return (
    <div style={{
      padding: "40px 20px", textAlign: "center",
      color: T.textFade, fontFamily: T.font, fontSize: 12, lineHeight: 2,
    }}>
      <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.4 }}>◈</div>
      {message}
    </div>
  );
}
