import { useState, useEffect, useCallback } from "react";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ── Config ────────────────────────────────────────────────────────────────────
const API = process.env.REACT_APP_API_URL || "http://localhost:8000";
const POLL_MS = 15000; // re-fetch every 15s

// ── Severity helpers ──────────────────────────────────────────────────────────
const SEV_COLOR = {
  CRITICAL: "#ff3b3b",
  HIGH:     "#ff8c00",
  MEDIUM:   "#f5c518",
  LOW:      "#4fc3f7",
  INFO:     "#90a4ae",
  UNKNOWN:  "#607d8b",
};
const SEV_BG = {
  CRITICAL: "rgba(255,59,59,0.12)",
  HIGH:     "rgba(255,140,0,0.12)",
  MEDIUM:   "rgba(245,197,24,0.12)",
  LOW:      "rgba(79,195,247,0.12)",
};

function sevBadge(sev) {
  const s = (sev || "UNKNOWN").toUpperCase();
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: 1,
      color: SEV_COLOR[s] || SEV_COLOR.UNKNOWN,
      background: SEV_BG[s] || "rgba(96,125,139,0.12)",
      border: `1px solid ${SEV_COLOR[s] || SEV_COLOR.UNKNOWN}33`,
    }}>{s}</span>
  );
}

// ── Tool icons (text) ─────────────────────────────────────────────────────────
const TOOL_ICON = {
  semgrep:  "⬡",
  bandit:   "🐍",
  gitleaks: "🔑",
  trivy:    "📦",
  zap:      "⚡",
};

// ── Top-level fetch helpers ───────────────────────────────────────────────────
async function fetchScans() {
  const r = await fetch(`${API}/api/scans?limit=100`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function fetchHealth() {
  const r = await fetch(`${API}/health`);
  return r.ok;
}

// ── CSS-in-JS tokens ─────────────────────────────────────────────────────────
const T = {
  bg:       "#0a0e14",
  surface:  "#0f1520",
  panel:    "#131c2e",
  border:   "#1e2d45",
  borderHi: "#2a3f5f",
  text:     "#cdd9e5",
  textDim:  "#5c7a9b",
  textFade: "#3a5070",
  accent:   "#00e5ff",
  accentDim:"#007b8a",
  green:    "#00e676",
  red:      "#ff3b3b",
  font:     "'JetBrains Mono', 'Fira Mono', 'Consolas', monospace",
  fontUI:   "'Inter', 'Segoe UI', system-ui, sans-serif",
};

const globalCSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, #root { height: 100%; }
  body {
    background: ${T.bg};
    color: ${T.text};
    font-family: ${T.fontUI};
    font-size: 14px;
    -webkit-font-smoothing: antialiased;
  }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: ${T.bg}; }
  ::-webkit-scrollbar-thumb { background: ${T.border}; border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: ${T.borderHi}; }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.3; }
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes scanline {
    0%   { top: -2px; }
    100% { top: 100%; }
  }
`;

// ── Subcomponents ─────────────────────────────────────────────────────────────

function Sidebar({ tab, setTab, online }) {
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

function StatCard({ label, value, sub, color, icon }) {
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

function SectionHeader({ title, count }) {
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
function Overview({ scans }) {
  const totalScans    = scans.length;
  const totalFindings = scans.reduce((s, r) => s + (r.total_findings || 0), 0);
  const totalCritical = scans.reduce((s, r) => s + (r.critical_count || 0), 0);
  const totalHigh     = scans.reduce((s, r) => s + (r.high_count || 0), 0);
  const aiFixed       = scans.reduce((s, r) => {
    const findings = r.findings || [];
    return s + findings.filter(f => f.ai_fix).length;
  }, 0);

  // Last 10 scans for area chart
  const trendData = [...scans].slice(-10).map((r, i) => ({
    name:     `#${i + 1}`,
    critical: r.critical_count || 0,
    high:     r.high_count || 0,
    total:    r.total_findings || 0,
  }));

  // Findings by tool (pie)
  const toolMap = {};
  scans.forEach(r => {
    (r.findings || []).forEach(f => {
      const t = f.tool || "unknown";
      toolMap[t] = (toolMap[t] || 0) + 1;
    });
  });
  const pieData = Object.entries(toolMap).map(([name, value]) => ({ name, value }));
  const PIE_COLORS = [T.accent, "#7c4dff", "#ff6d00", T.green, "#ff4081"];

  // Severity breakdown bar
  const sevMap = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  scans.forEach(r => {
    (r.findings || []).forEach(f => {
      const s = (f.severity || "").toUpperCase();
      if (s in sevMap) sevMap[s]++;
    });
  });
  const sevData = Object.entries(sevMap).map(([name, count]) => ({ name, count }));

  // Recent 5 scans
  const recent = [...scans].slice(0, 5);

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 24 }}>
        <StatCard label="TOTAL SCANS"     value={totalScans}    icon="⬡" color={T.accent} sub="all time" />
        <StatCard label="TOTAL FINDINGS"  value={totalFindings} icon="⚠" color={T.text}  sub="across all scans" />
        <StatCard label="CRITICAL"        value={totalCritical} icon="🔴" color={SEV_COLOR.CRITICAL} sub="CVSS ≥ 9.0" />
        <StatCard label="HIGH"            value={totalHigh}     icon="🟠" color={SEV_COLOR.HIGH}     sub="CVSS 7.0–8.9" />
        <StatCard label="AI FIXES OPENED" value={aiFixed}       icon="🤖" color={T.green} sub="auto-remediated" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        {/* Trend chart */}
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: 20 }}>
          <SectionHeader title="SCAN TREND" />
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="gc" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={T.red}   stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={T.red}   stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={SEV_COLOR.HIGH} stopOpacity={0.3}/>
                  <stop offset="95%" stopColor={SEV_COLOR.HIGH} stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis dataKey="name" tick={{ fill: T.textDim, fontSize: 10, fontFamily: T.font }} axisLine={false} tickLine={false}/>
              <YAxis tick={{ fill: T.textDim, fontSize: 10, fontFamily: T.font }} axisLine={false} tickLine={false}/>
              <Tooltip contentStyle={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6, fontFamily: T.font, fontSize: 12 }} />
              <Area type="monotone" dataKey="critical" stroke={T.red}   fill="url(#gc)" strokeWidth={2}/>
              <Area type="monotone" dataKey="high"     stroke={SEV_COLOR.HIGH} fill="url(#gh)" strokeWidth={2}/>
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Pie by tool */}
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: 20 }}>
          <SectionHeader title="FINDINGS BY SCANNER" />
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" paddingAngle={3}>
                  {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6, fontFamily: T.font, fontSize: 12 }} />
                <Legend iconType="circle" wrapperStyle={{ fontSize: 11, fontFamily: T.font, color: T.textDim }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState message="No scan data yet" />
          )}
        </div>
      </div>

      {/* Severity bar + recent scans */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: 20 }}>
          <SectionHeader title="SEVERITY BREAKDOWN" />
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={sevData} barSize={28}>
              <XAxis dataKey="name" tick={{ fill: T.textDim, fontSize: 10, fontFamily: T.font }} axisLine={false} tickLine={false}/>
              <YAxis tick={{ fill: T.textDim, fontSize: 10, fontFamily: T.font }} axisLine={false} tickLine={false}/>
              <Tooltip contentStyle={{ background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6, fontFamily: T.font, fontSize: 12 }} />
              <Bar dataKey="count" radius={[3,3,0,0]}>
                {sevData.map((entry, i) => (
                  <Cell key={i} fill={SEV_COLOR[entry.name] || T.textDim} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Recent scans */}
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: 20 }}>
          <SectionHeader title="RECENT SCANS" count={recent.length} />
          {recent.length === 0 ? <EmptyState message="No scans yet" /> : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {recent.map(scan => (
                <div key={scan.id} style={{
                  display: "flex", justifyContent: "space-between", alignItems: "center",
                  padding: "8px 12px", background: T.surface, borderRadius: 6,
                  border: `1px solid ${T.border}`,
                }}>
                  <div>
                    <div style={{ fontSize: 12, fontFamily: T.font, color: T.text }}>{scan.repo_name || "unknown repo"}</div>
                    <div style={{ fontSize: 10, color: T.textDim, fontFamily: T.font, marginTop: 2 }}>
                      {(scan.commit_sha || "").slice(0, 8)} · {scan.created_at ? new Date(scan.created_at).toLocaleTimeString() : ""}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    {scan.critical_count > 0 && (
                      <span style={{ fontSize: 11, color: SEV_COLOR.CRITICAL, fontFamily: T.font, fontWeight: 700 }}>
                        {scan.critical_count}C
                      </span>
                    )}
                    {scan.high_count > 0 && (
                      <span style={{ fontSize: 11, color: SEV_COLOR.HIGH, fontFamily: T.font, fontWeight: 700 }}>
                        {scan.high_count}H
                      </span>
                    )}
                    <span style={{ fontSize: 11, color: T.textDim, fontFamily: T.font }}>
                      {scan.total_findings} total
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Scan History Tab ──────────────────────────────────────────────────────────
function ScanHistory({ scans }) {
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

function KVRow({ label, value, mono }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "6px 0", borderBottom: `1px solid ${T.border}18` }}>
      <span style={{ width: 80, fontSize: 11, color: T.textDim, fontFamily: T.font, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 12, color: T.text, fontFamily: mono ? T.font : T.fontUI }}>{value}</span>
    </div>
  );
}

// ── Findings Tab ──────────────────────────────────────────────────────────────
function FindingsTab({ scans }) {
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

function FilterGroup({ label, options, value, onChange, colorMap }) {
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

function FindingCard({ finding, showRepo }) {
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
              }}>🤖 AI PR OPENED</span>
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
                🤖 AI FIX PR OPENED
                {finding.pr_confidence && ` — Confidence ${Math.round(finding.pr_confidence * 100)}%`}
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
const CVE_INTEL = process.env.REACT_APP_CVE_INTEL_URL || "http://localhost:8001";

function CVEFeed({ scans }) {
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
function EmptyState({ message }) {
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

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [tab,    setTab]    = useState("overview");
  const [scans,  setScans]  = useState([]);
  const [online, setOnline] = useState(false);
  const [error,  setError]  = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(async () => {
    try {
      const [healthy, data] = await Promise.all([fetchHealth(), fetchScans()]);
      setOnline(healthy);
      setScans(data);
      setError(null);
      setLastUpdated(new Date());
    } catch (e) {
      setError(e.message);
      setOnline(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, POLL_MS);
    return () => clearInterval(interval);
  }, [load]);

  const tabContent = {
    overview: <Overview  scans={scans} />,
    scans:    <ScanHistory scans={scans} />,
    findings: <FindingsTab scans={scans} />,
    cve:      <CVEFeed   scans={scans} />,
  };

  return (
    <>
      <style>{globalCSS}</style>

      <div style={{ display: "flex", minHeight: "100vh" }}>
        <Sidebar tab={tab} setTab={setTab} online={online} />

        {/* Main content */}
        <main style={{ marginLeft: 220, flex: 1, padding: 24, minHeight: "100vh" }}>
          {/* Top bar */}
          <div style={{
            display: "flex", justifyContent: "space-between", alignItems: "center",
            marginBottom: 24, paddingBottom: 16, borderBottom: `1px solid ${T.border}`,
          }}>
            <div>
              <h1 style={{
                fontFamily: T.font, fontSize: 16, fontWeight: 700,
                color: T.text, letterSpacing: 2,
              }}>
                {tab.toUpperCase().replace("-", " ")}
              </h1>
              {lastUpdated && (
                <div style={{ fontSize: 10, color: T.textFade, fontFamily: T.font, marginTop: 3 }}>
                  Last updated {lastUpdated.toLocaleTimeString()}
                </div>
              )}
            </div>
            <button onClick={load} style={{
              background: "none", border: `1px solid ${T.border}`,
              borderRadius: 6, padding: "6px 14px", color: T.textDim,
              cursor: "pointer", fontFamily: T.font, fontSize: 11, letterSpacing: 1,
              transition: "all 0.12s",
            }}>↻ REFRESH</button>
          </div>

          {/* Error banner */}
          {error && (
            <div style={{
              background: `${T.red}12`, border: `1px solid ${T.red}40`,
              borderRadius: 7, padding: "10px 16px", marginBottom: 16,
              fontSize: 12, color: T.red, fontFamily: T.font,
            }}>
              ⚠ API unreachable — {error}. Make sure the orchestrator is running on {API}
            </div>
          )}

          {tabContent[tab]}
        </main>
      </div>
    </>
  );
}
