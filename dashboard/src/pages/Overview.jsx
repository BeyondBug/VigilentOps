import { T, SEV_COLOR } from "../theme";
import { StatCard, SectionHeader, EmptyState } from "../components";
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from "recharts";

export default function Overview({ scans }) {
  const totalScans    = scans.length;
  const totalFindings = scans.reduce((s, r) => s + (r.total_findings || 0), 0);
  const totalCritical = scans.reduce((s, r) => s + (r.verified_severity_counts?.CRITICAL || 0), 0);
  const totalHigh     = scans.reduce((s, r) => s + (r.verified_severity_counts?.HIGH || 0), 0);
  const confirmed = scans.reduce((s, r) => s + (r.verified_finding_count || 0), 0);
  const proposedFindings = scans.reduce((s, r) => s + (r.proposed_finding_count || 0), 0);

  // Last 10 scans for area chart
  const trendData = scans.slice(0, 10).reverse().map(r => ({
    name:     `#${r.id}`,
    critical: r.critical_count || 0,
    high:     r.high_count || 0,
    total:    r.total_findings || 0,
  }));

  // Findings by tool (pie)
  const toolMap = {};
  scans.forEach(r => {
    Object.entries(r.scanner_counts || {}).forEach(([tool, count]) => {
      toolMap[tool] = (toolMap[tool] || 0) + count;
    });
  });
  const pieData = Object.entries(toolMap).map(([name, value]) => ({ name, value }));
  const PIE_COLORS = [T.accent, "#7c4dff", "#ff6d00", T.green, "#ff4081"];

  // Severity breakdown bar
  const sevMap = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
  scans.forEach(r => {
    Object.entries(r.severity_counts || {}).forEach(([severity, count]) => {
      if (severity in sevMap) sevMap[severity] += count;
    });
  });
  const sevData = Object.entries(sevMap).map(([name, count]) => ({ name, count }));

  // Recent 5 scans
  const recent = [...scans].slice(0, 5);

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 24 }}>
        <StatCard label="RECENT SCANS"     value={totalScans}    icon="⬡" color={T.accent} sub="latest 100 scans" />
        <StatCard label="FINDING RECORDS"  value={totalFindings} icon="⚠" color={T.text}  sub="across latest 100 scans" />
        <StatCard label="EVIDENCE CONFIRMED" value={confirmed} icon="✓" color={T.green} sub="reviewer attested reproduction" />
        <StatCard label="CONFIRMED CRITICAL"        value={totalCritical} icon="🔴" color={SEV_COLOR.CRITICAL} sub="evidence confirmed" />
        <StatCard label="CONFIRMED HIGH"            value={totalHigh}     icon="🟠" color={SEV_COLOR.HIGH}     sub="evidence confirmed" />
        <StatCard label="FINDINGS WITH PR" value={proposedFindings} icon="🤖" color={T.green} sub="review required" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        {/* Trend chart */}
        <div style={{ background: T.panel, border: `1px solid ${T.border}`, borderRadius: 8, padding: 20 }}>
          <SectionHeader title="RAW SCANNER TREND" />
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
          <SectionHeader title="RAW ALERT SEVERITY" />
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
