// ── Severity helpers ──────────────────────────────────────────────────────────
export const SEV_COLOR = {
  CRITICAL: "#ff3b3b",
  HIGH:     "#ff8c00",
  MEDIUM:   "#f5c518",
  LOW:      "#4fc3f7",
  INFO:     "#90a4ae",
  UNKNOWN:  "#607d8b",
};
export const SEV_BG = {
  CRITICAL: "rgba(255,59,59,0.12)",
  HIGH:     "rgba(255,140,0,0.12)",
  MEDIUM:   "rgba(245,197,24,0.12)",
  LOW:      "rgba(79,195,247,0.12)",
};

export function sevBadge(sev) {
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
export const TOOL_ICON = {
  semgrep:       "⬡",
  bandit:        "🐍",
  gitleaks:      "🔑",
  "trivy-deps":  "📦",
  "trivy-image": "🐋",
  zap:           "⚡",
  checkov:       "🏗️",
  snyk:          "🐕",
  dockle:        "🐳",
  "dep-check":   "🔗",
  nuclei:        "☢️",
  grype:         "🦑",
  sonarqube:     "🔍",
  "syft-sbom":   "📑",
  clamav:        "🦠",
  ffuf:          "💣",
  openscap:      "📋",
  cosign:        "✍️",
};

// ── CSS-in-JS tokens ─────────────────────────────────────────────────────────
export const T = {
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

export const globalCSS = `
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

