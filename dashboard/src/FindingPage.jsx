import { T } from "./theme";

export default function FindingPage({ page, total, loading, onChange }) {
  const pages = Math.max(1, Math.ceil(total / 50));
  const style = { background: T.surface, border: `1px solid ${T.border}`, borderRadius: 6,
    padding: "8px 12px", color: T.text, cursor: "pointer" };
  return <nav aria-label="Finding pages" style={{ display: "flex", gap: 12, alignItems: "center", margin: "16px 0" }}>
    <button style={style} disabled={loading || page === 0} onClick={() => onChange(page - 1)}>Previous</button>
    <span style={{ color: T.textDim, fontSize: 12 }}>Page {page + 1} of {pages} · {total.toLocaleString()} findings</span>
    <button style={style} disabled={loading || page + 1 >= pages} onClick={() => onChange(page + 1)}>Next</button>
  </nav>;
}
