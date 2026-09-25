import { useState, useEffect, useCallback } from "react";
import { API, POLL_MS, fetchHealth, fetchScans } from "./api";
import { T, globalCSS } from "./theme";
import { Sidebar } from "./components";
import Overview from "./pages/Overview";
import ScanHistory from "./pages/ScanHistory";
import FindingsTab from "./pages/FindingsTab";
import CVEFeed from "./pages/CVEFeed";

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
