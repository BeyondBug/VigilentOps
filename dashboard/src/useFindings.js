import { useEffect, useState } from "react";
import { fetchFindings } from "./api";

export default function useFindings({ scanId, page, severity = "", scanner = "", search = "", reviewStatus = "", findingClass = "", verifiedOnly = false, groupDuplicates = false, groupId, revision, enabled = true }) {
  const [result, setResult] = useState({ findings: [], total: 0, total_in_scope: 0, scanners: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    const timer = setTimeout(async () => {
      try {
        const data = await fetchFindings({ scanId, page, severity, scanner, search, reviewStatus, findingClass, verifiedOnly, groupDuplicates, groupId, signal: controller.signal });
        if (!controller.signal.aborted) setResult(data);
      } catch (failure) {
        if (!controller.signal.aborted) setError(failure.message);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 250);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [scanId, page, severity, scanner, search, reviewStatus, findingClass, verifiedOnly, groupDuplicates, groupId, revision, enabled]);
  return { ...result, loading, error };
}
