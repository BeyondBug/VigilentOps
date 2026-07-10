import os, httpx, time

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = os.getenv("NVD_API_KEY", "")

class NVDClient:
    def __init__(self):
        self.headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    
    def get_cve(self, cve_id: str) -> dict:
        try:
            with httpx.Client(timeout=15) as client:
                r = client.get(NVD_API, params={"cveId": cve_id}, headers=self.headers)
                if r.status_code == 200:
                    vulns = r.json().get("vulnerabilities", [])
                    if vulns:
                        cve = vulns[0].get("cve", {})
                        metrics = cve.get("metrics", {})
                        cvss4 = metrics.get("cvssMetricV40", [{}])[0]
                        cvss3 = metrics.get("cvssMetricV31", [{}])[0]
                        score = (cvss4.get("cvssData", {}).get("baseScore") or
                                 cvss3.get("cvssData", {}).get("baseScore") or 0)
                        return {
                            "cvss_score": float(score),
                            "cvss_vector": cvss3.get("cvssData", {}).get("vectorString", ""),
                            "description": cve.get("descriptions", [{}])[0].get("value", ""),
                            "published": cve.get("published", ""),
                        }
        except Exception as e:
            print(f"NVD lookup error for {cve_id}: {e}")
        return {}

    def enrich_findings(self, findings: list) -> list:
        enriched = []
        for f in findings:
            cve_id = f.get("cve_id") or f.get("rule_id", "")
            if cve_id.startswith("CVE-"):
                nvd_data = self.get_cve(cve_id)
                f.update(nvd_data)
                time.sleep(0.7)  # Respect NVD rate limit (no key: 5 req/30s)
            enriched.append(f)
        return enriched
