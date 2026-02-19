#!/usr/bin/env python3
"""
NVD API Client
Queries the NVD CPE and CVE APIs to find vulnerabilities
for a given software inventory.
"""

import time
import json
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Optional


NVD_CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits: 5 req/30s without key, 50 req/30s with key
REQUEST_DELAY_NO_KEY = 6.5   # seconds between requests
REQUEST_DELAY_WITH_KEY = 0.7


@dataclass
class CpeMatch:
    cpe_name: str
    cpe_name_id: str
    title: str
    deprecated: bool


@dataclass
class CveResult:
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published: str
    last_modified: str
    cpe_name: str
    references: list[str] = field(default_factory=list)


class NVDClient:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.delay = REQUEST_DELAY_WITH_KEY if api_key else REQUEST_DELAY_NO_KEY
        self._last_request = 0.0

    def _get(self, url: str, params: dict) -> dict:
        """Throttled GET request to NVD API."""
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

        query = urllib.parse.urlencode(params)
        full_url = f"{url}?{query}"

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        req = urllib.request.Request(full_url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self._last_request = time.time()
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f"  [!] HTTP {e.code} for {full_url}")
            if e.code == 429:
                print("  [!] Rate limited. Sleeping 30s...")
                time.sleep(30)
                return self._get(url, params)
            return {}
        except Exception as e:
            print(f"  [!] Request failed: {e}")
            return {}

    def search_cpe(self, keyword: str, limit=5) -> list[CpeMatch]:
        """Search NVD CPE dictionary by keyword."""
        params = {
            "keywordSearch": keyword,
            "keywordExactMatch": "",
            "resultsPerPage": limit,
        }
        data = self._get(NVD_CPE_BASE, params)
        results = []
        for product in data.get("products", []):
            cpe = product.get("cpe", {})
            title = ""
            titles = cpe.get("titles", [])
            if titles:
                title = titles[0].get("title", "")
            results.append(CpeMatch(
                cpe_name=cpe.get("cpeName", ""),
                cpe_name_id=cpe.get("cpeNameId", ""),
                title=title,
                deprecated=cpe.get("deprecated", False),
            ))
        return results

    def search_cpe_by_name(self, cpe_match_string: str, limit=5) -> list[CpeMatch]:
        """Search CPE by partial CPE name."""
        params = {
            "cpeMatchString": cpe_match_string,
            "resultsPerPage": limit,
        }
        data = self._get(NVD_CPE_BASE, params)
        results = []
        for product in data.get("products", []):
            cpe = product.get("cpe", {})
            title = ""
            titles = cpe.get("titles", [])
            if titles:
                title = titles[0].get("title", "")
            results.append(CpeMatch(
                cpe_name=cpe.get("cpeName", ""),
                cpe_name_id=cpe.get("cpeNameId", ""),
                title=title,
                deprecated=cpe.get("deprecated", False),
            ))
        return results

    def get_cves_for_cpe(self, cpe_name: str, limit=20) -> list[CveResult]:
        """Get CVEs associated with a specific CPE name."""
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": limit,
        }
        data = self._get(NVD_CVE_BASE, params)
        results = []

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            # Description
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS score and severity
            severity = "UNKNOWN"
            score = 0.0
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                    break

            # References
            refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

            results.append(CveResult(
                cve_id=cve_id,
                description=desc[:300],
                severity=severity,
                cvss_score=score,
                published=cve.get("published", ""),
                last_modified=cve.get("lastModified", ""),
                cpe_name=cpe_name,
                references=refs,
            ))

        return results

    def get_cves_by_keyword(self, keyword: str, limit=10) -> list[CveResult]:
        """Search CVEs directly by keyword (fallback)."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
        }
        data = self._get(NVD_CVE_BASE, params)
        results = []

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            severity = "UNKNOWN"
            score = 0.0
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get("cvssData", {})
                    score = cvss_data.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
                    break

            refs = [r.get("url", "") for r in cve.get("references", [])[:5]]

            results.append(CveResult(
                cve_id=cve_id,
                description=desc[:300],
                severity=severity,
                cvss_score=score,
                published=cve.get("published", ""),
                last_modified=cve.get("lastModified", ""),
                cpe_name=keyword,
                references=refs,
            ))

        return results
