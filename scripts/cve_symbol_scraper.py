#!/usr/bin/env python3
"""
CVE Symbol Scraper - Extract vulnerable function/symbol names from CVE entries
Scrapes NVD, GitHub commits, and advisories to identify specific vulnerable code symbols
"""

import requests
import re
import time
import json
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class VulnerableSymbol:
    """Represents a vulnerable function or symbol"""

    name: str
    source: str  # Where we found it (commit, advisory, description)
    confidence: str  # high, medium, low
    context: str  # Surrounding context
    cve_id: str


class CVESymbolScraper:
    """Scrapes CVE data and extracts vulnerable symbols"""

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CVE-Symbol-Scraper/1.0"})
        if nvd_api_key:
            logger.info("Appending api key")
            self.session.headers.update({"apiKey": nvd_api_key})

        # Rate limiting
        self.request_delay = 0.6 if not nvd_api_key else 0.02
        self.last_request_time = 0

    def fetch_cve(self, cve_id: str) -> Dict:
        """Fetch CVE data from NVD API"""
        self._rate_limit()
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            if data.get("vulnerabilities"):
                return data["vulnerabilities"][0]["cve"]
            return {}
        except requests.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return {}

    def extract_symbols_from_description(
        self, description: str, cve_id: str
    ) -> List[VulnerableSymbol]:
        """Extract function names from CVE description text"""
        symbols = []

        # Pattern 1: Explicit function mentions with parentheses
        # Matches: function_name(), my_func(), etc.
        func_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(\)"
        for match in re.finditer(func_pattern, description):
            func_name = match.group(1)
            context = description[
                max(0, match.start() - 50) : min(len(description), match.end() + 50)
            ]
            symbols.append(
                VulnerableSymbol(
                    name=func_name,
                    source="description",
                    confidence="medium",
                    context=context.strip(),
                    cve_id=cve_id,
                )
            )

        # Pattern 2: Backtick-quoted identifiers (common in markdown)
        backtick_pattern = r"`([a-zA-Z_][a-zA-Z0-9_]{2,})`"
        for match in re.finditer(backtick_pattern, description):
            identifier = match.group(1)
            # Filter out common words
            if identifier.lower() not in [
                "the",
                "and",
                "for",
                "with",
                "from",
                "null",
                "true",
                "false",
            ]:
                context = description[
                    max(0, match.start() - 50) : min(len(description), match.end() + 50)
                ]
                symbols.append(
                    VulnerableSymbol(
                        name=identifier,
                        source="description",
                        confidence="low",
                        context=context.strip(),
                        cve_id=cve_id,
                    )
                )

        # Pattern 3: Common vulnerability keywords followed by identifiers
        vuln_keywords = r'(vulnerable function|affected function|function|method|symbol|API|call to)\s+[`"]?([a-zA-Z_][a-zA-Z0-9_]{2,})[`"]?'
        for match in re.finditer(vuln_keywords, description, re.IGNORECASE):
            func_name = match.group(2)
            context = description[
                max(0, match.start() - 50) : min(len(description), match.end() + 50)
            ]
            symbols.append(
                VulnerableSymbol(
                    name=func_name,
                    source="description",
                    confidence="high",
                    context=context.strip(),
                    cve_id=cve_id,
                )
            )

        # Pattern 4: Identifiers followed by common vulnerability keywords
        vuln_keywords = r'[`"]?([a-zA-Z_][a-zA-Z0-9_]{2,})[`"]\s+(vulnerable function|affected function|function|method|symbol|API|call to)?'
        for match in re.finditer(vuln_keywords, description, re.IGNORECASE):
            func_name = match.group(1)
            context = description[
                max(0, match.start() - 50) : min(len(description), match.end() + 50)
            ]
            symbols.append(
                VulnerableSymbol(
                    name=func_name,
                    source="description",
                    confidence="high",
                    context=context.strip(),
                    cve_id=cve_id,
                )
            )

        # Pattern 5: Kernel-specific function prefixes (__, do_, sys_, ksys_)
        kernel_fn_prefixes = r"\s+(__[a-zA-Z0-9_]*|do_[a-zA-Z0-9_]*|sys_[a-zA-Z0-9_]*|ksys_[a-zA-Z0-9_]*)"
        for match in re.finditer(kernel_fn_prefixes, description):
            func_name = match.group(1)
            context = description[
                max(0, match.start() - 50) : min(len(description), match.end() + 50)
            ]
            symbols.append(
                VulnerableSymbol(
                    name=func_name,
                    source="description",
                    confidence="high",
                    context=context.strip(),
                    cve_id=cve_id,
                )
            )

        return symbols

    def fetch_github_commit_diff(self, commit_url: str) -> Optional[str]:
        """Fetch the diff from a GitHub commit"""
        try:
            # Convert GitHub URL to patch URL
            if "github.com" in commit_url:
                patch_url = commit_url.rstrip("/") + ".patch"
                response = self.session.get(patch_url, timeout=30)
                response.raise_for_status()
                return response.text
        except requests.RequestException as e:
            logger.warning(f"Could not fetch commit diff from {commit_url}: {e}")
        return None

    def extract_symbols_from_diff(
        self, diff_text: str, cve_id: str, source_url: str
    ) -> List[VulnerableSymbol]:
        """Extract function names from a git diff/patch"""
        symbols = []

        # Pattern 1: C/C++ function definitions
        # Matches: void function_name(...), int my_func(...), etc.
        c_func_pattern = r"^[-+]\s*(?:static\s+)?(?:inline\s+)?(?:const\s+)?(\w+(?:\s*\*)*)\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|;)?"

        # Pattern 2: Python function definitions
        py_func_pattern = r"^[-+]\s*def\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\("

        # Pattern 3: Java/JavaScript/C# methods
        java_func_pattern = r"^[-+]\s*(?:public|private|protected)?\s*(?:static)?\s*\w+\s+([a-zA-Z_][a-zA-Z0-9_]+)\s*\("

        lines = diff_text.split("\n")
        for i, line in enumerate(lines):
            # C/C++ functions
            match = re.match(c_func_pattern, line)
            if match:
                func_name = match.group(2)
                context = "\n".join(lines[max(0, i - 2) : min(len(lines), i + 3)])
                symbols.append(
                    VulnerableSymbol(
                        name=func_name,
                        source=f"commit_diff: {source_url}",
                        confidence="high",
                        context=context,
                        cve_id=cve_id,
                    )
                )

            # Python functions
            match = re.match(py_func_pattern, line)
            if match:
                func_name = match.group(1)
                context = "\n".join(lines[max(0, i - 2) : min(len(lines), i + 3)])
                symbols.append(
                    VulnerableSymbol(
                        name=func_name,
                        source=f"commit_diff: {source_url}",
                        confidence="high",
                        context=context,
                        cve_id=cve_id,
                    )
                )

            # Java/JavaScript/C# methods
            match = re.match(java_func_pattern, line)
            if match:
                func_name = match.group(1)
                context = "\n".join(lines[max(0, i - 2) : min(len(lines), i + 3)])
                symbols.append(
                    VulnerableSymbol(
                        name=func_name,
                        source=f"commit_diff: {source_url}",
                        confidence="high",
                        context=context,
                        cve_id=cve_id,
                    )
                )

            # Pattern 4: Function calls in changed lines (lower confidence)
            if line.startswith("+") or line.startswith("-"):
                func_call_pattern = r"\b([a-zA-Z_][a-zA-Z0-9_]{3,})\s*\("
                for match in re.finditer(func_call_pattern, line):
                    func_name = match.group(1)
                    # Filter out common keywords
                    if func_name not in [
                        "if",
                        "for",
                        "while",
                        "switch",
                        "return",
                        "sizeof",
                        "malloc",
                        "free",
                    ]:
                        context = "\n".join(
                            lines[max(0, i - 1) : min(len(lines), i + 2)]
                        )
                        symbols.append(
                            VulnerableSymbol(
                                name=func_name,
                                source=f"commit_call: {source_url}",
                                confidence="medium",
                                context=context,
                                cve_id=cve_id,
                            )
                        )

        return symbols

    def extract_symbols_from_github_issue(
        self, issue_url: str, cve_id: str
    ) -> List[VulnerableSymbol]:
        """Extract symbols from GitHub issue or PR description"""
        symbols = []

        try:
            # Convert to API URL
            api_url = issue_url.replace("github.com", "api.github.com/repos")
            if "/pull/" in api_url:
                api_url = api_url.replace("/pull/", "/pulls/")
            elif "/issues/" in api_url:
                api_url = api_url.replace("/issues/", "/issues/")

            response = self.session.get(api_url, timeout=30)
            response.raise_for_status()
            data = response.json()

            # Extract from title and body
            text = f"{data.get('title', '')} {data.get('body', '')}"
            symbols.extend(self.extract_symbols_from_description(text, cve_id))

            # Update source for these symbols
            for symbol in symbols:
                symbol.source = f"github_issue: {issue_url}"

        except requests.RequestException as e:
            logger.warning(f"Could not fetch GitHub issue {issue_url}: {e}")

        return symbols

    def analyze_cve_data(self, cve_data: Dict) -> Dict[str, Any]:
        """Complete analysis of a CVE to extract vulnerable symbols"""

        # Fetch CVE data
        # cve_data = self.fetch_cve(cve_id)
        # if not cve_data:
        #     return {
        #         "cve_id": cve_id,
        #         "error": "Could not fetch CVE data",
        #         "symbols": [],
        #     }

        all_symbols = []
        cve_id = cve_data.get("id", "")
        logger.info(f"Analyzing {cve_id}...")

        # Extract from description
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                all_symbols.extend(
                    self.extract_symbols_from_description(desc["value"], cve_id)
                )

        # Extract from references
        references = cve_data.get("references", [])
        for ref in references:
            url = ref.get("url", "")

            # GitHub commits
            if "github.com" in url and "/commit/" in url:
                logger.info(f"  Analyzing commit: {url}")
                diff = self.fetch_github_commit_diff(url)
                if diff:
                    all_symbols.extend(
                        self.extract_symbols_from_diff(diff, cve_id, url)
                    )

            # GitHub issues/PRs
            elif "github.com" in url and ("/issues/" in url or "/pull/" in url):
                logger.info(f"  Analyzing issue/PR: {url}")
                all_symbols.extend(self.extract_symbols_from_github_issue(url, cve_id))

        # Deduplicate symbols (keep highest confidence)
        symbol_dict = {}
        for symbol in all_symbols:
            key = symbol.name.lower()
            if key not in symbol_dict or self._confidence_score(
                symbol.confidence
            ) > self._confidence_score(symbol_dict[key].confidence):
                symbol_dict[key] = symbol

        unique_symbols = list(symbol_dict.values())

        # Sort by confidence
        unique_symbols.sort(
            key=lambda x: self._confidence_score(x.confidence), reverse=True
        )

        return {
            "cve_id": cve_id,
            "description": descriptions[0]["value"] if descriptions else "",
            "published_date": cve_data.get("published"),
            "references": [ref["url"] for ref in references],
            "symbols": unique_symbols,
            "symbol_count": len(unique_symbols),
        }

    def analyze_cve(self, cve_id: str) -> Dict[str, Any]:
        """Complete analysis of a CVE to extract vulnerable symbols"""
        logger.info(f"Analyzing {cve_id}...")

        # Fetch CVE data
        cve_data = self.fetch_cve(cve_id)
        if not cve_data:
            return {
                "cve_id": cve_id,
                "error": "Could not fetch CVE data",
                "symbols": [],
            }

        all_symbols = []

        # Extract from description
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                all_symbols.extend(
                    self.extract_symbols_from_description(desc["value"], cve_id)
                )

        # Extract from references
        references = cve_data.get("references", [])
        for ref in references:
            url = ref.get("url", "")

            # GitHub commits
            if "github.com" in url and "/commit/" in url:
                logger.info(f"  Analyzing commit: {url}")
                diff = self.fetch_github_commit_diff(url)
                if diff:
                    all_symbols.extend(
                        self.extract_symbols_from_diff(diff, cve_id, url)
                    )

            # GitHub issues/PRs
            elif "github.com" in url and ("/issues/" in url or "/pull/" in url):
                logger.info(f"  Analyzing issue/PR: {url}")
                all_symbols.extend(self.extract_symbols_from_github_issue(url, cve_id))

        # Deduplicate symbols (keep highest confidence)
        symbol_dict = {}
        for symbol in all_symbols:
            key = symbol.name.lower()
            if key not in symbol_dict or self._confidence_score(
                symbol.confidence
            ) > self._confidence_score(symbol_dict[key].confidence):
                symbol_dict[key] = symbol

        unique_symbols = list(symbol_dict.values())

        # Sort by confidence
        unique_symbols.sort(
            key=lambda x: self._confidence_score(x.confidence), reverse=True
        )

        return {
            "cve_id": cve_id,
            "description": descriptions[0]["value"] if descriptions else "",
            "published_date": cve_data.get("published"),
            "references": [ref["url"] for ref in references],
            "symbols": unique_symbols,
            "symbol_count": len(unique_symbols),
        }

    @staticmethod
    def _confidence_score(confidence: str) -> int:
        """Convert confidence level to numeric score"""
        return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)

    def export_results(self, results: Dict, output_file: str):
        """Export results to JSON file"""
        # Convert dataclasses to dicts
        export_data = results.copy()
        export_data["symbols"] = [asdict(s) for s in results["symbols"]]

        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)
        logger.info(f"Results exported to {output_file}")


def main():
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract vulnerable symbols from CVE entries"
    )
    parser.add_argument(
        "cve_ids", nargs="+", help="CVE IDs to analyze (e.g., CVE-2021-44228)"
    )
    parser.add_argument("--api-key", help="NVD API key for higher rate limits")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    scraper = CVESymbolScraper(nvd_api_key=args.api_key)

    all_results = []
    for cve_id in args.cve_ids:
        results = scraper.analyze_cve(cve_id)
        all_results.append(results)

        # Print results
        print(f"\n{'='*80}")
        print(f"CVE: {results['cve_id']}")
        print(f"Symbols found: {results['symbol_count']}")
        print(f"{'='*80}\n")

        for symbol in results["symbols"]:
            print(f"Symbol: {symbol.name}")
            print(f"  Source: {symbol.source}")
            print(f"  Confidence: {symbol.confidence}")
            print(f"  Context: {symbol.context[:100]}...")
            print()

    # Export if requested
    if args.output:
        if len(all_results) == 1:
            scraper.export_results(all_results[0], args.output)
        else:
            with open(args.output, "w") as f:
                export_data = []
                for result in all_results:
                    r = result.copy()
                    r["symbols"] = [asdict(s) for s in result["symbols"]]
                    export_data.append(r)
                json.dump(export_data, f, indent=2)
            logger.info(f"Results exported to {args.output}")


if __name__ == "__main__":
    main()
