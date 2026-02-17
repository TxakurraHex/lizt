# LIZT

A comprehensive tool for:
- Manufacturing and maintaining symbol maps extracted from CVE information
- Detecting and interpreting environment configurations and characteristics, including installed kernel modules
- Utilizing information collected by the tool to scan a process's runtime behavior, ranking any detected vulnerabilities with the added context information and reachability analysis.

## Features

- **NVD API Integration**: Fetches CVE data from the official National Vulnerability Database API
- **Multi-Source Analysis**: Extracts symbols from:
  - CVE descriptions
  - GitHub commit diffs
  - GitHub issues and pull requests
  - Referenced security advisories
- **Intelligent Symbol Detection**: Uses pattern matching to identify:
  - Function definitions and declarations
  - Function calls
  - Method names
  - API symbols
- **Confidence Scoring**: Rates symbol findings as high, medium, or low confidence

## Pre-Requisites
- python3
- PostgreSQL

## Installation

```bash
pip install -r requirements.txt
```

Or manually install:
```bash
pip install requests
```

## Quick Start

## How It Works

### 1. CVE Description Analysis
Extracts function names from CVE descriptions using patterns:
- `function_name()` - Explicit function mentions
- `` `identifier` `` - Backtick-quoted symbols (common in markdown)
- Keywords like "vulnerable function", "affected function", etc.

### 2. GitHub Commit Analysis
Parses git diffs from linked commits to find:
- Function definitions (C/C++, Python, Java, JavaScript)
- Modified function signatures
- Function calls in changed lines

### 3. GitHub Issue/PR Analysis
Extracts symbols from issue titles and descriptions where CVE fixes are discussed.

### 4. Confidence Scoring
- **High**: Symbol found in commit diff or explicitly mentioned with vulnerability keywords
- **Medium**: Symbol found in function calls or description text
- **Low**: Symbol found in backticks or generic mentions

## Output Format

The `analyze_cve()` method returns a dictionary with:

```python
{
    'cve_id': 'CVE-2021-44228',
    'description': 'Apache Log4j2 2.0-beta9 through 2.15.0...',
    'published_date': '2021-12-10T10:15:09.353',
    'references': ['https://github.com/apache/logging-log4j2/pull/608', ...],
    'symbols': [
        VulnerableSymbol(
            name='lookup',
            source='commit_diff: https://github.com/...',
            confidence='high',
            context='...',
            cve_id='CVE-2021-44228'
        ),
        ...
    ],
    'symbol_count': 15
}
```

## VulnerableSymbol Object

Each symbol has the following attributes:
- `name`: The function/symbol name
- `source`: Where it was found (description, commit_diff, github_issue, etc.)
- `confidence`: Rating (high, medium, low)
- `context`: Surrounding text/code
- `cve_id`: The CVE ID it belongs to

## Advanced Usage

## Limitations

- **Symbol Detection Accuracy**: Not all vulnerable symbols may be explicitly mentioned in CVE data
- **Rate Limiting**: Without an API key, limited to 5 requests per 30 seconds
- **GitHub Content**: Requires public GitHub repositories; cannot access private repos
- **Language Support**: Pattern matching works best for C/C++, Python, Java, JavaScript
- **False Positives**: May detect non-vulnerable functions mentioned in context

## License

MIT License - Feel free to use and modify as needed.

## Disclaimer

This tool is for security research and educational purposes. Always verify findings and use responsibly.
