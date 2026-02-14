# CVE Symbol Scraper

A comprehensive Python tool for extracting vulnerable function names and symbols from CVE (Common Vulnerabilities and Exposures) entries by analyzing NVD data, GitHub commits, and security advisories.

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
- **Rate Limiting**: Respects NVD API rate limits (with optional API key support)
- **Export Capabilities**: Save results to JSON for further analysis

## Installation

```bash
pip install -r requirements.txt
```

Or manually install:
```bash
pip install requests
```

## Quick Start

### Basic Usage

```python
from cve_symbol_scraper import CVESymbolScraper

# Initialize scraper
scraper = CVESymbolScraper()

# Analyze a CVE
results = scraper.analyze_cve('CVE-2021-44228')

# Display results
print(f"Found {results['symbol_count']} vulnerable symbols")
for symbol in results['symbols']:
    print(f"  {symbol.name} [{symbol.confidence}]")
```

### Command Line Usage

```bash
# Analyze a single CVE
python cve_symbol_scraper.py CVE-2021-44228

# Analyze multiple CVEs
python cve_symbol_scraper.py CVE-2021-44228 CVE-2021-3156 CVE-2021-4034

# Export results to JSON
python cve_symbol_scraper.py CVE-2021-44228 --output results.json

# Use with NVD API key for higher rate limits
python cve_symbol_scraper.py CVE-2021-44228 --api-key YOUR_API_KEY
```

## Getting an NVD API Key

While the tool works without an API key, getting one increases your rate limit from 5 to 50 requests per 30 seconds:

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Request an API key
3. Use it with `--api-key` flag or in code:

```python
scraper = CVESymbolScraper(nvd_api_key='your-api-key-here')
```

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

## Examples

### Example 1: Analyze Log4Shell (CVE-2021-44228)

```python
scraper = CVESymbolScraper()
results = scraper.analyze_cve('CVE-2021-44228')

# Filter high confidence symbols
high_conf = [s for s in results['symbols'] if s.confidence == 'high']
for symbol in high_conf:
    print(f"{symbol.name} - {symbol.source}")
```

### Example 2: Batch Analysis

```python
cves = ['CVE-2021-44228', 'CVE-2021-3156', 'CVE-2021-4034']
scraper = CVESymbolScraper()

for cve_id in cves:
    results = scraper.analyze_cve(cve_id)
    print(f"{cve_id}: {results['symbol_count']} symbols")
```

### Example 3: Export to JSON

```python
scraper = CVESymbolScraper()
results = scraper.analyze_cve('CVE-2021-44228')
scraper.export_results(results, 'log4shell_symbols.json')
```

### Example 4: Filter by Source

```python
results = scraper.analyze_cve('CVE-2021-44228')

# Symbols from commits
commit_symbols = [s for s in results['symbols'] if 'commit' in s.source]

# Symbols from descriptions
desc_symbols = [s for s in results['symbols'] if 'description' in s.source]
```

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

### Custom Symbol Pattern Matching

You can extend the scraper to detect additional patterns:

```python
# Add custom pattern to extract_symbols_from_description method
custom_pattern = r'your_regex_pattern'
for match in re.finditer(custom_pattern, description):
    # Process matches
    pass
```

### Analyzing Specific Programming Languages

The scraper includes patterns for C/C++, Python, Java, and JavaScript. To focus on specific languages:

```python
results = scraper.analyze_cve('CVE-2021-XXXXX')

# Filter to C/C++ symbols (from diffs)
c_symbols = [s for s in results['symbols'] 
             if 'commit_diff' in s.source and 
             ('void' in s.context or 'int' in s.context)]
```

## Limitations

- **Symbol Detection Accuracy**: Not all vulnerable symbols may be explicitly mentioned in CVE data
- **Rate Limiting**: Without an API key, limited to 5 requests per 30 seconds
- **GitHub Content**: Requires public GitHub repositories; cannot access private repos
- **Language Support**: Pattern matching works best for C/C++, Python, Java, JavaScript
- **False Positives**: May detect non-vulnerable functions mentioned in context

## Use Cases

1. **Security Research**: Identify specific vulnerable functions for deeper analysis
2. **Vulnerability Scanning**: Build custom scanners targeting specific vulnerable symbols
3. **Patch Verification**: Confirm which functions were patched in security updates
4. **Code Auditing**: Find usages of vulnerable functions in your codebase
5. **Threat Intelligence**: Track vulnerable symbols across multiple CVEs

## Best Practices

1. **Use API Key**: Get an NVD API key for faster analysis
2. **Cross-Reference**: Verify symbols by checking multiple sources
3. **Focus on High Confidence**: Prioritize high-confidence symbols for security work
4. **Check Context**: Review the context field to understand how/why a symbol is vulnerable
5. **Rate Limiting**: Be mindful of rate limits when analyzing many CVEs

## Testing Known CVEs

Try these well-documented CVEs for testing:

- `CVE-2021-44228` - Log4Shell (Apache Log4j2)
- `CVE-2021-3156` - Sudo heap overflow
- `CVE-2021-4034` - PwnKit (Polkit)
- `CVE-2022-0847` - Dirty Pipe (Linux kernel)
- `CVE-2014-0160` - Heartbleed (OpenSSL)

## Contributing

Feel free to extend this tool with:
- Additional programming language patterns
- More sophisticated symbol extraction
- Integration with other vulnerability databases
- Machine learning for improved symbol detection

## License

MIT License - Feel free to use and modify as needed.

## Disclaimer

This tool is for security research and educational purposes. Always verify findings and use responsibly.
