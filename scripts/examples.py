#!/usr/bin/env python3
"""
Example usage of CVE Symbol Scraper
Demonstrates different ways to analyze CVEs and extract vulnerable symbols
"""

from cve_symbol_scraper import CVESymbolScraper, VulnerableSymbol

def example_1_basic_usage():
    """Basic usage: Analyze a single CVE"""
    print("=" * 80)
    print("Example 1: Basic CVE Analysis")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    
    # Analyze Log4Shell (CVE-2021-44228)
    results = scraper.analyze_cve('CVE-2021-44228')
    
    print(f"\nCVE: {results['cve_id']}")
    print(f"Published: {results.get('published_date', 'N/A')}")
    print(f"Found {results['symbol_count']} unique symbols\n")
    
    # Display high confidence symbols only
    high_conf_symbols = [s for s in results['symbols'] if s.confidence == 'high']
    print(f"High confidence symbols ({len(high_conf_symbols)}):")
    for symbol in high_conf_symbols:
        print(f"  - {symbol.name} (from {symbol.source})")


def example_2_multiple_cves():
    """Analyze multiple CVEs and compare"""
    print("\n" + "=" * 80)
    print("Example 2: Multiple CVE Analysis")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    
    # Analyze multiple CVEs
    cve_ids = ['CVE-2021-3156', 'CVE-2021-4034', 'CVE-2022-0847']
    
    for cve_id in cve_ids:
        results = scraper.analyze_cve(cve_id)
        print(f"\n{cve_id}: {results['symbol_count']} symbols")
        
        # Show top 3 symbols by confidence
        top_symbols = sorted(results['symbols'], 
                           key=lambda x: scraper._confidence_score(x.confidence),
                           reverse=True)[:3]
        for symbol in top_symbols:
            print(f"  - {symbol.name} [{symbol.confidence}]")


def example_3_filter_by_source():
    """Filter symbols by their source"""
    print("\n" + "=" * 80)
    print("Example 3: Filter Symbols by Source")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    results = scraper.analyze_cve('CVE-2021-44228')
    
    # Group symbols by source type
    commit_symbols = [s for s in results['symbols'] if 'commit' in s.source]
    description_symbols = [s for s in results['symbols'] if 'description' in s.source]
    
    print(f"\nSymbols from commits: {len(commit_symbols)}")
    for symbol in commit_symbols[:5]:
        print(f"  - {symbol.name}")
    
    print(f"\nSymbols from descriptions: {len(description_symbols)}")
    for symbol in description_symbols[:5]:
        print(f"  - {symbol.name}")


def example_4_export_results():
    """Export results to JSON"""
    print("\n" + "=" * 80)
    print("Example 4: Export Results to JSON")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    results = scraper.analyze_cve('CVE-2021-44228')
    
    # Export to JSON file
    scraper.export_results(results, 'cve_analysis_results.json')
    print("\nResults exported to cve_analysis_results.json")


def example_5_with_api_key():
    """Use with NVD API key for higher rate limits"""
    print("\n" + "=" * 80)
    print("Example 5: Using NVD API Key")
    print("=" * 80)
    
    # Get API key from https://nvd.nist.gov/developers/request-an-api-key
    api_key = None  # Replace with your actual API key
    
    if api_key:
        scraper = CVESymbolScraper(nvd_api_key=api_key)
        print("Scraper initialized with API key (50 requests/30 seconds)")
    else:
        scraper = CVESymbolScraper()
        print("Scraper initialized without API key (5 requests/30 seconds)")
    
    # Now you can make requests much faster with an API key
    results = scraper.analyze_cve('CVE-2021-44228')
    print(f"Found {results['symbol_count']} symbols")


def example_6_detailed_symbol_info():
    """Show detailed information about each symbol"""
    print("\n" + "=" * 80)
    print("Example 6: Detailed Symbol Information")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    results = scraper.analyze_cve('CVE-2021-3156')
    
    print(f"\nDetailed analysis of {results['cve_id']}:\n")
    
    for i, symbol in enumerate(results['symbols'][:5], 1):
        print(f"{i}. {symbol.name}")
        print(f"   Confidence: {symbol.confidence}")
        print(f"   Source: {symbol.source}")
        print(f"   Context: {symbol.context[:150]}...")
        print()


def example_7_search_specific_patterns():
    """Search for specific function patterns in results"""
    print("\n" + "=" * 80)
    print("Example 7: Search for Specific Patterns")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    results = scraper.analyze_cve('CVE-2021-44228')
    
    # Search for symbols matching a pattern
    pattern = 'lookup'  # Search for functions with 'lookup' in name
    matching_symbols = [s for s in results['symbols'] 
                       if pattern.lower() in s.name.lower()]
    
    print(f"\nSymbols matching '{pattern}':")
    for symbol in matching_symbols:
        print(f"  - {symbol.name} [{symbol.confidence}] from {symbol.source}")


def example_8_batch_analysis():
    """Batch analyze multiple CVEs and create a summary report"""
    print("\n" + "=" * 80)
    print("Example 8: Batch Analysis Report")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    
    # List of CVEs to analyze
    cve_list = [
        'CVE-2021-44228',  # Log4Shell
        'CVE-2021-3156',   # Sudo heap overflow
        'CVE-2021-4034',   # PwnKit
    ]
    
    print("\nBatch Analysis Summary")
    print("-" * 80)
    print(f"{'CVE ID':<20} {'Symbols':<10} {'High Conf':<12} {'Commits':<10}")
    print("-" * 80)
    
    for cve_id in cve_list:
        results = scraper.analyze_cve(cve_id)
        
        high_conf = len([s for s in results['symbols'] if s.confidence == 'high'])
        from_commits = len([s for s in results['symbols'] if 'commit' in s.source])
        
        print(f"{cve_id:<20} {results['symbol_count']:<10} {high_conf:<12} {from_commits:<10}")


if __name__ == '__main__':
    # Run all examples
    example_1_basic_usage()
    example_2_multiple_cves()
    example_3_filter_by_source()
    example_4_export_results()
    example_5_with_api_key()
    example_6_detailed_symbol_info()
    example_7_search_specific_patterns()
    example_8_batch_analysis()
    
    print("\n" + "=" * 80)
    print("All examples completed!")
    print("=" * 80)
