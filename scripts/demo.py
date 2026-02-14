#!/usr/bin/env python3
"""
Demo script showing CVE Symbol Scraper functionality with example data
Works without network access by using cached CVE information
"""

from cve_symbol_scraper import CVESymbolScraper, VulnerableSymbol
from dataclasses import asdict
import json

# Example CVE data (simulating what would come from NVD API)
EXAMPLE_CVE_DATA = {
    'CVE-2021-44228': {
        'descriptions': [{
            'lang': 'en',
            'value': 'Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, '
                    'and parameters do not protect against attacker controlled LDAP and other JNDI '
                    'related endpoints. An attacker who can control log messages or log message '
                    'parameters can execute arbitrary code loaded from LDAP servers when message '
                    'lookup substitution is enabled. The vulnerable lookup() method in JndiLookup '
                    'class allows for remote code execution through ${jndi:ldap://...} patterns.'
        }],
        'published': '2021-12-10T10:00:00.000',
        'references': [
            {'url': 'https://github.com/apache/logging-log4j2/pull/608/commits'},
            {'url': 'https://github.com/apache/logging-log4j2/commit/7fe72d6'},
            {'url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'}
        ]
    },
    'CVE-2021-3156': {
        'descriptions': [{
            'lang': 'en',
            'value': 'Sudo before 1.9.5p2 contains a heap-based buffer overflow in the '
                    'set_cmnd() function, which can be exploited to execute arbitrary code. '
                    'The vulnerability is triggered when sudo is executed with the -s or -i '
                    'option and a single backslash character. The vulnerable set_cmnd() and '
                    'parse_args() functions process user input without proper bounds checking.'
        }],
        'published': '2021-01-26T18:15:12.000',
        'references': [
            {'url': 'https://github.com/sudo-project/sudo/commit/f752ae5'},
            {'url': 'https://www.sudo.ws/security/advisories/unescape_overflow/'}
        ]
    }
}

# Example git diff (simulating what would come from GitHub)
EXAMPLE_DIFF = """
diff --git a/plugins/sudoers/sudoers.c b/plugins/sudoers/sudoers.c
index 12345..67890 100644
--- a/plugins/sudoers/sudoers.c
+++ b/plugins/sudoers/sudoers.c
@@ -123,10 +123,15 @@
-static bool set_cmnd(struct sudoers_context *ctx)
+static bool set_cmnd_safe(struct sudoers_context *ctx)
 {
     char *user_args;
     size_t size;
+    
+    /* Add bounds checking to prevent overflow */
+    if (ctx->user.cmnd_args && strlen(ctx->user.cmnd_args) > MAX_CMND_SIZE) {
+        return false;
+    }
     
     size = strlen(user_cmnd) + 1;
     if (user_args)
@@ -145,7 +150,7 @@
 
-int parse_args(int argc, char **argv)
+int parse_args_safe(int argc, char **argv)
 {
     int ch;
     char *cp;
"""


def demo_symbol_extraction():
    """Demonstrate symbol extraction from various sources"""
    print("=" * 80)
    print("CVE Symbol Scraper - Demo Mode")
    print("=" * 80)
    
    scraper = CVESymbolScraper()
    
    # Demo 1: Extract from CVE description
    print("\n--- Demo 1: Extracting symbols from CVE description ---\n")
    cve_data = EXAMPLE_CVE_DATA['CVE-2021-44228']
    description = cve_data['descriptions'][0]['value']
    
    symbols = scraper.extract_symbols_from_description(description, 'CVE-2021-44228')
    print(f"Found {len(symbols)} symbols in description:")
    for symbol in symbols[:10]:  # Show first 10
        print(f"  • {symbol.name:<20} [{symbol.confidence:>6}] - {symbol.context[:60]}...")
    
    # Demo 2: Extract from git diff
    print("\n--- Demo 2: Extracting symbols from git diff ---\n")
    diff_symbols = scraper.extract_symbols_from_diff(EXAMPLE_DIFF, 'CVE-2021-3156', 
                                                      'https://github.com/example/commit/abc123')
    print(f"Found {len(diff_symbols)} symbols in diff:")
    for symbol in diff_symbols:
        print(f"  • {symbol.name:<25} [{symbol.confidence:>6}]")
        print(f"    Context: {symbol.context[:80]}...")
        print()
    
    # Demo 3: Full analysis simulation
    print("\n--- Demo 3: Complete CVE Analysis (simulated) ---\n")
    
    for cve_id, cve_data in EXAMPLE_CVE_DATA.items():
        print(f"\n{cve_id}:")
        print(f"  Published: {cve_data['published']}")
        print(f"  References: {len(cve_data['references'])}")
        
        # Extract from description
        description = cve_data['descriptions'][0]['value']
        symbols = scraper.extract_symbols_from_description(description, cve_id)
        
        # Deduplicate
        unique_symbols = {}
        for symbol in symbols:
            key = symbol.name.lower()
            if key not in unique_symbols:
                unique_symbols[key] = symbol
        
        symbols = list(unique_symbols.values())
        symbols.sort(key=lambda x: scraper._confidence_score(x.confidence), reverse=True)
        
        print(f"  Symbols found: {len(symbols)}")
        
        # Show by confidence level
        high = [s for s in symbols if s.confidence == 'high']
        medium = [s for s in symbols if s.confidence == 'medium']
        low = [s for s in symbols if s.confidence == 'low']
        
        print(f"    High confidence: {len(high)}")
        for s in high[:3]:
            print(f"      - {s.name}")
        
        print(f"    Medium confidence: {len(medium)}")
        for s in medium[:3]:
            print(f"      - {s.name}")
    
    # Demo 4: Pattern matching examples
    print("\n--- Demo 4: Pattern Matching Examples ---\n")
    
    test_texts = [
        "The vulnerable lookup() method allows RCE",
        "Call to `exec_command` with user input",
        "The set_cmnd() function processes without bounds checking",
        "Use safe_strcpy instead of strcpy for buffer handling"
    ]
    
    print("Testing pattern matching on various text patterns:\n")
    for text in test_texts:
        symbols = scraper.extract_symbols_from_description(text, 'TEST-CVE')
        print(f"Text: {text}")
        print(f"Found: {[s.name for s in symbols]}")
        print()


def demo_export_format():
    """Show the JSON export format"""
    print("\n" + "=" * 80)
    print("Demo: JSON Export Format")
    print("=" * 80 + "\n")
    
    scraper = CVESymbolScraper()
    
    # Create sample result
    symbols = [
        VulnerableSymbol(
            name='lookup',
            source='description',
            confidence='high',
            context='The vulnerable lookup() method in JndiLookup class',
            cve_id='CVE-2021-44228'
        ),
        VulnerableSymbol(
            name='set_cmnd',
            source='commit_diff',
            confidence='high',
            context='static bool set_cmnd(struct sudoers_context *ctx)',
            cve_id='CVE-2021-3156'
        )
    ]
    
    result = {
        'cve_id': 'CVE-2021-44228',
        'description': 'Apache Log4j2 vulnerability...',
        'published_date': '2021-12-10T10:00:00.000',
        'references': ['https://github.com/...'],
        'symbols': [asdict(s) for s in symbols],
        'symbol_count': len(symbols)
    }
    
    print(json.dumps(result, indent=2))


def demo_confidence_levels():
    """Explain confidence levels"""
    print("\n" + "=" * 80)
    print("Understanding Confidence Levels")
    print("=" * 80 + "\n")
    
    print("HIGH CONFIDENCE:")
    print("  • Found in git diff (function definition)")
    print("  • Explicitly mentioned with vulnerability keywords")
    print("  • Example: 'The vulnerable lookup() function allows RCE'")
    print()
    
    print("MEDIUM CONFIDENCE:")
    print("  • Found in function calls within diffs")
    print("  • Mentioned in CVE description without explicit vulnerability context")
    print("  • Example: 'The set_cmnd() function processes input'")
    print()
    
    print("LOW CONFIDENCE:")
    print("  • Found in backticks (markdown formatting)")
    print("  • Generic mentions without clear vulnerability context")
    print("  • Example: 'Use `safe_strcpy` instead'")


def demo_use_cases():
    """Show practical use cases"""
    print("\n" + "=" * 80)
    print("Practical Use Cases")
    print("=" * 80 + "\n")
    
    print("1. SECURITY SCANNING")
    print("   Search your codebase for vulnerable symbols:")
    print("   $ grep -r 'lookup(' src/")
    print()
    
    print("2. PATCH VERIFICATION")
    print("   Verify which functions were patched:")
    print("   Compare symbols from CVE with git history")
    print()
    
    print("3. VULNERABILITY RESEARCH")
    print("   Build database of vulnerable patterns:")
    print("   Track common vulnerable function patterns across CVEs")
    print()
    
    print("4. DEPENDENCY ANALYSIS")
    print("   Check if your dependencies use vulnerable symbols:")
    print("   Cross-reference with your dependency tree")
    print()
    
    print("5. THREAT INTELLIGENCE")
    print("   Monitor for new CVEs affecting functions you use:")
    print("   Set up alerts for symbols in your critical code")


def main():
    """Run all demos"""
    demo_symbol_extraction()
    demo_export_format()
    demo_confidence_levels()
    demo_use_cases()
    
    print("\n" + "=" * 80)
    print("Demo Complete!")
    print("=" * 80)
    print("\nTo use with real CVE data, ensure network access and run:")
    print("  python cve_symbol_scraper.py CVE-2021-44228")
    print("\nFor API key instructions, visit:")
    print("  https://nvd.nist.gov/developers/request-an-api-key")


if __name__ == '__main__':
    main()
