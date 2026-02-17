#!/usr/bin/env python3
import pathlib
import logging
import argparse
import json

from cve_symbol_scraper import CVESymbolScraper
from db_utils import insert_cve_symbols

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Ingest JSON data from CVE directory")
    parser.add_argument(
        "data_directory", help="Path to top-level directory holding the data to parse"
    )
    parser.add_argument("--schema", help="Schema of JSON to parse (e.g., NIST, KEV)")
    parser.add_argument(
        "--limit", type=int, help="Number of CVEs to parse (useful for debugging)"
    )
    parser.add_argument("--output", help="Output directory to place result files")

    args = parser.parse_args()

    parsed_cnt = 0
    cve_files = pathlib.Path(args.data_directory).glob("**/CVE*.json")
    scraper = CVESymbolScraper()
    all_results = []
    symbols_found = 0

    for cve_file in sorted(cve_files):
        if args.limit and parsed_cnt >= args.limit:
            logger.info("Limit reached, exiting")
            return

        logger.info(cve_file)
        with cve_file.open("r", encoding="utf-8") as file:
            try:
                cve_data = json.load(file)
                # logger.info(cve_data["descriptions"])
                results = scraper.analyze_cve_data(cve_data)
                all_results.append(results)

                # Print results
                logger.debug(f"\n{'='*80}")
                logger.info(f"CVE: {results['cve_id']}")
                logger.debug(f"Symbols found: {results['symbol_count']}")
                logger.debug(f"{'='*80}\n")

                for symbol in results["symbols"]:
                    logger.info(f"Symbol: {symbol.name}")
                    logger.debug(f"  Source: {symbol.source}")
                    logger.debug(f"  Confidence: {symbol.confidence}")
                    logger.debug(f"  Context: {symbol.context[:100]}...")
                    logger.info("")

                if args.output and results["symbol_count"] != 0:
                    output_file = f"{args.output}/{cve_data['id']}.json"
                    scraper.export_results(results, output_file)
                symbols_found += results["symbol_count"]
                insert_cve_symbols(results)
            except KeyError as e:
                logger.warning(f"Missing key in JSON file: {e}")

        parsed_cnt += 1

    logger.info(f"Total symbols found: {symbols_found}")


if __name__ == "__main__":
    main()
