#!/usr/bin/env python3
import psycopg
import os
import logging
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def insert_cve_symbols(scraper_result_dict: Dict) -> None:
    # Get connection params from environment variables
    conn_params = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "dbname": os.getenv("DB_NAME", "lizt"),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
    }

    with psycopg.connect(**conn_params) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO cves (cve_id) VALUES (%s) ON CONFLICT (cve_id) DO NOTHING",
                (scraper_result_dict["cve_id"],),
            )

            symbol_rows = []
            for symbol in scraper_result_dict["symbols"]:
                symbol_rows.append(
                    (
                        symbol.cve_id,
                        symbol.name,
                        symbol.source,
                        symbol.confidence,
                        symbol.context[:100],
                    )
                )
            cursor.executemany(
                """INSERT INTO symbols
                (cve_id, symbol_name, source, confidence, context)
                VALUES (%s, %s, %s, %s, %s)""",
                symbol_rows,
            )

        conn.commit()
