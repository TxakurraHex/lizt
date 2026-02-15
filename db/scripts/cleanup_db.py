#!/usr/bin/env python3
import psycopg
import os
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def cleanup_db():
    """Initialize database by running migration scripts."""

    # Get connection params from environment variables
    conn_params = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "dbname": os.getenv("DB_NAME", "lizt"),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", ""),
    }

    try:
        with psycopg.connect(**conn_params) as conn:
            with conn.cursor() as cursor:
                cursor.execute("DROP TABLE symbols;")
                cursor.execute("DROP TABLE cves;")

            conn.commit()
    except psycopg.Error as e:
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    cleanup_db()
