#!/usr/bin/env python3

import psycopg
import os
from pathlib import Path
import logging
import sys

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def init_database():
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
                # Get migrations dir
                migrations_dir = Path(__file__).parent.parent / "migrations"
                logger.info(migrations_dir)
                # Get all sorted migration files
                migration_files = sorted(migrations_dir.glob("*.sql"))

                if not migration_files:
                    logger.error("No migration files found")
                    return

                # Run all migrations in order
                for migration_file in migration_files:
                    logger.info(f"Running migration: {migration_file.name}")

                    sql = migration_file.read_text()
                    cursor.execute(sql)

                # Commit all changes
                conn.commit()
                logger.info(f"Successfully ran {len(migration_files)} migration(s)")

    except psycopg.Error as e:
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


def cleanup_database():
    """Clear out all rows from symbol and cve tables."""

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
                cursor.execute("TRUNCATE TABLE symbols CASCADE;")
            conn.commit()
    except psycopg.Error as e:
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


def destroy_database():
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
    if len(sys.argv) != 2:
        logger.error("Usage: python3 dbadmin.py [init|cleanup|destroy]")

    command = sys.argv[1]
    if command == "init":
        init_database()
    elif command == "cleanup":
        cleanup_database()
    elif command == "destroy":
        destroy_database()
    else:
        logger.error(f"Invalid command: {command}")
        logger.error("Usage: python3 dbadmin.py [init|cleanup|destroy]")
