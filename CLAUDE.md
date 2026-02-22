# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LIZT is a security tool for vulnerability detection. It collects a system software inventory (OS, packages, Python libraries), maps software to CPE (Common Platform Enumeration) entries, queries the NVD API for CVEs, extracts vulnerable symbols from CVE data, and (planned) uses eBPF to monitor runtime behavior against known vulnerable symbols.

The project is being rewritten from Python (in `pipeline/`, `inventory/`, `symbol_scraping/`) to Rust (in `crates/`). The `rust` branch is active development.

## Build Commands

```bash
cargo build                    # Build all crates
cargo build --release          # Release build
cargo run -p lizt-cli          # Run the CLI
cargo test                     # Run all tests
cargo test -p lizt_core        # Run tests for a specific crate
cargo check                    # Check compilation without building
cargo fmt                      # Format code
cargo clippy                   # Lint
```

## Rust Crates Architecture

All crates use Rust edition 2024 with resolver = "2".

- **lizt-core**: Shared domain models (`Cve`, `CpeEntry`, `Symbol`, `Severity`, etc.). All other crates should depend on this for common types.
- **lizt-cpe**: CPE inventory collection. Contains `Source` trait for inventory sources (dpkg, pip, linux OS info) and `Inventory` struct that aggregates sources.
- **lizt-cli**: Binary entry point. Currently a stub.
- **lizt-ebpf**: eBPF runtime scanning. Stub.
- **lizt-symbols**: Symbol extraction from CVE sources (git diffs, GitHub issues). Stub.

## Key Patterns

- **Source trait** (`lizt-cpe/src/inventory.rs`): Inventory sources implement `Source` with `name() -> &str` and `collect() -> Vec<SystemCpe>` methods.
- **Runner utility** (`lizt-cpe/src/runner.rs`): `run(cmd)` executes shell commands and returns stdout, used by dpkg/pip sources.
- **Tests are inline**: Use `#[cfg(test)]` modules colocated with source files.

## Database

PostgreSQL schema in `db/migrations/001_initial_schema.sql` with tables `cves` and `symbols`. The `sqlx` dependency is declared but DB layer (`lizt-core/src/db/`) is not yet implemented.

## Python Reference Implementation

The `pipeline/` directory contains working Python code that the Rust rewrite aims to replicate:

```bash
cd pipeline
python pipeline.py                     # Basic scan
python pipeline.py --min-score 7.0     # High severity only
python pipeline.py --dry-run           # Show inventory without CVE lookup
python pipeline.py --sources pip       # Only pip packages
```

Set `NVD_API_KEY` environment variable for faster API access.
