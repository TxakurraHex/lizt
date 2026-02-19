#!/usr/bin/env python3

import subprocess


def run(cmd: str, shell=True) -> str:
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"Failed to run {cmd}: {e}")
        return ""
