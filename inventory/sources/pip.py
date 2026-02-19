#!/usr/bin/env python3

import json
import logging
import sys

from ..inventory import InventoryItem
from .runner import run

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PipSource:
    name = "Pip"
    items = []

    def collect(self) -> list[InventoryItem]:
        out = run(f"{sys.executable} -m pip list --format=json 2>/dev/null")
        if not out:
            return self.items

        try:
            pkgs = json.loads(out)
            for pkg in pkgs:
                self.items.append(
                    InventoryItem(
                        vendor="",  # Inferred or left blank
                        product=pkg["name"].lower().replace("-", "_"),
                        version=pkg["version"],
                        part="a",
                        source="pip",
                    )
                )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode `pip list` results: {e}")
            return []

        return self.items
