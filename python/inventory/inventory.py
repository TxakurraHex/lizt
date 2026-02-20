#!/usr/bin/env python3
"""
Gathers information related to operating system, kernel, installed packages (apt, dpkg, npm...),
drivers, and hardware to build a comprehensive image of the contextual system in which it is run.
"""

import subprocess
import platform
import json
import re
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Protocol, runtime_checkable
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class InventoryItem:
    vendor: str
    product: str
    version: str
    part: str = "a"  # a = application, o = os, h = hardware
    source: str = ""
    cpe_guess: str = ""

    def to_cpe_string(self) -> str:
        v = self.vendor.lower().replace(" ", "_").replace("-", "_")
        p = self.product.lower().replace(" ", "_").replace("-", "_")
        ver = self.version.lower().replace(" ", "_")
        return f"cpe:2.3:{self.part}:{v}:{p}:{ver}:*:*:*:*:*:*:*"


# Allows verification that the object "implementing" Source matches the shape
@runtime_checkable
class Source(Protocol):
    name: str

    def collect(self) -> list[InventoryItem]:
        return []


class Inventory:
    """Collects and maintains a system inventory"""

    def __init__(self, sources: list[Source]):
        self.sources = sources
        self.items: list[InventoryItem] = []

    def collect(self) -> None:
        seen = set()
        for source in self.sources:
            logger.info(source)
            for item in source.collect():
                key = (item.product, item.version, item.source)
                if key not in seen:
                    seen.add(key)
                    self.items.append(item)

    def filter_by_source(self, name: str) -> list[InventoryItem]:
        return [i for i in self.items if i.source == name]

    def print(self) -> None:
        for item in self.items:
            logger.info(item.to_cpe_string())

        logger.info("=" * 80)
        logger.info(
            f"Detected {len(self.items)} items from {len(self.sources)} sources"
        )
        logger.info("=" * 80)

    def to_json(self) -> list[dict]:
        # TODO: Implement
        return []
