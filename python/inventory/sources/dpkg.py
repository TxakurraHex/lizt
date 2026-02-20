#!/usr/bin/env python3
"""
Source object to collect and standardize information collected from dpkg-installed packages
"""
import logging
import re

from ..inventory import InventoryItem
from .runner import run

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DpkgSource:
    name = "dpkg"
    items = []

    def collect(self) -> list[InventoryItem]:
        dpkg_results = run(
            "dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n' 2>/dev/null"
        )
        if not dpkg_results:
            return self.items

        for line in dpkg_results.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                pkg = parts[0].strip()
                ver = parts[1].strip()

                # Remove epoch and distro suffix
                ver = re.sub(r"\d+:", "", ver)
                ver = re.split(r"[~+-]", ver)[0]
                self.items.append(
                    InventoryItem(
                        vendor="",  # Inferred or left blank
                        product=pkg,
                        version=ver,
                        part="a",
                        source="dpkg",
                    )
                )
        return self.items
