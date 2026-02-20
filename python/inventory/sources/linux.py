#!/usr/bin/env python3
"""
Source object to collect and standardize information on a Linux OS
"""
import platform
import logging

# import subprocess

from ..inventory import InventoryItem
from .runner import run

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# def run(cmd: str, shell=True) -> str:
#     try:
#         result = subprocess.run(
#             cmd, shell=shell, capture_output=True, text=True, timeout=10
#         )
#         return result.stdout.strip()
#     except Exception as e:
#         logger.error(f"Failed to run {cmd}: {e}")
#         return ""


class LinuxSource:
    name = "Linux"
    items = []

    def __init__(self, release_file: str = "/etc/os-release"):
        self.release_file = release_file

    def collect(self) -> list[InventoryItem]:
        self.collect_release_info()
        self.collect_kernel_module_info()
        return self.items

    def collect_release_info(self) -> None:
        # Get basics
        system = platform.system()
        release = platform.release()
        version = platform.version()

        os_release = {}
        try:
            with open(self.release_file) as file:
                # Dict-ify the release file
                for line in file:
                    line = line.strip()
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os_release[key] = value.strip('"')
        except FileNotFoundError as e:
            logger.error(f"Unable to find {self.release_file} in the system")
            return

        distro_id = os_release.get("ID", "linux")
        distro_version = os_release.get("VERSION_ID", release)
        distro_name = os_release.get("NAME", "Linux")

        self.items.append(
            InventoryItem(
                vendor=distro_id,
                product=distro_id + "_linux",
                version=distro_version,
                part="o",
                source=self.release_file,
            )
        )

        # Kernel info
        self.items.append(
            InventoryItem(
                vendor="linux",
                product="linux_kernel",
                version=release.split("-")[0],
                part="o",
                source="uname",
            )
        )

    def collect_kernel_module_info(self) -> None:
        lsmod = run("lsmod")
        if not lsmod:
            return

        lines = lsmod.split("\n")[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if parts:
                mod_name = parts[0]
                self.items.append(
                    InventoryItem(
                        vendor="linux",
                        product=mod_name,
                        version="kernel_module",
                        part="a",
                        source="lsmod",
                    )
                )
