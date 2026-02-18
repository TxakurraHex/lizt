#!/usr/bin/env python3

from .sources import LinuxSource, DpkgSource
from .inventory import Inventory, InventoryItem


def main():
    inventory = Inventory([LinuxSource(release_file="/etc/os-release"), DpkgSource()])
    inventory.collect()
    inventory.print()


if __name__ == "__main__":
    main()
