#!/usr/bin/env python3
"""
CPE parser - Collects, parses, and stores a CPE record associated with a vulnerability
"""

import requests
import re
import time
import json
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class CPERecord:
    """Represents a vulnerable function or symbol"""

    cpe_id: str
    cpe_version: str  # CPE version
    part: str  # a(pplication), h(ardware), or o(perating system)
    vendor: str
    product: str
    product_version: str
    update: str  # a.k.a. extraversion, can vary by vendor
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str


class CVESymbolScraper:
    """Scrapes CVE data and extracts vulnerable symbols"""

    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd_api_key = nvd_api_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CVE-Symbol-Scraper/1.0"})
        if nvd_api_key:
            logger.debug("Appending api key")
            self.session.headers.update({"apiKey": nvd_api_key})

        # Rate limiting
        self.request_delay = 0.6 if not nvd_api_key else 0.02
        self.last_request_time = 0
