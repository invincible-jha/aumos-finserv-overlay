"""Regulatory change feed adapter — polls public regulator RSS/Atom feeds.

GAP-293: Regulatory Change Tracking.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Iterator

import httpx
from lxml import etree

from aumos_common.observability import get_logger

logger = get_logger(__name__)

REGULATOR_FEEDS: dict[str, str] = {
    "SEC": "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=AI&dateb=&owner=include&count=40&search_text=&output=atom",
    "FINRA": "https://www.finra.org/rules-guidance/notices/rss.xml",
    "OCC": "https://www.occ.gov/news-issuances/bulletins/index-bulletin.xml",
    "CFPB": "https://www.consumerfinance.gov/feed/",
    "FRB": "https://www.federalreserve.gov/feeds/releases.xml",
}

COMPLIANCE_DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "SOX": ["sarbanes", "sox", "internal control", "financial reporting", "material weakness"],
    "SR_11_7": ["model risk", "sr 11-7", "model validation", "supervisory guidance"],
    "PCI_DSS": ["payment card", "pci", "cardholder data", "data security standard"],
    "DORA": ["digital operational resilience", "dora", "ict risk", "third-party ict"],
    "SEC_AI": ["artificial intelligence", "machine learning", "predictive analytics", "robo-advisor"],
    "AML": ["anti-money laundering", "bsa", "suspicious activity", "currency transaction"],
}


class RegulatoryFeedAdapter:
    """Polls public regulator feeds and classifies new regulatory updates.

    Supports SEC EDGAR, FINRA, OCC, CFPB, and FRB RSS/Atom feeds.
    Hash-based deduplication prevents duplicate records on re-poll.
    """

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self._client = http_client

    async def fetch_updates(self, regulator: str, since: datetime) -> list[dict]:
        """Fetch regulatory updates from a regulator's feed since a given date.

        Args:
            regulator: Regulator key (SEC, FINRA, OCC, CFPB, FRB).
            since: Only return updates published after this datetime.

        Returns:
            List of normalized update dicts with title, url, published_at,
            content_hash, and affected_domains.

        Raises:
            ValueError: If regulator key is unknown.
        """
        feed_url = REGULATOR_FEEDS.get(regulator)
        if not feed_url:
            raise ValueError(f"Unknown regulator: {regulator}")
        response = await self._client.get(feed_url, timeout=30.0)
        response.raise_for_status()
        return list(self._parse_feed(response.text, since))

    def _parse_feed(self, xml_text: str, since: datetime) -> Iterator[dict]:
        """Parse RSS/Atom XML and yield normalized entries.

        Args:
            xml_text: Raw XML feed content.
            since: Filter entries published after this datetime.

        Yields:
            Normalized update dicts.
        """
        root = etree.fromstring(xml_text.encode())
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall(".//item") or root.findall(".//atom:entry", ns)

        for entry in entries:
            title = (entry.findtext("title") or entry.findtext("atom:title", namespaces=ns) or "").strip()
            url = (entry.findtext("link") or entry.findtext("atom:link", namespaces=ns) or "").strip()
            pub_str = entry.findtext("pubDate") or entry.findtext("atom:published", namespaces=ns) or ""

            try:
                pub_dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            except ValueError:
                continue

            if pub_dt <= since:
                continue

            content = f"{title} {url}".lower()
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            affected_domains = [
                domain
                for domain, keywords in COMPLIANCE_DOMAIN_KEYWORDS.items()
                if any(kw in content for kw in keywords)
            ]

            yield {
                "title": title,
                "url": url,
                "published_at": pub_dt,
                "content_hash": content_hash,
                "affected_domains": affected_domains,
            }
