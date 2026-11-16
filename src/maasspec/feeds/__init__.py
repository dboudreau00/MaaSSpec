"""Registry of public-feed adapters. Add a feed by adding a class here."""

from __future__ import annotations

from maasspec.feeds.base import FeedAdapter
from maasspec.feeds.malwarebazaar import MalwareBazaarFeed
from maasspec.feeds.threatfox import ThreatFoxFeed
from maasspec.feeds.unpacme import UnpacMeFeed

ADAPTERS: dict[str, FeedAdapter] = {
    adapter.feed: adapter for adapter in (MalwareBazaarFeed(), ThreatFoxFeed(), UnpacMeFeed())
}


def get_adapter(name: str) -> FeedAdapter:
    try:
        return ADAPTERS[name]
    except KeyError:
        raise ValueError(f"Unknown feed {name!r}. Known: {', '.join(sorted(ADAPTERS))}.") from None
