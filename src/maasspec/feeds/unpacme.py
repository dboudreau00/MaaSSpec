"""UnpacMe: unpack results and the public feed, metadata only.

Endpoints and field names are from the public UnpacMe API client
(github.com/kryptoslogic/unpacme-go): `GET /api/v1/public/feed`,
`GET /api/v1/public/results/{id}`, no key. A results document is one
submission with the parent and its unpacked layers; the feed is a list of
short entries. Nothing is uploaded and no layer is downloaded. Strings that
UnpacMe returns for a layer go through the same selector scan as a local
sample.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar
from urllib.parse import quote, urlsplit

from maasspec import net
from maasspec.feeds import base
from maasspec.feeds.base import FeedAdapter, FeedFormatError, FetchOptions
from maasspec.models import Artifact, DraftFinding, FamilySummary, Selector, SourceRef
from maasspec.modules.base import ModuleOutput
from maasspec.selectors import MAX_SELECTOR_FINDINGS, selector_findings

API_ROOT = "https://api.unpac.me/api/v1"
MAX_LAYERS = 64
MAX_URLS_PER_LAYER = 50
MAX_STRINGS_PER_LAYER = 2000
_LEVELS = {"high": 0.7, "medium": 0.55, "low": 0.4}
_UNPACK_ID = re.compile(r"[A-Za-z0-9_\-]{6,64}")


class UnpacMeFeed(FeedAdapter):
    feed = "unpacme"
    name = "feed.unpacme"
    hosts = frozenset({"api.unpac.me"})
    needs_key = False
    queries: ClassVar[dict[str, str]] = {
        "feed": "the public feed of recent unpack submissions",
        "results": "one submission's results by unpack id",
    }

    def records(self, data: bytes) -> Iterator[dict]:
        document = base.load_json(data)
        if isinstance(document, dict):
            results = document.get("results")
            if not isinstance(results, list):
                raise FeedFormatError("UnpacMe input has no results list.")
            if _is_submission(document):
                yield document
                return
            rows = results
        elif isinstance(document, list):
            rows = document
        else:
            raise FeedFormatError("UnpacMe input is not an object or a list.")
        for row in rows:
            if isinstance(row, dict) and base.hex_digest(row.get("sha256"), "sha256"):
                yield row

    def record_id(self, record: dict) -> str | None:
        return base.text(record.get("id"), 64)

    def sample_sha256(self, record: dict) -> str | None:
        return base.hex_digest(record.get("sha256"), "sha256")

    def run(self, record: dict) -> ModuleOutput:
        if self.sample_sha256(record) is None:
            return ModuleOutput(errors=[base.warning(self.name, "Record has no valid sha256.")])
        if _is_submission(record):
            return self._submission(record)
        return self._entry(record)

    def _entry(self, record: dict) -> ModuleOutput:
        out = ModuleOutput()
        sha256 = self.sample_sha256(record) or ""
        out.artifacts.append(
            Artifact(
                id="art_sample_ref",
                type="sample_reference",
                sha256=sha256,
                description="Sample named in the UnpacMe public feed. Not fetched.",
                produced_by=f"{self.name}@{self.version}",
            )
        )
        source = SourceRef(artifact_id="art_sample_ref", method="feed")
        tags = ["feed", "feed:unpacme", "claimed"]
        if record.get("downloader") is True:
            tags.append("capability:downloader")
        if record.get("autoit") is True:
            tags.append("autoit")
        context = {}
        for key in ("status", "created"):
            cleaned = base.text(record.get(key), 64)
            if cleaned:
                context[key] = cleaned
        if isinstance(record.get("children"), int) and not isinstance(record.get("children"), bool):
            context["children"] = record["children"]
        out.findings.append(
            DraftFinding(
                type="embedded_artifact",
                subtype="sample_hash",
                value=sha256,
                normalized=sha256,
                confidence=0.8,
                confidence_method="feed_record",
                technique="unpacme_feed",
                source=source,
                context=context,
                selectors=[Selector(kind="sha256", value=sha256, normalized=sha256)],
                proposed_grade=base.claim_grade("Listed by UnpacMe. MaaSSpec has not seen the sample."),
                tags=tags,
            )
        )
        for match in _dicts(record.get("malwareid"))[:20]:
            name = base.text(match.get("match"), 128)
            if name:
                self._family(out, name, 0.5, {"type": base.text(match.get("type"), 64)}, source, tags)
        return out

    def _submission(self, record: dict) -> ModuleOutput:
        out = ModuleOutput()
        parent_sha = self.sample_sha256(record) or ""
        layers = _dicts(record.get("results"))
        if len(layers) > MAX_LAYERS:
            out.errors.append(
                base.warning(self.name, f"Listed the first {MAX_LAYERS} of {len(layers)} results.")
            )
            layers = layers[:MAX_LAYERS]
        digests = [base.hex_digest(_dict(layer.get("hashes")).get("sha256"), "sha256") for layer in layers]
        parent_art = next((f"art_unpack_{i}" for i, d in enumerate(digests) if d == parent_sha), None)
        status = base.text(record.get("status"), 32)
        if status and status.lower() != "complete":
            out.errors.append(base.info(self.name, f"Submission status is {status!r}, not complete."))
        seen: set[tuple[str, str]] = set()
        string_budget = MAX_SELECTOR_FINDINGS
        skipped_detectors = False
        for index, layer in enumerate(layers):
            sha256 = digests[index]
            if sha256 is None:
                out.errors.append(base.warning(self.name, f"Result {index} has no valid sha256."))
                continue
            hashes = _dict(layer.get("hashes"))
            is_parent = sha256 == parent_sha
            artifact_id = f"art_unpack_{index}"
            out.artifacts.append(
                Artifact(
                    id=artifact_id,
                    type="submitted_sample" if is_parent else "unpacked_layer",
                    sha256=sha256,
                    description="As reported by UnpacMe. Not fetched.",
                    produced_by=f"{self.name}@{self.version}",
                    parent_artifact_id=None if is_parent else parent_art,
                )
            )
            source = SourceRef(artifact_id=artifact_id, method="feed")
            tags = ["feed", "feed:unpacme", "claimed", "unpacked"]
            out.findings.append(
                DraftFinding(
                    type="embedded_artifact",
                    subtype="submitted_sample" if is_parent else "unpacked_payload",
                    value=sha256,
                    normalized=sha256,
                    confidence=0.8,
                    confidence_method="feed_record",
                    technique="unpacme_results",
                    source=source,
                    selectors=base.hash_selectors(
                        {
                            "sha256": sha256,
                            "sha1": base.hex_digest(hashes.get("sha1"), "sha1"),
                            "md5": base.hex_digest(hashes.get("md5"), "md5"),
                        }
                    ),
                    proposed_grade=base.claim_grade("Reported by UnpacMe. MaaSSpec has not seen the layer."),
                    tags=tags,
                )
            )
            for found in _dicts(layer.get("malware_id"))[:20]:
                name = base.text(found.get("name"), 128)
                if name:
                    reported = base.text(found.get("confidence"), 32)
                    self._family(
                        out,
                        name,
                        _LEVELS.get((reported or "").lower(), 0.45),
                        {
                            "source": base.text(found.get("source"), 128),
                            "reference": base.text(found.get("reference"), 512),
                            "reported_confidence": reported,
                        },
                        source,
                        tags,
                    )
            urls = layer.get("urls")
            for url in (urls if isinstance(urls, list) else [])[:MAX_URLS_PER_LAYER]:
                cleaned = base.text(url, 2048)
                if cleaned and ("url", cleaned.lower()) not in seen:
                    seen.add(("url", cleaned.lower()))
                    out.findings.append(_url_finding(cleaned, source, tags))
            strings = _strings(layer.get("strings"))
            if strings and string_budget > 0:
                drafts, _ = selector_findings(strings)
                for draft in drafts:
                    key = (draft.subtype or "", str(draft.value).lower())
                    if key in seen or string_budget <= 0:
                        continue
                    seen.add(key)
                    string_budget -= 1
                    draft.source = source
                    draft.confidence = min(draft.confidence, 0.6)
                    draft.tags = [*draft.tags, *tags]
                    out.findings.append(draft)
            skipped_detectors = skipped_detectors or bool(layer.get("deepmatch") or layer.get("detectit"))
        if skipped_detectors:
            out.errors.append(
                base.info(self.name, "deepmatch and detectit entries are present and not normalized in 0.1.")
            )
        return out

    def _family(
        self,
        out: ModuleOutput,
        name: str,
        confidence: float,
        data: dict,
        source: SourceRef,
        tags: list[str],
    ) -> None:
        if out.family is None or confidence > out.family.confidence:
            out.family = FamilySummary(name=name, confidence=confidence, method="unpacme_malware_id")
        out.findings.append(
            DraftFinding(
                type="family_indicator",
                subtype="malware_id",
                value=name,
                confidence=confidence,
                confidence_method="feed_claim",
                technique="unpacme_malware_id",
                source=source,
                family_data={key: value for key, value in data.items() if value},
                proposed_grade=base.claim_grade("Detection reported by UnpacMe. Not confirmed by MaaSSpec."),
                tags=tags,
            )
        )

    def fetch(
        self,
        query: str,
        term: str | None,
        options: FetchOptions,
        key: str | None = None,
        opener: net.Opener | None = None,
    ) -> bytes:
        if query == "feed":
            url = f"{API_ROOT}/public/feed"
        elif query == "results":
            if not term or not _UNPACK_ID.fullmatch(term):
                raise ValueError("An unpack id of 6 to 64 letters, digits, dash, underscore is required.")
            url = f"{API_ROOT}/public/results/{quote(term, safe='')}"
        else:
            raise ValueError(f"Unknown UnpacMe query {query!r}.")
        return net.request(
            url,
            allow_hosts=self.hosts,
            headers={"Accept": "application/json"},
            max_bytes=base.MAX_IMPORT_BYTES,
            opener=opener,
        )


def _is_submission(document: dict) -> bool:
    return (
        isinstance(document.get("results"), list)
        and "sha256" in document
        and "id" in document
        and "time" in document
    )


def _url_finding(url: str, source: SourceRef, tags: list[str]) -> DraftFinding:
    host = (urlsplit(url).hostname or "").lower()
    selectors = [Selector(kind="url", value=url, normalized=host or url.lower())]
    if host:
        selectors.append(Selector(kind="domain", value=host, normalized=host))
    return DraftFinding(
        type="c2",
        subtype="url",
        value=url,
        normalized=host or url.lower(),
        confidence=0.5,
        confidence_method="feed_claim",
        technique="unpacme_urls",
        source=source,
        selectors=selectors,
        proposed_grade=base.claim_grade("URL listed by UnpacMe for an unpacked layer."),
        tags=tags,
    )


def _strings(value: object) -> list[str]:
    block = _dict(value)
    collected: list[str] = []
    for key in ("ascii", "wide", "stack"):
        items = block.get(key)
        if isinstance(items, list):
            collected.extend(item for item in items if isinstance(item, str))
        if len(collected) >= MAX_STRINGS_PER_LAYER:
            break
    return collected[:MAX_STRINGS_PER_LAYER]


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
