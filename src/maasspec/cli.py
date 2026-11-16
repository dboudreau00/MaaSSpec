"""Command line. Analysis stays on disk or on a pipe until an operator posts it."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from maasspec import net
from maasspec.engine import analyze_path, spectra_from_feed
from maasspec.feeds import ADAPTERS, get_adapter
from maasspec.feeds.base import FeedFormatError, FetchOptions
from maasspec.ingest.noctornal import IngestClient, spectrum_ndjson
from maasspec.models import Spectrum, spectrum_json_schema
from maasspec.stream import parse_spectra, read_input, spectra_jsonl

KEY_ENV = "MAASSPEC_ABUSECH_KEY"
EXPECTED = (ValueError, OSError, net.HttpError, FeedFormatError)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except EXPECTED as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="maasspec", description="Malware spectrometer.")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Write a spectrum for one file.")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--out", type=Path, help="Defaults to stdout.")

    validate = sub.add_parser("validate", help="Check spectra against the models. Path or - for stdin.")
    validate.add_argument("path", nargs="?", default="-")

    sub.add_parser("schema", help="Print the JSON Schema.")

    review = sub.add_parser("ndjson", help="Turn a spectrum into a review NDJSON. Does not send it.")
    review.add_argument("path", type=Path)
    review.add_argument("--out", type=Path)

    post = sub.add_parser(
        "ingest",
        help="POST each spectrum as raw bytes. Path or - for stdin. "
        "Reads MAASSPEC_NOCTORNAL_URL and MAASSPEC_INGEST_KEY.",
    )
    post.add_argument("path", nargs="?", default="-")

    feed = sub.add_parser("feed", help="Public malware feeds: list, fetch, import.")
    feed_sub = feed.add_subparsers(dest="feed_command", required=True)
    feed_sub.add_parser("list", help="Show feeds and their queries.")

    fetch = feed_sub.add_parser(
        "fetch",
        help=f"One read-only API query. Writes the raw response. Abuse.ch feeds read {KEY_ENV}.",
    )
    fetch.add_argument("feed", choices=sorted(ADAPTERS))
    fetch.add_argument("query")
    fetch.add_argument("term", nargs="?")
    fetch.add_argument("--limit", type=int)
    fetch.add_argument("--days", type=int)
    fetch.add_argument("--selector")
    fetch.add_argument("--exact", action="store_true")
    fetch.add_argument("--out", type=Path, help="Defaults to stdout.")

    ingest = feed_sub.add_parser(
        "import",
        help="Turn a saved response or export into spectra, one per record, as JSON Lines.",
    )
    ingest.add_argument("feed", choices=sorted(ADAPTERS))
    ingest.add_argument("path", nargs="?", default="-", help="File, or - for stdin.")
    ingest.add_argument("--limit", type=int, default=1000)
    ingest.add_argument("--out", type=Path, help="Defaults to stdout.")
    return parser


def _analyze(args: argparse.Namespace) -> int:
    spectrum = analyze_path(args.path)
    _write(args.out, [spectrum.model_dump_json(indent=2).encode("utf-8") + b"\n"])
    return 0


def _validate(args: argparse.Namespace) -> int:
    count = sum(1 for _ in parse_spectra(read_input(args.path, sys.stdin.buffer)))
    print(f"valid ({count})")
    return 0


def _schema(_: argparse.Namespace) -> int:
    print(json.dumps(spectrum_json_schema(), indent=2))
    return 0


def _ndjson(args: argparse.Namespace) -> int:
    spectrum = Spectrum.model_validate_json(args.path.read_text(encoding="utf-8"))
    _write(args.out, [spectrum_ndjson(spectrum)])
    return 0


def _ingest(args: argparse.Namespace) -> int:
    url = os.environ.get("MAASSPEC_NOCTORNAL_URL", "")
    key = os.environ.get("MAASSPEC_INGEST_KEY", "")
    if not url or not key:
        print("Set MAASSPEC_NOCTORNAL_URL and MAASSPEC_INGEST_KEY.", file=sys.stderr)
        return 2
    client = IngestClient(url, key)
    for number, spectrum in enumerate(parse_spectra(read_input(args.path, sys.stdin.buffer)), 1):
        try:
            body = client.submit_spectrum(spectrum)
        except net.HttpError as exc:
            print(f"Spectrum {number} ({spectrum.analysis_id}) was not accepted: {exc}", file=sys.stderr)
            return 1
        sys.stdout.buffer.write(body.rstrip(b"\n") + b"\n")
    return 0


def _feed(args: argparse.Namespace) -> int:
    if args.feed_command == "list":
        for name in sorted(ADAPTERS):
            adapter = ADAPTERS[name]
            print(f"{name}  ({'key: ' + KEY_ENV if adapter.needs_key else 'no key'})")
            for query, help_text in adapter.queries.items():
                print(f"  {query:<10} {help_text}")
        return 0
    adapter = get_adapter(args.feed)
    if args.feed_command == "fetch":
        options = FetchOptions(
            limit=args.limit, days=args.days, selector=args.selector, exact=args.exact
        )
        key = os.environ.get(KEY_ENV) if adapter.needs_key else None
        try:
            body = adapter.fetch(args.query, args.term, options, key=key)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        _write(args.out, [body])
        return 0
    if not 1 <= args.limit <= 100_000:
        print("--limit must be between 1 and 100000.", file=sys.stderr)
        return 2
    data = read_input(args.path, sys.stdin.buffer)
    count = 0

    def counted():
        nonlocal count
        for spectrum in spectra_from_feed(adapter, data, limit=args.limit):
            count += 1
            yield spectrum

    _write(args.out, spectra_jsonl(counted()))
    print(f"{count} spectra written.", file=sys.stderr)
    return 0


def _write(path: Path | None, chunks) -> None:
    if path is None:
        for chunk in chunks:
            sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        return
    with path.open("wb") as handle:
        for chunk in chunks:
            handle.write(chunk)


_COMMANDS = {
    "analyze": _analyze,
    "validate": _validate,
    "schema": _schema,
    "ndjson": _ndjson,
    "ingest": _ingest,
    "feed": _feed,
}


if __name__ == "__main__":
    raise SystemExit(main())
