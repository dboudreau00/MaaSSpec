# MaaSSpec specification (0.1)

## Purpose

MaaSSpec ionizes one input and emits a spectrum of what is inside it:
C2 candidates, selectors, archive member names, sandbox observations, and
family indicators. Every row carries the module, the technique, a
confidence, and an optional Admiralty-style grade.

NocTORnal remains the case system. This tool does not keep cases, graphs,
or custody chains.

## Inputs

| type | how it is recognized | what runs |
|---|---|---|
| `sample` | default | static scan, then family modules |
| `archive` | ZIP magic | static scan, member names only, then family modules |
| `cape_report` | JSON object with `network`, `signatures`, `behavior`, or `CAPE` | CAPE normalizer only |
| `feed_record` | `maasspec feed import <feed>`, never sniffed from a file | the feed's adapter only |

`memory_dump` and `config_dump` are reserved on the model and are not
detected yet. A module that wants them should set `input.type` only when
the detector is real.

## Output

One `Spectrum` document. See `src/maasspec/models.py` and
`schema/spectrum.schema.json`.

Findings are a closed set of types: `c2`, `config`, `credential_pattern`,
`crypto_material`, `embedded_artifact`, `family_indicator`, `behavior`,
`wallet`, `panel`, `other`.

A module returns `DraftFinding`. The engine assigns `id`, `extracted_by`,
and `first_seen_in_analysis`. Ids are `fnd_0001` in module order so a
re-run of the same engine is diffable. `analysis_id` is a UUID.

`summary.family` is the highest-confidence `FamilySummary` any module
returned. It is a claim, not a verdict.

## Confidence

- Static magic of a known container: about 0.95.
- Static URL or email: about 0.7.
- Bitcoin address shape: about 0.66.
- Public IPv4: about 0.55. Private or loopback: about 0.35, grade `C/4`
  (the same `C/4` applies to a private ThreatFox IP:port, whatever level
  the feed states).
- CAPE network or signature: at most 0.45, grade `C/3`.
- CAPE parser output (`CAPE.configs`, decoded by CAPE's own configuration parsers): at most 0.6,
  grade `C/2`, tagged `sandbox`, `cape`, `cape_config`. A private or loopback address in a config is
  0.35, `C/4`. CAPE payload hashes are 0.5, `C/3`.
- Feed claims (MalwareBazaar, ThreatFox, UnpacMe): grade `C/3`, tagged
  `claimed`. A hash naming the sample 0.9 (MalwareBazaar) or 0.8 (UnpacMe),
  a family label 0.6 (MalwareBazaar) or 0.7 at most (ThreatFox), a YARA or
  delivery claim 0.5, a ThreatFox IOC `0.7 x confidence_level / 100`, or 0.35
  when no level is given. ThreatFox grade is `C/2` from level 75 up.
  An UnpacMe `malware_id` takes its reported level (high 0.7, medium 0.55,
  low 0.4, anything else 0.45); a public-feed `malwareid` is 0.5. Strings
  from an unpacked UnpacMe layer cap at 0.6.
- A fixture or structural family match states its own method. Do not copy
  the example module's 0.99 onto a real family unless the evidence is that
  specific.

Partial results are valid. Gaps go in `errors` with `info`, `warning`, or
`error`. An empty finding list with an error is a successful run.

## Safety

- No process is spawned for the sample.
- A module that raises is recorded as an `error` and the spectrum is still
  produced. The message carries the exception type only.
- All outbound HTTP is `maasspec.net`: HTTPS, a per-request host allowlist,
  no redirects, no credentials in the URL, a response size cap, and no
  header or query text in errors. Plain HTTP is allowed only to a loopback
  host, for a local NocTORnal.
- No bytes from the sample are written back out except hashes, names, and
  the short values already inside findings.
- ZIP: refuse more than 200 members or 64 MiB of declared uncompressed
  size. Never extract. Skip absolute paths and `..`.
- Scan window: 8 MiB, head and tail when the file is larger. The SHA-256
  still covers the whole file. `metadata.scan_window_truncated` says so. A JSON object is the
  exception: it is read whole, up to 128 MiB, so a CAPE report (usually larger than the window) is
  parsed. Larger JSON is analyzed as a raw file and a warning says so.

## NocTORnal

`POST /api/v1/ingest` accepts raw bytes. Format is sniffed. The body is
stored, then a person parses and attaches it. MaaSSpec therefore:

1. Writes the spectrum locally.
2. Optionally posts that JSON, unchanged, with
   `Authorization: Bearer noct_sk_<live or test>_<32 characters>` and `Idempotency-Key: <analysis_id>`.
3. Stops. It does not call parse, attach, or any graph route.

`ndjson` is a local review form (one header record, one record per
finding). It is not sent unless an operator posts it themselves.

`maasspec ingest` accepts one spectrum or a JSON Lines stream (one compact
spectrum per line, from a file or stdin) and posts each as its own request
with its own `Idempotency-Key`. It stops at the first rejection. Issue the
ingest key with the declared category `IOC_FEED` for feed spectra. NocTORnal
categorises by the key's declared category or by the structure of the body;
it has no MaaSSpec mapper, so a spectrum waits in the ingest queue until a
person triages it or a mapper is added on that side.

## CAPE reports

The CAPE normalizer reads `network` (hosts, http, https, dns), `signatures`, `malfamily`, and the
`CAPE` section CAPE's own parsers fill: `CAPE.configs` and `CAPE.payloads`. Custom extractors for
dumped payloads are CAPE parsers, written for and run by CAPE (`custom/parsers/` on the CAPE host,
enabled with `[CAPE_extractors]` in `processing.conf`). MaaSSpec does not run extractor code.

A `configs` entry is `{family: {fields}}`; field names are the parser's own, so they are read by
name pattern: fields named like a C2 (c2, cnc, server, host, domain, address, url, gate, panel, ip)
become `c2` findings when the value is a URL, host, or IP with optional port; fields named like a
key (key, password, secret, token, rc4, aes, xor, salt, iv) become `crypto_material`; campaign,
botnet and mutex fields become `config` findings with a selector; every other string goes through
the same selector scan as a local sample. The family key becomes the family claim. The payload
hashes in `_associated_config_hashes` and `CAPE.payloads` become `sandbox_payload` artifacts and hash
selectors. Parser field names that match none of these patterns stay in the `cape_parser_config`
finding's context (first 30 fields).

## Feeds

A feed adapter reads public malware-intelligence records and emits one
spectrum per record. It never fetches or uploads a sample.

| feed | accepted input | fetch (read-only, one request) |
|---|---|---|
| `malwarebazaar` | `get_*` API JSON; CSV export (header-driven) | `POST mb-api.abuse.ch/api/v1/`, `Auth-Key` header |
| `threatfox` | API JSON; JSON or CSV export (older field names accepted) | `POST threatfox-api.abuse.ch/api/v1/`, `Auth-Key` header |
| `unpacme` | `GET /public/results/{id}` JSON; `GET /public/feed` JSON | `GET api.unpac.me/api/v1/public/...`, no key |

What a record becomes:

- `input` is the record. `input.sha256` is the SHA-256 of its canonical JSON
  (sorted keys, compact), so it can be re-derived from the export.
- The sample the feed describes is an artifact of type `sample_reference` (or
  `submitted_sample` and `unpacked_layer` for UnpacMe) with the hash the feed
  gave. It was not fetched and is not verified.
- Selectors carry the hashes, hosts, URLs, and IP:port pairs. A ThreatFox
  IP:port yields an `ipv4` selector and an `ipv4_port` selector.
- UnpacMe layer strings go through the same selector scan as a local sample.
- `analysis_id` is a UUIDv5 over feed, adapter version, and record hash.
- `metadata` holds `feed`, `feed_record_id`, `claimed_sample_sha256`, and
  `claims_not_verified: true`.

Verified against the services' own documentation: the API request and response
shapes. Not verified: the CSV and JSON export layouts of MalwareBazaar and
ThreatFox, which are published only behind the abuse.ch login. Those readers
use the header row (CSV) or accept both the current and the older field names
(JSON), and have been run only on synthetic files. Check one real export
before relying on them. The UnpacMe field names come from the public Go
client's models; the shape of `deepmatch` and `detectit` entries is not
normalized in 0.1.

## Modules

`Module.accepts(ctx)` then `Module.run(ctx) -> ModuleOutput`.

`AnalysisContext` holds the path, the scan window, the hash, the size,
the input type, extracted strings, and parsed JSON when the input was a
CAPE report. Modules must treat all of that as hostile data.

## Non-goals

Case management. Interactive reversing. A sandbox. OSINT collection beyond
the three named feeds. Identity resolution. Shipping a real family decryptor
inside 0.1.0. Downloading samples from any feed, or uploading to one.
