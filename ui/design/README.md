# MaaSSpec UI design

Design source for the web UI, exported on 2026-11-16. The files are unchanged from the export except
the `name` in `package.json`. This folder is a design reference. It is not wired to MaaSSpec and has no
build config. The working app is `../app/`.

| Folder | What it is |
|---|---|
| `huhNFrUmLQLCwqkE3F5xvs.prototype/` | MaaSSpec prototype: plays the five frames, holds selection and theme state |
| `7A6AUWxkx7Bfm4sXQSj1iZ.frame/` | Spectra (list, filters, review marks) |
| `9squQUDscDCvFzh8Gkz6VH.frame/` | Spectrum Detail (findings table, artifact tree) |
| `qgootDymB1AjUEkNJzrG7R.frame/` | Selectors (pivot across spectra) |
| `kbERcU6MYXBSJxQ8mFE6hD.frame/` | Feeds (MalwareBazaar, ThreatFox, UnpacMe) |
| `1PyqVxCgFzGv9gav8ejjpi.frame/` | Send (to NocTORnal) |
| `7VRZzGiEFP2JVmHbxh1oa7.doc/` | Design theme: tokens, type, signature components |
| `shared/` | Shell, ui components, mock spectra |

Imports use `@os/<id>` (the folder named `<id>.frame` or `<id>.prototype`) and `@shared/` (the
`shared/` folder). It needs React 18, Tailwind 4, lucide-react and framer-motion (see `package.json`).

## Gaps against the CLI

Found by reading the Spectra, Send and Feeds frames and the prototype. All of these are fixed in
`ui/app/` (this folder stays as exported).

- **Env vars.** Send shows `NOCTORNAL_INGEST_KEY`. The CLI reads `MAASSPEC_INGEST_KEY` and
  `MAASSPEC_NOCTORNAL_URL`. Feeds shows `MB_AUTH_KEY` and `THREATFOX_AUTH_KEY`. The CLI reads one
  key for both, `MAASSPEC_ABUSECH_KEY`.
- **Destination rule.** The design allows loopback only (127.0.0.0/8, `::1`, `localhost`, http or
  https). The client allows https to any host, and http only to `127.0.0.1`, `::1` or `localhost`.
- **Feed commands.** `buildCommand` in `FeedCard.tsx` prints `maasspec feed <feed> <query> --<field> <value> --out <feed>_<query>.jsonl`.
  The real form is `maasspec feed fetch <feed> <query> [term] [--limit N] [--days N] [--selector S] [--exact] --out <file>.json`,
  which writes the raw response. `maasspec feed import <feed> <file>` then produces the JSON Lines.
  The term is positional, not `--hash` or `--tag`.
- **UnpacMe query id.** The design uses `public`. The CLI query is `feed`.
- **ThreatFox `recent` days.** The design defaults to 3. The CLI defaults to 1.
- **Review marks.** The help text says they are stored in the browser. The prototype keeps them in
  component state only.

Spectrum Detail, Selectors and the mock data were scanned only for links, downloads, HTML injection
and network calls. None were found in any file.
