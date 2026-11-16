# MaaSSpec design theme

**Idea: a spectrometer readout.** A mass spectrometer turns a sample into a set of peaks, and an analyst reads them. MaaSSpec does the same with malware: one input becomes one spectrum of findings. The UI behaves like the instrument's readout. It is quiet and exact, it shows where each number came from, and it makes no decisions for the analyst.

The fun stays small and stays in the details: the peaks logomark, the "spectrum" vocabulary, and the 5-segment confidence bar that looks like a short peak row. Screens, layout and copy stay as plain as NocTORnal, so the two tools work side by side.

## Principles
- **Machines propose, analysts dispose.** No control accepts, rejects or promotes a finding. Send forwards spectra unchanged.
- **Provenance before value.** Every finding shows who claimed it (Static, Sandbox (CAPE), Feed claim · feed), how sure it is, and the grade it proposes.
- **Inert by construction.** Values are monospace text and never links. URLs and domains are defanged by default. No control downloads, runs or renders a sample.
- **Open straight on the work.** No intro text. An empty state is one line. Explanations sit behind a `?`.

## Mark
Five vertical peaks of different heights on a baseline, drawn with 1.5px strokes in the accent colour. It sits at 16px in the header next to "MaaSSpec" and the version. It is not used anywhere else.

## Colour
One muted accent, a spectral teal. Amber and red only ever appear with an icon and a word.

| Token | Dark | Light | Use |
|---|---|---|---|
| bg | `#151719` | `#f3f4f5` | App background, table body |
| panel | `#1b1e21` | `#ffffff` | Header, nav, toolbars, group rows |
| raised | `#23272b` | `#eceef0` | Hover, chips |
| line / line-strong | `#2b3035` / `#3b4248` | `#dde0e3` / `#c4c9ce` | 1px borders, empty segments |
| fg / muted / faint | `#dadee2` / `#9ba3ab` / `#79818a` | `#1c2024` / `#59626b` / `#6b747d` | Text tiers |
| accent | `#7cb6a6` | `#2f7a68` | Selection, filled segments, active tab, primary action |
| warn | `#d8a648` | `#94620a` | Always shown with ▲ and "Warning" |
| err | `#e26d66` | `#b93a33` | Always shown with ⬣ and "Error" |

Tokens live as CSS variables (`--mx-*`) under `.theme-dark` and `.theme-light`. Tailwind reads them as `bg-panel`, `text-muted`, `border-line`, and so on.

## Type
- UI: system sans. Base size 13px. Secondary text 12px, column headers 11px.
- Monospace (`ui-monospace`, SF Mono, Menlo, Consolas) for every hash, URL, IP, selector, id, subtype, module name, number and command.
- Tabular figures for every count and confidence.

## Shape and density
- Flat panels, 1px borders, 4px radius. No shadows, gradients or glow.
- Table rows are 28 to 32px tall. Group header rows use the panel colour. Grouping comes from rules and whitespace, not cards; Feeds is the one screen that uses cards.
- Motion is limited to what tells you something: 100ms colour on hover, 150ms popovers, 180ms row expand, all `cubic-bezier(0.23, 1, 0.32, 1)`.

## Signature components
- **Confidence bar:** 5 segments filled to `round(value × 5)`, followed by the number to two decimals.
- **Grade chip:** `C/3`, monospace, 1px border. Hover shows the rationale. The `?` in the column header explains the A–F and 1–6 scales.
- **Provenance badge:** Static and Sandbox (CAPE) in full text colour. Feed claims are muted and carry a dashed "claimed" marker.
- **Input type chip:** a bordered monospace label (`sample`, `archive`, `cape_report`, `feed_record`).
- **Notice:** one line with an icon, a bold word and a sentence. Used for the scan window and for the feed-claims banner.
- **Copy button:** a 20px icon after any value. It turns into a check for 1.2s after copying.

## Layout
- 36px header with the name and version only. The left nav is 132px of text labels (Spectra, Selectors, Feeds, Send), with the theme switch at the bottom. Below `md` the nav moves to a horizontal bar.
- Spectrum detail keeps the spectra list in a 260px rail, so the list stays in view.
- Selectors uses a table with a 380px side panel for the selected value.
