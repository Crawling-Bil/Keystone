---
name: Keystone
description: A local-first network operations workspace with an FTD-inspired visual system. Formerly named Network Engineer Suite.
colors:
  dark-canvas: "#101113"
  dark-sidebar: "#17181b"
  dark-panel: "#1b1c1f"
  dark-panel-raised: "#212327"
  dark-panel-inset: "#18191c"
  dark-border: "#2b2d31"
  dark-text: "#ece9e3"
  dark-text-soft: "#c7c3bc"
  dark-muted: "#8c8985"
  dark-faint: "#6b6864"
  accent-teal: "#45bcae"
  accent-teal-hover: "#5fcabd"
  status-green: "#74c08f"
  status-amber: "#d3a24b"
  status-red: "#dd828a"
  on-accent: "#06231e"
  light-canvas: "#f7f6f3"
  light-sidebar: "#ffffff"
  light-accent: "#0f8a7e"
typography:
  heading: '"Archivo NES", "Atkinson NES", sans-serif'
  body: '"Atkinson NES", -apple-system, BlinkMacSystemFont, sans-serif'
  network-data: 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace'
spacing: [4, 8, 12, 16, 24, 32]
radius:
  control: "999px (M3 pill)"
  card: "20px"
  panel: "20px"
---

# Design System: FTD Operations Console

## North star

Keystone should feel like a focused security appliance console: dark navy work surfaces, compact cyan interaction cues, strong text legibility, and restrained status colors. It is built for engineers who need to understand the next action without a long briefing.

The interface uses density to keep operational data close, but grouping and spacing prevent it from becoming a wall of controls. Resting surfaces are flat; borders and tonal layers carry hierarchy. Cyan identifies navigation, focus, and primary actions—not decoration.

## Color rules

- Dark mode is the default. Use `#071a24` for the page, `#0a2430` for navigation, and the panel ladder `#0c2733` → `#102d39` → `#153744`.
- Use `#24b4cd` for the primary action, active navigation, links, focus, and selected interaction cues. Hover may move to `#55c7d9`.
- Use green, amber, and red only for success, caution, and critical state. Always pair state color with text, a number, or an icon.
- Use semantic CSS variables in components. Avoid screen-level hardcoded colors except for deliberate dark-theme surface overrides.
- Light mode remains supported with a cool gray-blue canvas and darker cyan accent.

## Typography

Archivo NES structures page headings, section titles, navigation, and compact labels. Atkinson NES carries body copy, instructions, and controls for high legibility. Monospace is reserved for commands, addresses, versions, identifiers, and tabular network data.

Type hierarchy uses a compact operational scale: 12px metadata, 13–15px body/control copy, 18px section headings, and fluid 28–42px display headings. Body line-height stays near 1.5.

## Layout and spacing

- Desktop frame: 232px navigation rail, sticky top bar, and a fluid main column.
- Use a 4/8px spacing family. Related controls use 8–16px gaps; major regions use 24–32px.
- Panels use 12px corners; nested cards use 10px; controls use 8px.
- Mobile stacks workflow columns in their original reading order. No horizontal page overflow is allowed; data tables may scroll inside their own wrapper.
- General controls and interactive targets are at least 44px high.

## Wireless Analyzer intake

The intake is a visible three-step sequence:

1. **WLC configuration — Required.** Upload controller configuration or terminal capture.
2. **AP runtime inventory — Recommended.** Upload Huawei AP Info or AP Master CSV/XLSX to enrich live device fields.
3. **Vendor and analysis.** Choose Auto Detect, Huawei, or Cisco, then run the single primary CTA.

Steps 1 and 2 use equal-height cards at desktop width. Each card has the same heading anatomy, drop zone height, file-removal action, and bottom helper region. At 720px and below, they stack into one column. A selected file is communicated by its filename and removal action in addition to the green state treatment.

## Interaction and accessibility

- All iconography uses the shared SVG sprite; structural emoji are prohibited.
- Visible labels are required for form controls. File drop zones must remain keyboard-accessible through their native file input.
- Global `:focus-visible` treatment uses the cyan focus token and remains visible in both themes.
- Loading buttons become disabled and replace their label with a progress message.
- Motion stays within 150–300ms and does not shift layout. `prefers-reduced-motion` removes nonessential transitions.
- Text contrast targets WCAG AA. The validated dark intake pairs range from 5.83:1 to 16.42:1.

## Do / don't

- Do keep one primary action per workflow region and subordinate export/clear actions.
- Do use progressive disclosure for capture commands and advanced instructions.
- Do preserve explicit status text alongside color.
- Don't add decorative glow, gradient text, glass effects, or competing accent hues.
- Don't shrink buttons, selects, or file targets below 44px.
- Don't put configuration prose and primary controls into one unstructured row.


## v1.9.2 — restraint pass

The two prior passes (v1.9.0, v1.9.1) leaned on Material 3 for structural
ideas but over-applied its surface signifiers — full-pill shapes on every
control, a five-tier surface ladder, a pulsing nav dot, a decorative radial
gradient glow, and a navy-tinted "sci-fi" dark background. Individually
defensible, together it read as generic AI-dashboard styling rather than a
considered tool. This pass keeps what's genuinely useful from M3 (tonal
elevation over drop shadows) and drops the rest:

- **Palette**: dark theme moved from a navy/cyan-tinted canvas to a neutral
  graphite (`#101113`) — the accent teal now reads as a deliberate color
  choice instead of blending into a themed "hacker console" background.
  Light theme moved from cold gray-blue to a warm near-white (`#f7f6f3`)
  with near-black text and a deep confident teal accent — closer to
  contemporary developer tools (Linear, Vercel, Raycast) than a generic
  SaaS dashboard.
- **Removed**: the decorative radial-gradient glow on `body`, the pulsing
  animation on the active nav indicator and status dots, and the full-pill
  shape on every single control. Buttons and cards use a restrained,
  consistent radius (8–12px) rather than maximal roundness everywhere.
- **Icons**: redrawn the sidebar/module icon set with more specific,
  less geometric-primitive compositions (e.g. Configuration Studio is now
  a bracket-transform mark rather than generic sliders; Lifecycle Manager
  is a device with an orbiting refresh arc rather than a generic gear).
- **Cleanup**: the CSS had accumulated three overlapping theme-token
  layers from earlier redesign passes, several with hardcoded hex values
  that leaked through the newest palette. Consolidated to one source of
  truth per theme and converted leftover hardcoded colors to tokens, so
  future palette changes don't require hunting through the cascade.
