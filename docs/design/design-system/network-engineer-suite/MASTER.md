# Keystone — FTD Operations Console

_Formerly named Network Engineer Suite (NES). Renamed 2026-08._

> Page rules in `pages/` override this file where explicitly stated.

**Version:** 1.7.1  
**Product:** Local-first network engineering operations console  
**Direction:** Dense, calm, appliance-like, dark-first

## Tokens

| Role | Dark | Light | CSS token |
|---|---:|---:|---|
| Canvas | `#071a24` | `#edf3f5` | `--bg` |
| Navigation | `#0a2430` | `#e2ebee` | `--sidebar` |
| Panel | `#102d39` | cool white | `--panel` |
| Raised panel | `#153744` | pale blue-gray | `--panel-2` |
| Inset panel | `#0c2733` | pale gray-blue | `--panel-3` |
| Border | `#2b4b59` | cool divider | `--border` |
| Primary text | `#f1f7f9` | navy ink | `--text` |
| Secondary text | `#d8e5e9` | slate ink | `--text-soft` |
| Muted text | `#a8bbc3` | slate | `--muted` |
| Accent | `#24b4cd` | `#087b93` | `--blue` |
| Accent hover | `#55c7d9` | darker cyan | `--blue-2` |
| Success | `#73ca9c` | deep green | `--green` |
| Warning | `#efbc5c` | deep amber | `--amber` |
| Critical | `#ff7f85` | deep red | `--red` |

## Type

- Headings and labels: Archivo NES, weights 600–700.
- Body and controls: Atkinson NES, weight 400–600, line-height 1.45–1.6.
- Technical values only: system monospace.
- Font files are self-hosted and use `font-display: swap`.

## Geometry and rhythm

- Spacing: 4, 8, 12, 16, 24, 32px.
- Controls: 8px radius and at least 44px height.
- Cards: 10px radius. Outer panels: 12px radius.
- Resting surfaces use tonal separation and 1px borders, not decorative shadows.
- Desktop navigation rail is 232px; it becomes an off-canvas drawer under 900px.

## Interaction

- One cyan primary CTA per workflow region.
- Hover/focus/active transitions: 150–220ms, without layout-changing transforms.
- Keyboard focus: visible 3px cyan outline/ring.
- Disabled controls: semantic `disabled`, reduced opacity, unavailable cursor.
- Status meaning must include text/icon/number; never color alone.
- Use only the shared outline SVG icon system.
- Honor `prefers-reduced-motion`.

## Responsive

- Preserve reading and focus order as columns stack.
- No page-level horizontal overflow at 390px or landscape phone widths.
- Keep tables in explicit horizontal scroll wrappers.
- Collapse optional metadata before reducing touch-target size.

## Forbidden patterns

- Decorative neon glow, glassmorphism, gradient text, and ambient animation.
- Violet or unrelated accent colors competing with FTD cyan.
- Placeholder-only form labels, icon-only primary actions, emoji icons.
- Arbitrary z-index values or animation longer than 500ms.
