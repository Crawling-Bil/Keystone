# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users are network engineers working in staging, assessment, and change activities. The working assumption for this redesign is a mixed-experience internal team: senior engineers need speed and density, while junior engineers need concise guidance without a long briefing.

## Product Purpose

Keystone (formerly Network Engineer Suite) gives an internal engineering team one local workspace for configuration conversion, wireless assessment, switch analysis, and device lifecycle operations. Success means another engineer can open the application, understand which tool to use, provide the required input, and complete or export a result without the creator explaining the interface.

## Positioning

Keystone combines multi-vendor network engineering workflows in one local-first web interface. Configuration and inventory data are processed on the engineer's machine instead of requiring separate desktop utilities or an external service.

## Operating Context

- Used during switch staging, wireless assessments, configuration migration, pre-check, and firmware preparation.
- Runs from a local Flask/Waitress service at `127.0.0.1:8002`.
- Common source material includes running configurations, terminal captures, WLC backups, AP inventory files, and firmware images.
- Engineers need to scan the interface quickly while working alongside terminals, consoles, spreadsheets, and change documentation.

## Capabilities and Constraints

- Preserve Configuration Studio, Wireless Analyzer, Switch Analyzer, Lifecycle Manager, their routes, and their existing business logic.
- Preserve Cisco, Huawei, and Aruba terminology where applicable.
- Keep the application local-first and usable without external UI dependencies.
- Make required input, supported file types, system feedback, and the next action obvious.
- Use progressive disclosure so advanced detail remains available without overwhelming the first view.
- Working assumption: the dashboard primarily launches tools; operational status remains visible but secondary.

## Brand Commitments

- Product name is Keystone (renamed from Network Engineer Suite, 2026-08); "Network Engineer Suite" is kept as the descriptive subtitle. Logo is being redesigned to match — see the logo-concepts canvas.
- Voice should be calm, precise, direct, and professional.
- The user requested a simpler visual language, calmer colors, clearer hierarchy, more intentional spacing, and a new font treatment.

## Evidence on Hand

- Existing Flask application and four working modules in this repository.
- Existing SVG icon sprite at `static/icons/nes-icons.svg`.
- Existing activity data and health endpoint.
- No customer claims, performance benchmarks, testimonials, or external brand assets should be fabricated.

## Product Principles

1. Make the next action obvious.
2. Explain only what prevents an error.
3. Keep technical detail available on demand.
4. Use one consistent interaction pattern across modules.
5. Preserve local trust and operational clarity.

## Accessibility & Inclusion

Support keyboard navigation, visible focus states, WCAG AA color contrast, reduced motion, readable scaling, and touch-friendly controls. Do not rely on color alone for operational status.
