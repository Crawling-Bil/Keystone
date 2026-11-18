# Security policy

Keystone is a local application: it listens only on the computer that runs it and keeps no account database.
That does not make a vulnerability harmless, because the tool reads customer configurations and can push
firmware and configuration to devices.

## Reporting a problem

- Do **not** open a public issue for a vulnerability, and never attach a real customer capture to any issue.
- Use GitHub's private report: **Security > Report a vulnerability** on the repository page
  ([how it works](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).
  If that button is not shown, message the maintainer directly.
- Say what you did, what you expected and what happened. A short capture with invented names is enough.

## Supported versions

Only the latest release on `main` is supported. Update with `git pull` (or GitHub Desktop, **Fetch origin** then **Pull**) before you report.

## What the design already does

See `core/local_guard.py` (local-only listening, `Host` and `Origin` checks, content security policy) and the
"Security" part of `CONTRIBUTING.md`. Sharing one running copy with other people on a network is not supported:
keep one copy per engineer.
