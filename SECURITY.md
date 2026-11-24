# Security Policy

OpenInvestigation is a self-hosted threat-investigation workspace meant to run on the
analyst's own machine, bound to `127.0.0.1`. Because it fetches and renders attacker-controlled
content and talks to third-party intelligence sources, we take reports about data exfiltration,
server-side request forgery, and prompt injection seriously.

## Supported versions

The project ships from `main`. Only the latest commit on `main` is supported; fixes land there
and are not backported. Please reproduce on the current `main` before reporting.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| older commits / tags | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Report it privately through GitHub Security
Advisories:

1. Go to the repository's **Security** tab → **Report a vulnerability**
   (<https://github.com/V1n1v131r4/OpenInvestigation/security/advisories/new>).
2. Describe the issue, the affected version/commit, and the impact.
3. Include a minimal reproduction: inputs, configuration, and expected vs. actual behavior.

Please do not include real case data, live victim indicators, or secrets in the report. Use
synthetic fixtures (for example `192.0.2.0/24`, `example.org`) whenever possible.

### Response targets

These are goals, not contractual guarantees, for a volunteer-maintained project:

- **Acknowledgement:** within 5 business days.
- **Initial assessment / triage:** within 10 business days.
- **Fix or mitigation plan:** communicated after triage, prioritized by severity.

We will coordinate a disclosure timeline with you and credit you in the advisory unless you prefer
to remain anonymous.

## Scope

In scope — issues that undermine the analyst's control over what leaves their machine or the
integrity of an assessment, including:

- **Server-side request forgery (SSRF):** bypassing the public-IP validation and host pinning in
  `public_pages.request` / `public_address`, reaching loopback, link-local, or internal addresses,
  or forcing requests to unintended hosts.
- **Prompt injection:** source text that manipulates the LLM assessment into ignoring instructions,
  fabricating citations, or exfiltrating data, beyond the documented sanitization limits.
- **Seed/indicator leakage:** a case sending its seeds or evidence to a source or provider that the
  configured policy should not have contacted.
- Secret handling: API keys written to logs, disk, or outbound requests that should not carry them.
- Local HTTP interface: session/same-origin bypass, request-smuggling, or injection in the API.

Out of scope:

- Findings that require the operator to deliberately disable safeguards (for example
  `OSINT_WEB=1` with sources they explicitly enabled).
- Denial of service through resource exhaustion on a single-user local instance.
- Vulnerabilities in third-party sources, SearXNG, or model providers themselves.
- Deployments exposed to untrusted networks without the documented local binding.

## Hardening expectations

Run the application bound to localhost as shipped. Keep API keys in a local `.env` that is not
committed. Treat all collected source text as untrusted data.
