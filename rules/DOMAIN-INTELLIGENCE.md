# Domain Intelligence Pack

The five optional files in `rules/domain-intelligence/` use indicators reported
in [Huntress's July 22, 2026 FakeAgent incident response report](https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat).
The report describes Claude Desktop-themed malvertising leading through a
public Claude Artifact, a lookalike redirect, and an installer landing page;
it also publishes SectopRAT command-and-control indicators. These rules test
those exact reported values, not broad vendor domains or inferred variants.

Use `--rules rules/domain-intelligence` to load this pack alongside the eight
default starter rules. Each file is one detection using the same template as
other packs. `CommandDomains` and `CommandURLs` are extracted from tool-input
HTTP(S) URLs. `ObservedDomains` and `ObservedURLs` come from `--network-log`
records only when session ID and call ID uniquely match a recorded call.
`OutputDomains` and `OutputURLs` are also available in custom rules, but a
tool's returned text mentioning an IOC does not trigger these five rules.

The `*Domains` selectors match exact normalized hosts, not subdomain suffixes.
The installer and Artifact rules match host and path together in one URL, so
unrelated URLs cannot satisfy separate host/path clauses. URL query contents
are redacted before matching. The template demonstrates both a command-domain
and an observed-domain selection; replace `example.invalid` with a vetted IOC.

A tool command can contain a quoted URL for research or documentation without
making a network request. Imported observations are only as trustworthy as the
supplied log and its call correlation. Domains and IPs may be reassigned; the
malicious content may have disappeared. A match warrants review of response,
payload hash, process lineage, timing, user authorization, and independent
proxy/DNS/endpoint evidence. All five rules are deliberately left unmapped to
MITRE ATLAS and OWASP LLM: an IOC match alone does not demonstrate an AI-specific
technique or LLM application weakness.
