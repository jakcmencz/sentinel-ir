# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

- email **sentinel.ir.contact@gmail.com** with the subject `SECURITY: sentinel-ir`, or
- open a [confidential issue](https://gitlab.com/jakubrojicek11/sentinel-ir/-/issues/new?issue[confidential]=true) on GitLab.

Include the version, your operating system and Node.js version, and the
smallest input or steps that show the problem. I aim to reply within 7 days.
A fix is released as a new patch version; you are credited in the release
notes unless you ask not to be.

## What counts

Anything that makes `sentinel-ir` execute, load or evaluate the analyzed source, read files other than the input it was given, hang the caller past the parse budget, or crash the process.

A finding that the analyzer misses (a false negative) or over-reports is a
normal bug unless it can be used to make an agent trust unsafe code; report it
privately if unsure.

## Supported versions

Only the newest release of the current minor line (the npm `latest` tag)
gets fixes.

## Known limits

Sentinel-IR reads code and never runs it. That makes it safe to point at
untrusted code, and it also sets limits no release can remove. They are normal
behavior, not vulnerabilities:

- **Code that exists only at run time is not visible.** Code that is
  downloaded, decoded or assembled while the program runs is not in the file.
  Sentinel-IR reports the mechanism (`dynamic_code`, `dynamic_import`,
  `dynamic_reference`) and raises the risk, but cannot say what that code does.
- **`low` is not proof of safety.** It means no known risky pattern was found
  in this file. New evasion patterns are reported as normal bugs.
- **One file at a time.** Capabilities split across files are not combined.
- **The IR contains text chosen by the file's author.** Names of exports,
  imports, env variables and paths are copied as data. Names that look like
  instructions to an agent are flagged `suspicious_text`, but an agent must
  treat the whole IR as untrusted data, never as instructions.
- **`incomplete` means facts may be missing.** A file that does not fully
  parse (syntax error, nesting too deep, parse budget) is at least `medium`;
  its facts cover only what was parsed.

More detail is in the README section
[Limitations](https://gitlab.com/jakubrojicek11/sentinel-ir#limitations).

## Release integrity

Releases are published only from GitLab CI on a protected `v*` tag, through
npm trusted publishing (GitLab OIDC) with
[provenance](https://docs.npmjs.com/generating-provenance-statements); no npm
token is stored. Check a release with `npm audit signatures`. GitHub is a
read-only mirror.
