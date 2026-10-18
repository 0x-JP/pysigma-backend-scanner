# Upstream fixtures

`sigma/` contains nine SigmaHQ rules under DRL-1.1. Authors, references and rule
IDs are retained in each file. See `DRL-1.1.md` for terms.

`expected-queries.yml` records reviewed Sigma-preserving translations. Native
Scanner comparison rules are linked below rather than copied into this repository.

Sources:

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma/tree/b7920ed31356fb7f6a9275b34737d8604c65bac3): `rules/cloud/aws/cloudtrail/` and `rules/windows/process_creation/`.
- [Scanner CloudTrail](https://github.com/scanner-inc/detection-rules-aws-cloudtrail/tree/f7540bd09e4e35172bd3c6146c7188c8b7401025): `rules/`.
- [Scanner Windows](https://github.com/scanner-inc/detection-rules-windows-process-creation/tree/c4759c3f39f167a6e557a5440d5a65add2bf14ba): `rules/`.

Corresponding filenames are identical in the upstream Sigma and Scanner repositories.
Final newlines are normalized. Review fixture changes together with expected
queries; do not regenerate expected queries simply to make a test pass.

## Comparison notes

Scanner's examples add source-type filters and summary aggregation. Generated
queries preserve Sigma's predicates; the user's pipeline supplies index selection.
Native Scanner examples are references, not exact output requirements:

- CloudTrail/GuardDuty/SecurityHub rules have the same source and event-name
  selections. Native double-quoted strings are case-sensitive; Sigma's default
  strings are case-insensitive.
- The root-account rule preserves its service-event exclusion.
- The EC2 startup-script rule uses whole-field attribute equality; Scanner's
  native token predicate can match broader values.
- The RDS password rule uses Sigma's wildcard-only contains pattern. Native
  Scanner uses an existence check; empty-value equivalence needs live validation.
- The RDS restore rule uses Sigma's string `true`; Scanner's native rule uses
  bare `true`. Stored data-type behaviour needs live validation.
- Finger and ConHost rules retain filename equality, image suffixes and command
  substrings. Native token predicates can differ at boundaries.

These tests check reviewed query output. They do not execute Scanner queries.
