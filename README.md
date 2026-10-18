# pySigma Scanner Backend

The `scanner` backend for pySigma provides `sigma.backends.scanner.ScannerBackend`.
Its default output is a [Scanner query](https://docs.scanner.dev/scanner/using-scanner-complete-feature-reference/querying-and-analysis/query-syntax), not a deployed detection rule.

## Installation and usage

Requires Python 3.10 or newer. Install from this checkout:

```sh
python -m pip install . sigma-cli
sigma convert -t scanner -p pipeline.yml path/to/rule.yml
```

Supply your index using a standard pySigma processing pipeline (`pipeline.yml`):

```yaml
name: Scanner CloudTrail index
priority: 100
transformations:
  - id: cloudtrail_index
    type: add_condition
    conditions:
      '@index': cloudtrail
    rule_conditions:
      - type: logsource
        product: aws
        service: cloudtrail
```

Replace `cloudtrail` with your index alias. Add logsource-specific conditions and
field mappings for other datasets. No `@scnr.source_type` filter is added.
Without an applicable index pipeline, output is an unscoped predicate.

## Query support

Supports string equality, `cased`, `contains`, `startswith`, `endswith`, `*`
wildcards, boolean conditions, lists, numeric comparisons and field existence.
Field string matching uses whole-field equality, not Scanner token matching (`:`).
Unfielded keywords use Scanner's native quoted free-text search, including its
token boundaries. No field is inferred and no surrounding wildcards are added.

Regex uses Scanner's beta [scalar functions](https://docs.scanner.dev/scanner/using-scanner-complete-feature-reference/beta-features/scalar-functions-and-operators):
`regex.is_match` through `eval`, followed by `where`.
Supports `re`, `re|i`, `re|m` and `re|s`; patterns must be compatible with Scanner's
Rust regex engine (no lookaround, backreferences or atomic groups). Native AND
filters and index selection stay before `eval`; mixed OR/NOT branches are retained
in the final filter. Null checks (`field == null`) and field-to-field equality also
use this eval path. Field equality is value-sensitive and requires non-null operands.
Index selection inside a scalar-containing OR/NOT branch is rejected, as are
unfielded searches in those branches: generated columns would change their search
scope. Generated `_sigma_regex_*`, `_sigma_null_*` and `_sigma_fieldref_*` columns
are reserved for intermediate results.

CIDR, field-reference substring matching, typed booleans, single-character
wildcards, field wildcards and correlations raise conversion errors.
Deployment formats are not implemented. Validation is offline; actual Scanner
execution, Unicode case folding and schema-dependent array/missing-value behaviour
remain unverified.
Cloud rules often assume normalized fields or serialized objects. Map these to
your ingested fields; successful conversion alone does not establish a match.

## Development

```sh
poetry install
poetry run pytest
poetry build
```

Tests include upstream Sigma rules and installed CLI conversion. See
[fixture provenance](tests/fixtures/README.md) for sources and comparison notes.

## License

Backend code: [LGPL-2.1-only](LICENSE). Upstream Sigma test rules retain their
[DRL-1.1 license](tests/fixtures/DRL-1.1.md).
