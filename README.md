# pySigma Scanner Backend

This is the [Scanner](https://scanner.dev/) backend for
[pySigma](https://github.com/SigmaHQ/pySigma). It provides the package
`sigma.backends.scanner` with the `ScannerBackend` class.

The `default` output format produces Scanner queries.

## Installation

Requires Python 3.10 or newer. Install from this checkout:

```sh
python -m pip install . sigma-cli
```

## Usage

```sh
sigma convert -t scanner -p pipeline.yml path/to/rule.yml
```

Use a pySigma processing pipeline to select your Scanner index and map Sigma
fields to your log schema. For example, `pipeline.yml` for CloudTrail:

```yaml
name: Scanner CloudTrail
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

Replace `cloudtrail` with your index alias. Without an index condition, queries
search all indexes. No field mappings or source-type filters are added automatically.

### Scanner CloudTrail

For AWS CloudTrail logs using Scanner's [ECS normalization](https://docs.scanner.dev/scanner/using-scanner-complete-feature-reference/data-transformation-and-enrichment/data-transformations),
the optional `scanner_cloudtrail` pipeline maps documented fields into `@ecs`:

```sh
sigma convert -t scanner -p scanner_cloudtrail path/to/cloudtrail-rule.yml
```

It applies only to AWS CloudTrail rules, retains native paths for unmapped fields,
and does not select an index. Scanner preserves the original fields, so this
pipeline is optional even when ECS normalization is enabled.

## Limitations

- CIDR matching, field-reference substring matching, correlation rules and
  detection deployment formats are not supported.
- Regex, single-character wildcards (`?`), null checks and field-to-field equality
  use Scanner's beta [scalar functions](https://docs.scanner.dev/scanner/using-scanner-complete-feature-reference/beta-features/scalar-functions-and-operators).
  These operations require individual fields, not wildcard field patterns.
  Regex must be compatible with Rust regex syntax: no lookaround, backreferences
  or atomic groups.
- Unfielded keywords use Scanner's token boundaries. Index selection and unfielded
  searches cannot share an OR/NOT branch with scalar predicates. Wildcard filters
  that would match generated `_sigma_*` columns are also rejected.

## Development

```sh
poetry install
poetry run pytest
poetry build
```

## License

[LGPL-2.1-only](LICENSE). Upstream Sigma test rules retain their
[DRL-1.1 license](tests/fixtures/DRL-1.1.md).
