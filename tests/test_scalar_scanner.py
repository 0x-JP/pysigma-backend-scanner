import pytest

from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.mark.parametrize("condition, predicate", [
    ("selection", '_sigma_null_0 = "true"'),
    ("not selection", 'not _sigma_null_0 = "true"'),
])
def test_null_comparison(convert_rule, condition, predicate):
    assert convert_rule({"selection": {"name": None}, "condition": condition}) == [
        f'* | eval _sigma_null_0 = `name` == null | where {predicate}'
    ]


def test_null_or_empty_keeps_branches_together(convert_rule):
    assert convert_rule({
        "scope": {"@index": "cloudtrail"},
        "missing": {"name": None},
        "empty": {"name": ""},
        "condition": "scope and (missing or empty)",
    }) == [
        '@index=cloudtrail | eval _sigma_null_0 = `name` == null'
        ' | where (_sigma_null_0 = "true" or name = \'\')'
    ]


def test_field_equality_checks_both_operands_present(convert_rule):
    assert convert_rule({"selection": {"actor|fieldref": "target"}, "condition": "not selection"}) == [
        '* | eval _sigma_fieldref_0 = `actor` != null and `target` != null and `actor` == `target`'
        ' | where not _sigma_fieldref_0 = "true"'
    ]


def test_fieldref_operand_not_overwritten(convert_rule):
    result = convert_rule({
        "selection": {"actor|fieldref": "_sigma_fieldref_0"}, "condition": "selection",
    })[0]
    assert result.startswith('* | eval _sigma_fieldref_1 = ')
    assert '`actor` == `_sigma_fieldref_0`' in result


def test_unfielded_or_list_and_field_selection(convert_rule):
    assert convert_rule({
        "selection": {"eventName": "Create"},
        "keywords": ["break-glass", "listKeys/action"],
        "condition": "selection and not keywords",
    }) == ["eventName = 'Create' and not ('break-glass' or 'listKeys/action')"]


@pytest.mark.parametrize("keyword, expected", [
    ("O'Brien", r"'O\'Brien'"),
    ("*admin*", "'*admin*'"),
    (r"literal\*", r"'literal\*'"),
    ("image-policy.k8s.io/break-glass", "'image-policy.k8s.io/break-glass'"),
])
def test_unfielded_escaping(convert_rule, keyword, expected):
    assert convert_rule({"keywords": [keyword], "condition": "keywords"}) == [expected]


def test_unfielded_search_before_eval(convert_rule):
    assert convert_rule({
        "keywords": ["true"], "missing": {"name": None}, "condition": "keywords and missing",
    }) == ['\'true\' | eval _sigma_null_0 = `name` == null | where _sigma_null_0 = "true"']


def test_unfielded_search_does_not_match_generated_columns(convert_rule):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="eval columns"):
        convert_rule({
            "keywords": ["true"], "missing": {"name": None}, "condition": "keywords or missing",
        })


def test_mixed_scalar_predicates_use_one_eval(convert_rule):
    result = convert_rule({
        "missing": {"name": None}, "pattern": {"name|re": "admin"},
        "condition": "missing or pattern",
    })[0]
    assert result.count(' | eval ') == 1
    assert result.endswith(' | where (_sigma_null_0 = "true" or _sigma_regex_1 = "true")')
