import pytest
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError, SigmaValueError


@pytest.mark.parametrize(("field", "value", "expected"), [
    ("name", "Admin", "name = 'Admin'"),
    ("name|cased", "Admin", 'name = "Admin"'),
    ("name", "", "name = ''"),
    ("name|contains", "min", "name = '*min*'"),
    ("name|startswith", "adm", "name = 'adm*'"),
    ("name|endswith", "min", "name = '*min'"),
    ("name|contains|cased", "Ad", 'name = "*Ad*"'),
    ("name", r"C:\Windows\cmd.exe", r"name = 'C:\\Windows\\cmd.exe'"),
    ("name", "O'Brien", r"name = 'O\'Brien'"),
    ("name|cased", 'a"b', r'name = "a\"b"'),
    ("name", r"literal\*", r"name = 'literal\*'"),
    ("name", r"literal\?", "name = 'literal?'"),
    ("name", "foo*bar", "name = 'foo*bar'"),
    ("name", "x\ny\tz\x00", r"name = 'x\u000ay\u0009z\u0000'"),
    ("name", "a' or dangerous = *", r"name = 'a\' or dangerous = *'"),
    ("name", "straße", "name = 'straße'"),
    ("field with spaces", "value", "`field with spaces` = 'value'"),
    ("AND", "value", "`AND` = 'value'"),
    ("field`name", "value", r"`field\`name` = 'value'"),
    ("field\nname", "value", r"`field\u000aname` = 'value'"),
    ("name\n", "value", r"`name\u000a` = 'value'"),
    ("status", 200, "status = 200"),
    ("elapsed|gte", 100, "elapsed >= 100"),
    ("elapsed|lt", 100, "elapsed < 100"),
    ("elapsed|gt", -1, "elapsed > -1"),
    ("elapsed|lte", 0.5, "elapsed <= 0.5"),
    ("elapsed|neq", 100, "not elapsed = 100"),
    ("name|exists", True, "name = *"),
    ("name|exists", False, "not name = *"),
])
def test_scalar_translation(convert_rule, field, value, expected):
    assert convert_rule({"selection": {field: value}, "condition": "selection"}) == [expected]


def test_grouping_keeps_exclusion_outside_or(convert_rule):
    assert convert_rule({
        "selection": {"name": ["one", "two"]},
        "filter": {"user": "trusted"},
        "condition": "selection and not filter",
    }) == ["(name = 'one' or name = 'two') and not user = 'trusted'"]


def test_negation_groups_conjunction(convert_rule):
    assert convert_rule({
        "selection": {"name": "one", "user": "trusted"},
        "condition": "not selection",
    }) == ["not (name = 'one' and user = 'trusted')"]


def test_all_modifier(convert_rule):
    assert convert_rule({
        "selection": {"CommandLine|contains|all": ["one", "two"]},
        "condition": "selection",
    }) == ["CommandLine = '*one*' and CommandLine = '*two*'"]


@pytest.mark.parametrize("condition, operator", [("1 of selection_*", "or"), ("all of selection_*", "and")])
def test_selector_expansion(convert_rule, condition, operator):
    assert convert_rule({
        "selection_one": {"name": "one"},
        "selection_two": {"name": "two"},
        "condition": condition,
    }) == [f"name = 'one' {operator} name = 'two'"]


def test_multiple_conditions(convert_rule):
    assert convert_rule({
        "selection_one": {"name": "one"},
        "selection_two": {"name": "two"},
        "condition": ["selection_one", "selection_two"],
    }) == ["name = 'one'", "name = 'two'"]


def test_numeric_inequality_negation_preserves_pysigma_semantics(convert_rule):
    assert convert_rule({
        "selection": {"elapsed|neq": 0}, "condition": "not selection",
    }) == ["not (not elapsed = 0)"]


@pytest.mark.parametrize("field, value", [
    ("name|re", "a(?=b)"),
    ("enabled", True),
    ("enabled", False),
    ("ip|cidr", "10.0.0.0/8"),
    ("name|fieldref|contains", "other"),
    ("field?", "value"),
])
def test_unsupported_features_fail_explicitly(convert_rule, field, value):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        convert_rule({"selection": {field: value}, "condition": "selection"})


def test_single_character_wildcard_fails_explicitly(convert_rule):
    with pytest.raises(SigmaValueError, match="Single-character wildcard"):
        convert_rule({"selection": {"name": "a?b"}, "condition": "selection"})


def test_keyword_search_uses_native_unfielded_search(convert_rule):
    assert convert_rule({"selection": ["keyword"], "condition": "selection"}) == ["'keyword'"]


def test_errors_can_be_collected():
    from sigma.backends.scanner import ScannerBackend
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml("""
title: Unsupported regex
logsource: {product: test}
detection:
  selection:
    name|re: '(?=unsupported)'
  condition: selection
""")
    backend = ScannerBackend(collect_errors=True)
    assert backend.convert(collection) == []
    assert len(backend.errors) == 1
    assert isinstance(backend.errors[0][1], SigmaFeatureNotSupportedByBackendError)


def test_base64_transformation_uses_pysigma(convert_rule):
    assert convert_rule({"selection": {"name|base64": "admin"}, "condition": "selection"}) == [
        "name = 'YWRtaW4='"
    ]


@pytest.mark.parametrize("field, value, alternatives", [
    (
        "name|base64offset|contains", "admin",
        "name = '*YWRtaW*' or name = '*FkbWlu*' or name = '*hZG1pb*'",
    ),
    (
        "name|contains|windash", "-test",
        "name = '*-test*' or name = '*/test*' or name = '*–test*' or name = '*—test*' or name = '*―test*'",
    ),
])
def test_negated_expansion_groups_all_alternatives(convert_rule, field, value, alternatives):
    assert convert_rule({
        "selection": {"eventName": "test"},
        "filter": {field: value},
        "condition": "selection and not filter",
    }) == [f"eventName = 'test' and not ({alternatives})"]


def test_unexpanded_placeholder_fails(convert_rule):
    from sigma.exceptions import SigmaPlaceholderError

    with pytest.raises(SigmaPlaceholderError, match="unhandled placeholder"):
        convert_rule({"selection": {"name|expand": "%unconfigured%"}, "condition": "selection"})


def test_correlations_fail_explicitly():
    from sigma.backends.scanner import ScannerBackend
    from sigma.collection import SigmaCollection

    rules = SigmaCollection.from_yaml("""
title: Base
name: base_rule
logsource: {product: test}
detection:
  selection: {name: value}
  condition: selection
---
title: Count
correlation:
  type: event_count
  rules: [base_rule]
  group-by: [user]
  timespan: 5m
  condition: {gte: 5}
""")
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="correlation"):
        ScannerBackend().convert(rules)
