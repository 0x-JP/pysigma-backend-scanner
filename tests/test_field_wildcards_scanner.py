import pytest

from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline

from sigma.backends.scanner import ScannerBackend


@pytest.mark.parametrize("field, value, expected", [
    ("*name", "Jackson", "*name = 'Jackson'"),
    ("request.*.status", 500, "request.*.status = 500"),
    ("request.**.status|gte", 500, "request.**.status >= 500"),
    ("pet_kinds[*]", "fish", "pet_kinds[*] = 'fish'"),
    ("pet_kinds[**]|contains", "fish", "pet_kinds[**] = '*fish*'"),
    ("request.*|exists", True, "request.* = *"),
    ("request.*|exists", False, "not request.* = *"),
    ("field with spaces.*", "value", "`field with spaces.*` = 'value'"),
    (r"literal\*", "value", r"`literal\*` = 'value'"),
    (r"parent\child.*", "value", r"`parent\\child.*` = 'value'"),
    ("field`name.*", "value", r"`field\`name.*` = 'value'"),
])
def test_field_patterns(convert_rule, field, value, expected):
    assert convert_rule({"selection": {field: value}, "condition": "selection"}) == [expected]


def test_pipeline_can_map_to_array_pattern(convert_rule):
    pipeline = ProcessingPipeline.from_dict({
        "name": "Array mapping", "priority": 100,
        "transformations": [{"id": "fields", "type": "field_name_mapping",
                             "mapping": {"permission": "authorizationInfo[*].permission"}}],
    })
    assert convert_rule({"selection": {"permission": "read"}, "condition": "selection"}, pipeline) == [
        "authorizationInfo[*].permission = 'read'"
    ]


def test_wildcard_prefilter_before_scalar_eval(convert_rule):
    result = convert_rule({
        "selection": {"request.*.status": 500}, "regex": {"name|re": "error"},
        "condition": "selection and regex",
    })[0]
    assert result.startswith("request.*.status = 500 | eval ")


@pytest.mark.parametrize("field, value", [
    ("request.*|re", "error"),
    ("request.*", None),
    ("request.*|fieldref", "other"),
])
def test_scalar_field_patterns_rejected(convert_rule, field, value):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="[Ww]ildcard"):
        convert_rule({"selection": {field: value}, "condition": "selection"})


def test_postfilter_cannot_match_generated_columns(convert_rule):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="before eval"):
        convert_rule({
            "wildcard": {"**": "true"}, "regex": {"name|re": "error"},
            "condition": "wildcard or regex",
        })


def test_scoped_wildcard_postfilter_does_not_match_generated_columns(convert_rule):
    result = convert_rule({
        "wildcard": {"request.*.status": 500}, "regex": {"name|re": "error"},
        "condition": "wildcard or regex",
    })[0]
    assert result.endswith(' | where (request.*.status = 500 or _sigma_regex_0 = "true")')


@pytest.mark.parametrize("pattern, field, matches", [
    ("request.*.status", "request.first.status", True),
    ("request.*.status", "request.first.second.status", False),
    ("request.**.status", "request.first.second.status", True),
    ("pet[*]", "pet[0]", True),
    ("pet[*]", "pet[0][1]", False),
    (r"literal\*", "literal*", True),
    (r"literal\*", "literal_other", False),
])
def test_field_pattern_matching_follows_scanner_boundaries(pattern, field, matches):
    assert ScannerBackend.field_pattern_matches(pattern, field) is matches


def test_scalar_reference_operand_patterns_rejected():
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="single field"):
        ScannerBackend().scalar_field("request.*")


def test_literal_asterisk_is_not_a_scalar_pattern(convert_rule):
    assert convert_rule({"selection": {r"literal\*": None}, "condition": "selection"}) == [
        r'* | eval _sigma_null_0 = `literal\*` == null | where _sigma_null_0 = "true"'
    ]


def test_wildcard_list_negation_preserves_grouping(convert_rule):
    assert convert_rule({
        "selection": {"request.*.status": [400, 500]}, "condition": "not selection",
    }) == ["not (request.*.status = 400 or request.*.status = 500)"]
