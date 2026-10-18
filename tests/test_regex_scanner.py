import pytest

from sigma.exceptions import SigmaFeatureNotSupportedByBackendError


@pytest.mark.parametrize("modifier, pattern, literal", [
    ("re", "a.*b", "/a.*b/"),
    ("re|i", "ADMIN", "/ADMIN/i"),
    ("re|m|s", "^a.b$", "/^a.b$/ms"),
    ("re", r"https://host/\d+", r"/https:\/\/host\/\d+/"),
    ("re", r"a\/b", r"/a\/b/"),
    ("re", r"a\\/b", r"/a\\\/b/"),
    ("re", "a\nb", r"/a\u000ab/"),
    ("re", r"\Aadmin\Z", r"/\Aadmin\z/"),
    ("re", r"literal\\Z", r"/literal\\Z/"),
])
def test_regex_literal(convert_rule, modifier, pattern, literal):
    assert convert_rule({"selection": {f"name|{modifier}": pattern}, "condition": "selection"}) == [
        f'* | eval _sigma_regex_0 = coalesce(regex.is_match(`name`, {literal}), false)'
        ' | where _sigma_regex_0 = "true"'
    ]


def test_regex_or_keeps_nonregex_branch(convert_rule):
    assert convert_rule({
        "regex": {"message|re": "error"},
        "plain": {"status": 500},
        "condition": "regex or plain",
    }) == [
        '* | eval _sigma_regex_0 = coalesce(regex.is_match(`message`, /error/), false)'
        ' | where (_sigma_regex_0 = "true" or status = 500)'
    ]


def test_regex_index_and_native_filters_stay_before_eval(convert_rule):
    assert convert_rule({
        "scope": {"@index": "cloudtrail", "eventSource": "iam.amazonaws.com"},
        "regex": {"userIdentity.arn|re": "role/.+"},
        "condition": "scope and not regex",
    }) == [
        "@index=cloudtrail and eventSource = 'iam.amazonaws.com'"
        r' | eval _sigma_regex_0 = coalesce(regex.is_match(`userIdentity.arn`, /role\/.+/), false)'
        ' | where not _sigma_regex_0 = "true"'
    ]


def test_regex_negated_or_and_reserved_scalar_field(convert_rule):
    assert convert_rule({
        "regex": {"true|re": "error"},
        "plain": {"status": 500},
        "condition": "not (regex or plain)",
    }) == [
        '* | eval _sigma_regex_0 = coalesce(regex.is_match(`true`, /error/), false)'
        ' | where not (_sigma_regex_0 = "true" or status = 500)'
    ]


def test_regex_temporary_fields_do_not_overwrite_rule_fields(convert_rule):
    result = convert_rule({
        "selection": {"_sigma_regex_0": "keep", "name|re": ["first", "second"]},
        "condition": "selection",
    })[0]
    assert result.startswith("_sigma_regex_0 = 'keep' | eval _sigma_regex_1 = ")
    assert ', _sigma_regex_2 = ' in result
    assert result.endswith(' | where (_sigma_regex_1 = "true" or _sigma_regex_2 = "true")')


def test_regex_state_does_not_leak_between_conditions(convert_rule):
    result = convert_rule({
        "selection": {"name|re": "error"},
        "condition": ["selection", "not selection"],
    })
    assert all('_sigma_regex_0 =' in query and '_sigma_regex_1' not in query for query in result)


@pytest.mark.parametrize("pattern", [r"a(?=b)", r"a(?!b)", r"(?<=a)b", r"(a)\1"])
def test_nonportable_regex_rejected(convert_rule, pattern):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="Scanner regex"):
        convert_rule({"selection": {"name|re": pattern}, "condition": "selection"})


def test_index_branch_not_silently_relocated(convert_rule):
    with pytest.raises(SigmaFeatureNotSupportedByBackendError, match="index selection"):
        convert_rule({
            "selection": {"@index": "first"},
            "regex": {"name|re": "error"},
            "condition": "selection or regex",
        })
