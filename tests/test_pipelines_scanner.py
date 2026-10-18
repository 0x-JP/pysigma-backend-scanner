import pytest
from sigma.exceptions import SigmaConfigurationError
from sigma.processing.pipeline import ProcessingPipeline


def index_pipeline(value):
    return ProcessingPipeline.from_dict({
        "name": "Index selection",
        "priority": 100,
        "transformations": [{"id": "index", "type": "add_condition", "conditions": {"@index": value}}],
    })


@pytest.mark.parametrize("index", ["cloudtrail", "my-index", "my_index.v2", '{ 00000000-0000-0000-0000-000000000000 | "cloudtrail" }'])
def test_index_selector_is_not_a_field_string(convert_rule, index):
    assert convert_rule({"selection": {"name": "one"}, "condition": "selection"}, index_pipeline(index)) == [
        f"@index={index} and name = 'one'"
    ]


@pytest.mark.parametrize("index", ["*", "cloudtrail or *", "foo|stats", "", "a'", '{ invalid | "alias" }'])
def test_invalid_index_rejected(convert_rule, index):
    with pytest.raises(SigmaConfigurationError):
        convert_rule({"selection": {"name": "one"}, "condition": "selection"}, index_pipeline(index))


def test_index_applies_to_entire_disjunction(convert_rule):
    assert convert_rule({"selection": {"name": ["one", "two"]}, "condition": "selection"}, index_pipeline("logs")) == [
        "@index=logs and (name = 'one' or name = 'two')"
    ]


def test_field_mapping_uses_standard_pipeline(convert_rule):
    pipeline = ProcessingPipeline.from_dict({
        "name": "Custom schema",
        "priority": 100,
        "transformations": [{"id": "fields", "type": "field_name_mapping", "mapping": {"Image": "process.executable"}}],
    })
    assert convert_rule({"selection": {"Image|endswith": "cmd.exe"}, "condition": "selection"}, pipeline) == [
        "process.executable = '*cmd.exe'"
    ]


def test_multiple_indexes_remain_selectors(convert_rule):
    assert convert_rule({"selection": {"name": "one"}, "condition": "selection"}, index_pipeline(["logs", "archive"])) == [
        "(@index=logs or @index=archive) and name = 'one'"
    ]


@pytest.mark.parametrize("index", [123, True])
def test_index_type_must_be_string(convert_rule, index):
    with pytest.raises(SigmaConfigurationError, match="plain strings"):
        convert_rule({"selection": {"name": "one"}, "condition": "selection"}, index_pipeline(index))
