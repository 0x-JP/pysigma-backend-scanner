import re

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import TextQueryBackend
from sigma.exceptions import SigmaConfigurationError, SigmaFeatureNotSupportedByBackendError
from sigma.types import (
    CompareOperators,
    SigmaCasedString,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaRegularExpression,
    SigmaString,
)


class ScannerBackend(TextQueryBackend):
    name = "Scanner"
    formats = {"default": "Scanner query"}
    requires_pipeline = False
    precedence = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression = "({expr})"
    token_separator = " "
    and_token = "and"
    or_token = "or"
    not_token = "not"
    eq_token = " = "
    field_quote = "`"
    field_quote_pattern = re.compile(
        r"^(?!(?:and|or|not|let|from|in)\Z)[a-zA-Z_@%*][a-zA-Z0-9_@%.*\[\]]*\Z",
        re.IGNORECASE,
    )
    field_quote_pattern_negation = True
    field_escape = "\\"
    field_escape_quote = True
    field_escape_pattern = re.compile(r"\\(?!\*)")
    str_quote = "'"
    escape_char = "\\"
    wildcard_multi = "*"
    wildcard_single = None
    add_escaped = "\\*"
    filter_chars = ""
    case_sensitive_match_expression = "{field} = {value}"
    compare_op_expression = "{field} {operator} {value}"
    compare_operators = {
        CompareOperators.LT: "<",
        CompareOperators.LTE: "<=",
        CompareOperators.GT: ">",
        CompareOperators.GTE: ">=",
    }
    field_exists_expression = "{field} = *"
    field_not_exists_expression = "not {field} = *"
    bool_values = {True: None, False: None}

    @staticmethod
    def needs_eval(leaf):
        return isinstance(getattr(leaf, "value", None), (SigmaRegularExpression, SigmaNull, SigmaFieldReference))

    def convert_condition(self, cond, state):
        try:
            if "scanner" not in state.processing_state:
                leaves = list(self.condition_leaves(cond))
                state.processing_state["scanner"] = {
                    "fields": {leaf.field for leaf in leaves if hasattr(leaf, "field")} | {
                        leaf.value.field for leaf in leaves
                        if isinstance(getattr(leaf, "value", None), SigmaFieldReference)
                    },
                    "eval": [],
                    "aliases": [],
                }
                if any(self.needs_eval(leaf) for leaf in leaves):
                    return self.convert_scalar_query(cond, state)
            return super().convert_condition(cond, state)
        except NotImplementedError as error:
            raise SigmaFeatureNotSupportedByBackendError(str(error)) from error

    @classmethod
    def condition_leaves(cls, cond):
        if isinstance(cond, (ConditionAND, ConditionOR, ConditionNOT)):
            for child in cond.args:
                yield from cls.condition_leaves(child)
        else:
            yield cond

    @classmethod
    def conjuncts(cls, cond):
        if isinstance(cond, ConditionAND):
            for child in cond.args:
                yield from cls.conjuncts(child)
        else:
            yield cond

    def convert_scalar_query(self, cond, state):
        prefilters = []
        postfilters = []
        postfilter_patterns = []
        for part in self.conjuncts(cond):
            leaves = list(self.condition_leaves(part))
            has_scalar = any(self.needs_eval(leaf) for leaf in leaves)
            if has_scalar and any(getattr(leaf, "field", None) == "@index" for leaf in leaves):
                raise SigmaFeatureNotSupportedByBackendError(
                    "Scalar queries require index selection outside OR/NOT branches containing scalar predicates"
                )
            if has_scalar and any(isinstance(leaf, ConditionValueExpression) for leaf in leaves):
                raise SigmaFeatureNotSupportedByBackendError(
                    "Unfielded searches cannot share an OR/NOT branch with scalar predicates: "
                    "eval columns would change the searched event"
                )
            if has_scalar:
                postfilter_patterns.extend(
                    leaf.field for leaf in leaves
                    if self.has_field_wildcard(getattr(leaf, "field", ""))
                )
            converted = self.convert_condition(part, state)
            if isinstance(part, (ConditionAND, ConditionOR)):
                converted = self.group_expression.format(expr=converted)
            (postfilters if has_scalar else prefilters).append(converted)
        prefilter = " and ".join(prefilters) or "*"
        for pattern in postfilter_patterns:
            if any(self.field_pattern_matches(pattern, alias) for alias in state.processing_state["scanner"]["aliases"]):
                raise SigmaFeatureNotSupportedByBackendError(
                    "Wildcard postfilter would match generated eval columns; filter it before eval"
                )
        assignments = ", ".join(state.processing_state["scanner"]["eval"])
        return f"{prefilter} | eval {assignments} | where {' and '.join(postfilters)}"

    def convert_condition_field_eq_val_re(self, cond, state):
        pattern = str(cond.value.regexp)
        if re.search(r"(?<!\\)(?:\\\\)*(?:\(\?(?:[=!]|<[=!]|P=|>)|\\[1-9])", pattern):
            raise SigmaFeatureNotSupportedByBackendError(
                "Scanner regex does not support lookaround, backreferences or atomic groups"
            )
        pattern = re.sub(
            r"(\\*)/",
            lambda match: match[1] + (r"\/" if len(match[1]) % 2 == 0 else "/"),
            pattern,
        )
        pattern = re.sub(r"(?<!\\)((?:\\\\)*)\\Z", lambda match: match[1] + r"\z", pattern)
        pattern = self.escape_controls(pattern)
        flags = "".join(sorted(cond.value.sigma_to_re_flag[flag] for flag in cond.value.flags))
        field = self.scalar_field(cond.field)
        return self.scalar_predicate(f"coalesce(regex.is_match({field}, /{pattern}/{flags}), false)", "regex", state)

    def scalar_field(self, field_name):
        if self.has_field_wildcard(field_name):
            raise SigmaFeatureNotSupportedByBackendError(
                "Scalar expressions require a single field, not a wildcard field pattern"
            )
        field = self.escape_and_quote_field(field_name)
        return field if field.startswith("`") else f"`{field}`"

    def scalar_predicate(self, expression, kind, state):
        context = state.processing_state["scanner"]
        number = len(context["eval"])
        alias = f"_sigma_{kind}_{number}"
        while alias in context["fields"]:
            number += 1
            alias = f"_sigma_{kind}_{number}"
        context["fields"].add(alias)
        context["aliases"].append(alias)
        context["eval"].append(f"{alias} = {expression}")
        return f'{alias} = "true"'

    def convert_condition_field_eq_val_null(self, cond, state):
        return self.scalar_predicate(f"{self.scalar_field(cond.field)} == null", "null", state)

    def convert_condition_field_eq_field(self, cond, state):
        if cond.value.starts_with or cond.value.ends_with:
            raise SigmaFeatureNotSupportedByBackendError("Scanner field reference substring matching is not implemented")
        left = self.scalar_field(cond.field)
        right = self.scalar_field(cond.value.field)
        expression = f"{left} != null and {right} != null and {left} == {right}"
        return self.scalar_predicate(expression, "fieldref", state)

    def convert_condition_val_str(self, cond, state):
        return self.convert_value_str(cond.value, state)

    def convert_correlation_rule(self, *args, **kwargs):
        raise SigmaFeatureNotSupportedByBackendError("Scanner correlation conversion is not implemented")

    def convert_condition_not(self, cond, state):
        arg = cond.args[0]
        if isinstance(arg, ConditionFieldEqualsValueExpression) and isinstance(arg.value, SigmaExpansion):
            return self.not_token + self.token_separator + self.convert_condition_group(arg, state)
        return super().convert_condition_not(cond, state)

    def escape_and_quote_field(self, field_name):
        if "?" in field_name:
            raise SigmaFeatureNotSupportedByBackendError("Scanner does not document ? as a field wildcard")
        return self.escape_controls(super().escape_and_quote_field(field_name))

    @staticmethod
    def has_field_wildcard(field_name):
        return "*" in field_name.replace(r"\*", "")

    @staticmethod
    def field_pattern_matches(pattern, field_name):
        expression = "".join(
            ".*" if part == "**" else r"[^.\[\]]*" if part == "*"
            else re.escape(part.replace(r"\*", "*"))
            for part in re.split(r"(\\\*|\*{1,2})", pattern)
        )
        return re.fullmatch(expression, field_name, re.DOTALL) is not None

    @staticmethod
    def escape_controls(value):
        return re.sub(r"[\x00-\x1f]", lambda match: f"\\u{ord(match.group()):04x}", value)

    def convert_value_str(self, value, state):
        quote = '"' if isinstance(value, SigmaCasedString) else "'"
        converted = value.convert("\\", "*", None, quote + "\\*", "")
        return quote + self.escape_controls(converted) + quote

    def convert_condition_field_compare_op_val(self, cond, state):
        if cond.value.op not in self.compare_operators:
            raise SigmaFeatureNotSupportedByBackendError("Unsupported numeric comparison operator")
        return super().convert_condition_field_compare_op_val(cond, state)

    def convert_condition_field_eq_val_str(self, cond, state):
        if cond.field == "@index":
            value = str(cond.value)
            if cond.value.contains_special():
                raise SigmaConfigurationError("Scanner index selectors cannot contain wildcards")
            if re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", value):
                return "@index=" + value
            if re.fullmatch(
                r'\{\s*[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\s*\|\s*"(?:[^"\\\x00-\x1f]|\\["\\])*"\s*\}',
                value,
            ):
                return "@index=" + value
            raise SigmaConfigurationError("Use an index alias or Scanner's { UUID | \"alias\" } specifier")
        return super().convert_condition_field_eq_val_str(cond, state)

    def convert_condition_field_eq_val(self, cond, state):
        if cond.field == "@index":
            if type(cond.value) is not SigmaString:
                raise SigmaConfigurationError("Scanner index selectors must be plain strings")
            return self.convert_condition_field_eq_val_str(cond, state)
        return super().convert_condition_field_eq_val(cond, state)

    def convert_condition_field_eq_val_cidr(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Scanner CIDR matching is not implemented")
