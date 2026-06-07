"""
OverflowGuard - Integer Overflow Detection Engine.

AST-based analyzer built on pycparser.
"""
from __future__ import annotations

from dataclasses import dataclass
from pycparser import c_ast, c_parser
from pycparser.c_parser import ParseError

from analysis_config import (
    classify_binary,
    classify_function,
    RISK_PRIORITY,
)


@dataclass
class Finding:
    line_number: int
    line_content: str
    function_name: str
    expression: str
    cwe: str
    category: str
    type: str
    risk_type: str
    risk: str
    severity: str
    certainty_type: str
    confidence: int
    reason: str
    suggestion: str


@dataclass(frozen=True)
class GuardSignature:
    kind: str
    operands: tuple[str, ...]


@dataclass
class FlowState:
    active_guards: frozenset[GuardSignature]
    tainted_vars: set[str]
    input_params: set[str]
    value_env: dict[str, "SymbolicValue"]
    function_name: str | None = None


@dataclass(frozen=True)
class FunctionSummary:
    returns_user_input: bool


@dataclass(frozen=True)
class SymbolicValue:
    kind: str
    value: int | None = None

    @property
    def is_constant(self) -> bool:
        return self.kind == "CONST" and self.value is not None

    @property
    def is_unbounded(self) -> bool:
        return self.kind == "UNBOUNDED"


@dataclass(frozen=True)
class AnalysisDecision:
    cwe: str
    category: str
    type: str
    risk_type: str
    severity: str
    certainty_type: str
    confidence: int
    reason: str
    suggestion: str
    expression: str
    function_name: str


_COMPARISON_OPS = {"<", "<=", ">", ">=", "==", "!="}
_LOGICAL_OPS = {"&&", "||"}

_CERTAINTY_PRIORITY = {
    "POTENTIAL": 0,
    "DEFINITE": 1,
}

_PROLOG = """typedef unsigned long size_t;
typedef int FILE;
"""
_PROLOG_LINE_OFFSET = len(_PROLOG.splitlines())
INT_MIN = -(2**31)
INT_MAX = 2**31 - 1
SIZE_MAX = 2**64 - 1

_UNBOUNDED = SymbolicValue("UNBOUNDED")
_UNKNOWN = SymbolicValue("UNKNOWN")


def _const_value(value: int) -> SymbolicValue:
    return SymbolicValue("CONST", value)


def _is_within_int32(value: int) -> bool:
    return INT_MIN <= value <= INT_MAX


def _parse_int_literal(text: str) -> int | None:
    try:
        return int(text, 0)
    except ValueError:
        return None


def _value_to_int(node: c_ast.Node | None) -> SymbolicValue:
    if node is None:
        return _UNKNOWN
    if isinstance(node, c_ast.Constant) and node.type == "int":
        parsed = _parse_int_literal(node.value)
        if parsed is None:
            return _UNKNOWN
        return _const_value(parsed)
    return _UNKNOWN


def _strip_comments(source: str) -> str:
    """Remove C comments while preserving line structure."""
    output: list[str] = []
    i = 0
    in_line_comment = False
    in_block_comment = False

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                output.append(ch)
            else:
                output.append(" ")
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                output.extend("  ")
                i += 1
            elif ch == "\n":
                output.append("\n")
            else:
                output.append(" ")
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                output.extend("  ")
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                output.extend("  ")
                i += 1
            else:
                output.append(ch)

        i += 1

    return "".join(output)


def _blank_preprocessor_lines(source: str) -> str:
    lines = source.splitlines()
    return "\n".join("" if line.lstrip().startswith("#") else line for line in lines)


def _prepare_source(source: str) -> str:
    return _PROLOG + _blank_preprocessor_lines(_strip_comments(source))


def _line_content(lines: list[str], line_number: int) -> str:
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def _simple_name(node: c_ast.Node | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, c_ast.ID):
        return node.name
    if isinstance(node, c_ast.Cast):
        return _simple_name(node.expr)
    return None


def _is_constant(node: c_ast.Node | None) -> bool:
    return isinstance(node, c_ast.Constant)


def _collect_ids(node: c_ast.Node | None) -> set[str]:
    if node is None:
        return set()
    names: set[str] = set()
    if isinstance(node, c_ast.ID):
        names.add(node.name)
        return names
    if isinstance(node, c_ast.Cast):
        return _collect_ids(node.expr)
    if isinstance(node, c_ast.ExprList):
        for expr in node.exprs or []:
            names.update(_collect_ids(expr))
        return names
    if isinstance(node, c_ast.UnaryOp):
        return _collect_ids(node.expr)
    if isinstance(node, c_ast.BinaryOp):
        return _collect_ids(node.left) | _collect_ids(node.right)
    if isinstance(node, c_ast.FuncCall):
        names.update(_collect_ids(node.name))
        names.update(_collect_ids(node.args))
        return names
    if isinstance(node, c_ast.TernaryOp):
        return _collect_ids(node.cond) | _collect_ids(node.iftrue) | _collect_ids(node.iffalse)
    for _, child in node.children():
        if isinstance(child, c_ast.Node):
            names.update(_collect_ids(child))
    return names


def _contains_sizeof(node: c_ast.Node | None) -> bool:
    if node is None:
        return False
    if isinstance(node, c_ast.UnaryOp) and node.op == "sizeof":
        return True
    if isinstance(node, c_ast.Cast):
        return _contains_sizeof(node.expr)
    if isinstance(node, c_ast.BinaryOp):
        return _contains_sizeof(node.left) or _contains_sizeof(node.right)
    if isinstance(node, c_ast.ExprList):
        return any(_contains_sizeof(expr) for expr in node.exprs or [])
    if isinstance(node, c_ast.FuncCall):
        return _contains_sizeof(node.args)
    if isinstance(node, c_ast.TernaryOp):
        return _contains_sizeof(node.cond) or _contains_sizeof(node.iftrue) or _contains_sizeof(node.iffalse)
    return any(_contains_sizeof(child) for _, child in node.children() if isinstance(child, c_ast.Node))


def _flatten_mul_terms(node: c_ast.Node | None) -> list[c_ast.Node]:
    if node is None:
        return []
    if isinstance(node, c_ast.BinaryOp) and node.op == "*":
        return _flatten_mul_terms(node.left) + _flatten_mul_terms(node.right)
    return [node]


def _function_call_args(node: c_ast.FuncCall) -> list[c_ast.Node]:
    args = node.args
    if isinstance(args, c_ast.ExprList):
        return [expr for expr in args.exprs or [] if isinstance(expr, c_ast.Node)]
    if isinstance(args, c_ast.Node):
        return [args]
    return []


def _function_param_names(node: c_ast.FuncDef) -> set[str]:
    params: set[str] = set()
    decl = getattr(node, "decl", None)
    func_type = getattr(decl, "type", None)
    args = getattr(func_type, "args", None)
    for param in getattr(args, "params", []) or []:
        if isinstance(param, c_ast.Decl):
            params.add(param.name)
    return params


def _ordered_function_param_names(node: c_ast.FuncDef) -> list[str]:
    params: list[str] = []
    decl = getattr(node, "decl", None)
    func_type = getattr(decl, "type", None)
    args = getattr(func_type, "args", None)
    for param in getattr(args, "params", []) or []:
        if isinstance(param, c_ast.Decl) and param.name:
            params.append(param.name)
    return params


def _contains_function_call(node: c_ast.Node | None, function_name: str) -> bool:
    if node is None:
        return False
    if isinstance(node, c_ast.FuncCall):
        return _simple_name(node.name) == function_name or _contains_function_call(node.args, function_name)
    for _, child in node.children():
        if isinstance(child, c_ast.Node) and _contains_function_call(child, function_name):
            return True
    return False


def _returning_id(node: c_ast.Node | None) -> bool:
    if node is None:
        return False
    if isinstance(node, c_ast.Return):
        return isinstance(node.expr, c_ast.ID)
    if isinstance(node, c_ast.Compound):
        return any(_returning_id(item) for item in node.block_items or [])
    if isinstance(node, c_ast.If):
        return _returning_id(node.iftrue) or _returning_id(node.iffalse)
    for _, child in node.children():
        if isinstance(child, c_ast.Node) and _returning_id(child):
            return True
    return False


def _summarize_function(node: c_ast.FuncDef) -> FunctionSummary:
    # Lightweight heuristic: if a function uses scanf and returns an ID, treat its result as user-input driven.
    returns_user_input = _contains_function_call(node.body, "scanf") and _returning_id(node.body)
    return FunctionSummary(returns_user_input=returns_user_input)


def _scan_target_names(args: c_ast.Node | None) -> set[str]:
    return _collect_ids(args)


def _assign_target_names(node: c_ast.Node | None) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, c_ast.ID):
        return {node.name}
    if isinstance(node, c_ast.UnaryOp):
        return _collect_ids(node.expr)
    return _collect_ids(node)


def _function_call_name(node: c_ast.Node | None) -> str | None:
    if isinstance(node, c_ast.FuncCall):
        return _simple_name(node.name)
    return None


def _function_def_name(node: c_ast.FuncDef) -> str | None:
    decl = getattr(node, "decl", None)
    return getattr(decl, "name", None)


def _expr_to_source(node: c_ast.Node | None) -> str:
    if node is None:
        return ""
    if isinstance(node, c_ast.Constant):
        return node.value
    if isinstance(node, c_ast.ID):
        return node.name
    if isinstance(node, c_ast.BinaryOp):
        return f"({_expr_to_source(node.left)} {node.op} {_expr_to_source(node.right)})"
    if isinstance(node, c_ast.UnaryOp):
        if node.op == "sizeof":
            if isinstance(node.expr, c_ast.Typename):
                decl = getattr(node.expr, "type", None)
                type_decl = getattr(decl, "type", None)
                names = getattr(type_decl, "names", [])
                inner = " ".join(names) if names else "?"
            else:
                inner = _expr_to_source(node.expr)
            return f"sizeof({inner})"
        return f"({node.op}{_expr_to_source(node.expr)})"
    if isinstance(node, c_ast.Cast):
        return _expr_to_source(node.expr)
    if isinstance(node, c_ast.FuncCall):
        args = ", ".join(_expr_to_source(arg) for arg in _function_call_args(node))
        return f"{_simple_name(node.name) or 'call'}({args})"
    if isinstance(node, c_ast.ExprList):
        return ", ".join(_expr_to_source(expr) for expr in node.exprs or [])
    return _simple_name(node) or node.__class__.__name__


def _symbolic_to_string(value: SymbolicValue) -> str:
    if value.kind == "CONST" and value.value is not None:
        return str(value.value)
    return value.kind


def _combine_values(op: str, left: SymbolicValue, right: SymbolicValue) -> tuple[SymbolicValue, bool]:
    if left.is_constant and right.is_constant:
        assert left.value is not None and right.value is not None
        try:
            if op == "+":
                result = left.value + right.value
            elif op == "-":
                result = left.value - right.value
            elif op == "*":
                result = left.value * right.value
            else:
                return _UNKNOWN, False
        except Exception:
            return _UNKNOWN, True
        if _is_within_int32(result):
            return _const_value(result), False
        return _UNKNOWN, True

    if op == "+":
        if left.is_constant and left.value == 0:
            return right, False
        if right.is_constant and right.value == 0:
            return left, False
    elif op == "-":
        if right.is_constant and right.value == 0:
            return left, False
    elif op == "*":
        if (left.is_constant and left.value == 0) or (right.is_constant and right.value == 0):
            return _const_value(0), False
        if left.is_constant and left.value == 1:
            return right, False
        if right.is_constant and right.value == 1:
            return left, False

    if left.is_unbounded or right.is_unbounded:
        return _UNBOUNDED, False
    return _UNKNOWN, False


def _value_is_constant_within_range(value: SymbolicValue) -> bool:
    return value.is_constant and value.value is not None and _is_within_int32(value.value)


def _safe_allocation_constant(node: c_ast.Node | None, state: FlowState) -> bool:
    value, overflow = _eval_expression(node, state)
    return value.is_constant and not overflow and value.value is not None and value.value >= 0


def _contains_unbounded(node: c_ast.Node | None, state: FlowState) -> bool:
    if node is None:
        return False
    value, _ = _eval_expression(node, state)
    return value.is_unbounded


def _eval_expression(node: c_ast.Node | None, state: FlowState) -> tuple[SymbolicValue, bool]:
    if node is None:
        return _UNKNOWN, False

    if isinstance(node, c_ast.Constant):
        if node.type == "int":
            parsed = _parse_int_literal(node.value)
            if parsed is None:
                return _UNKNOWN, False
            return _const_value(parsed), False
        return _UNKNOWN, False

    if isinstance(node, c_ast.ID):
        if node.name == "INT_MAX":
            return _const_value(INT_MAX), False
        if node.name == "INT_MIN":
            return _const_value(INT_MIN), False
        if node.name == "SIZE_MAX":
            return _const_value(SIZE_MAX), False
        if node.name in state.value_env:
            return state.value_env[node.name], False
        if node.name in state.input_params or node.name in state.tainted_vars:
            return _UNBOUNDED, False
        return _UNBOUNDED, False

    if isinstance(node, c_ast.Cast):
        return _eval_expression(node.expr, state)

    if isinstance(node, c_ast.UnaryOp):
        if node.op == "+":
            return _eval_expression(node.expr, state)
        if node.op == "-":
            inner, overflow = _eval_expression(node.expr, state)
            if inner.is_constant and inner.value is not None:
                result = -inner.value
                if _is_within_int32(result):
                    return _const_value(result), overflow
                return _UNKNOWN, True
            return inner, overflow
        if node.op == "sizeof":
            return _const_value(4), False
        return _UNBOUNDED, False

    if isinstance(node, c_ast.BinaryOp):
        left, left_overflow = _eval_expression(node.left, state)
        right, right_overflow = _eval_expression(node.right, state)
        combined, overflow = _combine_values(node.op, left, right)
        return combined, overflow or left_overflow or right_overflow

    if isinstance(node, c_ast.FuncCall):
        function_name = _simple_name(node.name) or ""
        if function_name == "scanf":
            return _UNBOUNDED, False
        if function_name in {"malloc", "calloc", "realloc"}:
            return _UNBOUNDED, False
        return _UNBOUNDED, False

    if isinstance(node, c_ast.ExprList):
        values = [_eval_expression(expr, state)[0] for expr in node.exprs or []]
        return (values[-1] if values else _UNKNOWN), False

    if isinstance(node, c_ast.TernaryOp):
        cond_val, cond_overflow = _eval_expression(node.cond, state)
        true_val, true_overflow = _eval_expression(node.iftrue, state)
        false_val, false_overflow = _eval_expression(node.iffalse, state)
        if true_val == false_val:
            return true_val, cond_overflow or true_overflow or false_overflow
        return _UNBOUNDED, cond_overflow or true_overflow or false_overflow

    return _UNBOUNDED, False


def _sorted_pair(left: str, right: str) -> tuple[str, str]:
    return tuple(sorted((left, right)))


def _binary_decision(node: c_ast.BinaryOp, state: FlowState) -> AnalysisDecision | None:
    left_value, left_overflow = _eval_expression(node.left, state)
    right_value, right_overflow = _eval_expression(node.right, state)
    left_name = _simple_name(node.left)
    right_name = _simple_name(node.right)
    expression = _expr_to_source(node)
    function_name = state.function_name or ""

    if node.op == "+":
        if _value_is_constant_within_range(left_value) and _value_is_constant_within_range(right_value):
            result = left_value.value + right_value.value  # type: ignore[operator]
            if _is_within_int32(result):
                return None
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_BOUNDARY_OVERFLOW",
                type="INTEGER_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="CRITICAL",
                certainty_type="DEFINITE",
                confidence=100,
                reason="Constant addition exceeds the representable range of signed int, resulting in undefined behavior (CWE-190).",
                suggestion="Check bounds before adding: if (x > INT_MAX - y) handle_error();",
                expression=expression,
                function_name=function_name,
            )
        if left_value.is_constant and left_value.value == 0:
            return None
        if right_value.is_constant and right_value.value == 0:
            return None
        if left_name == "INT_MAX" or right_name == "INT_MAX" or left_value.value == INT_MAX or right_value.value == INT_MAX:
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_BOUNDARY_OVERFLOW",
                type="INTEGER_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="CRITICAL",
                certainty_type="DEFINITE",
                confidence=100,
                reason="Integer addition involving INT_MAX may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
                suggestion="Check bounds before adding: if (x == INT_MAX) handle_error();",
                expression=expression,
                function_name=function_name,
            )
        if left_value.is_unbounded or right_value.is_unbounded or left_overflow or right_overflow:
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_ARITHMETIC_OVERFLOW",
                type="INTEGER_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="MEDIUM",
                certainty_type="POTENTIAL",
                confidence=_confidence_score_value(50, left_value, right_value, state),
                reason="Integer addition may exceed the representable range of signed int when applied to unbounded operands, resulting in undefined behavior (CWE-190).",
                suggestion="Validate bounds before addition and reject values that can exceed INT_MAX.",
                expression=expression,
                function_name=function_name,
            )
        return None

    if node.op == "-":
        if _value_is_constant_within_range(left_value) and _value_is_constant_within_range(right_value):
            result = left_value.value - right_value.value  # type: ignore[operator]
            if _is_within_int32(result):
                return None
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_BOUNDARY_OVERFLOW",
                type="INTEGER_UNDERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="CRITICAL",
                certainty_type="DEFINITE",
                confidence=100,
                reason="Constant subtraction exceeds the representable range of signed int, resulting in undefined behavior (CWE-190).",
                suggestion="Check bounds before subtracting: if (x == INT_MIN) handle_error();",
                expression=expression,
                function_name=function_name,
            )
        if right_value.is_constant and right_value.value == 0:
            return None
        if left_name == "INT_MIN" or left_value.value == INT_MIN:
            if (
                right_value.is_constant
                and right_value.value is not None
                and right_value.value > 0
            ) or right_value.is_unbounded or right_value.kind == "UNKNOWN":
                return AnalysisDecision(
                    cwe="CWE-190",
                    category="INTEGER_BOUNDARY_OVERFLOW",
                    type="INTEGER_UNDERFLOW",
                    risk_type="REAL_OVERFLOW_RISK",
                    severity="CRITICAL",
                    certainty_type="DEFINITE",
                    confidence=100,
                    reason="Integer subtraction from INT_MIN may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
                    suggestion="Check bounds before subtracting: if (x == INT_MIN) handle_error();",
                    expression=expression,
                    function_name=function_name,
                )
        if left_value.is_unbounded or right_value.is_unbounded or left_overflow or right_overflow:
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_ARITHMETIC_OVERFLOW",
                type="INTEGER_UNDERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="MEDIUM",
                certainty_type="POTENTIAL",
                confidence=_confidence_score_value(50, left_value, right_value, state),
                reason="Integer subtraction may exceed the representable range of signed int when applied to unbounded operands, resulting in undefined behavior (CWE-190).",
                suggestion="Validate bounds before subtraction and reject values that can fall below INT_MIN.",
                expression=expression,
                function_name=function_name,
            )
        return None

    if node.op == "*":
        if _value_is_constant_within_range(left_value) and _value_is_constant_within_range(right_value):
            result = left_value.value * right_value.value  # type: ignore[operator]
            if _is_within_int32(result):
                return None
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_ARITHMETIC_OVERFLOW",
                type="INTEGER_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="CRITICAL",
                certainty_type="DEFINITE",
                confidence=100,
                reason="Constant multiplication exceeds the representable range of signed int, resulting in undefined behavior (CWE-190).",
                suggestion="Guard multiplication with a range check before evaluating the product.",
                expression=expression,
                function_name=function_name,
            )
        if (left_value.is_constant and left_value.value in {0, 1}) or (right_value.is_constant and right_value.value in {0, 1}):
            return None
        if (left_value.is_constant and left_value.value is not None and abs(left_value.value) > 1 and (right_value.is_unbounded or right_value.kind == "UNKNOWN")) or (
            right_value.is_constant and right_value.value is not None and abs(right_value.value) > 1 and (left_value.is_unbounded or left_value.kind == "UNKNOWN")
        ):
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_ARITHMETIC_OVERFLOW",
                type="INTEGER_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="HIGH",
                certainty_type="POTENTIAL",
                confidence=_confidence_score_value(70, left_value, right_value, state),
                reason="Integer multiplication may exceed the representable range of signed int when one operand is unbounded, resulting in undefined behavior (CWE-190).",
                suggestion="Check multiplicative bounds before evaluating the product.",
                expression=expression,
                function_name=function_name,
            )
        if left_value.is_unbounded and right_value.is_unbounded:
            return AnalysisDecision(
                cwe="CWE-190",
                category="INTEGER_ARITHMETIC_OVERFLOW",
                type="INTEGER_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="HIGH",
                certainty_type="POTENTIAL",
                confidence=_confidence_score_value(70, left_value, right_value, state),
                reason="Integer multiplication of unbounded operands may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
                suggestion="Check multiplicative bounds before evaluating the product.",
                expression=expression,
                function_name=function_name,
            )
        return None

    return None


def _allocation_decision(node: c_ast.FuncCall, state: FlowState) -> AnalysisDecision | None:
    function_name = _simple_name(node.name)
    if function_name not in {"malloc", "calloc", "realloc"}:
        return None

    allocation_exprs = _function_call_args(node)
    if function_name == "calloc" and len(allocation_exprs) >= 2:
        size_expr = allocation_exprs[0]
        elem_expr = allocation_exprs[1]
        size_value, size_overflow = _eval_expression(size_expr, state)
        elem_value, elem_overflow = _eval_expression(elem_expr, state)
        size_safe = _value_is_constant_within_range(size_value) and not size_overflow
        elem_safe = _value_is_constant_within_range(elem_value) and not elem_overflow
        if size_safe and elem_safe and size_value.value is not None and elem_value.value is not None:
            product = size_value.value * elem_value.value
            if _is_within_int32(product) and product <= SIZE_MAX:
                return None
        if size_value.is_unbounded or elem_value.is_unbounded or size_overflow or elem_overflow:
            return AnalysisDecision(
                cwe="CWE-190",
                category="MEMORY_ALLOCATION_OVERFLOW",
                type="ALLOCATION_OVERFLOW",
                risk_type="REAL_OVERFLOW_RISK",
                severity="CRITICAL",
                certainty_type="POTENTIAL",
                confidence=95,
                reason="Multiplication in allocation size may wrap size_t, potentially causing an undersized heap allocation (CWE-190).",
                suggestion="Validate allocation operands before calling calloc.",
                expression=_expr_to_source(node),
                function_name=state.function_name or "",
            )
        return None

    if not allocation_exprs:
        return None

    expr = allocation_exprs[0]
    value, overflow = _eval_expression(expr, state)
    if value.is_constant and not overflow and value.value is not None and 0 <= value.value <= SIZE_MAX:
        return None

    if not _contains_unbounded(expr, state) and not _contains_binary_op(expr, "*"):
        return None

    if _contains_unbounded(expr, state) or _contains_binary_op(expr, "*"):
        return AnalysisDecision(
            cwe="CWE-190",
            category="MEMORY_ALLOCATION_OVERFLOW",
            type="ALLOCATION_OVERFLOW",
            risk_type="REAL_OVERFLOW_RISK",
            severity="CRITICAL",
            certainty_type="POTENTIAL",
            confidence=95,
            reason="Multiplication in allocation size may wrap size_t, potentially causing an undersized heap allocation (CWE-190).",
            suggestion="Validate allocation operands before calling the allocation routine.",
            expression=_expr_to_source(node),
            function_name=state.function_name or "",
        )

    return None


def _confidence_score_value(base: int, left_value: SymbolicValue, right_value: SymbolicValue, state: FlowState) -> int:
    score = base
    if left_value.is_unbounded or right_value.is_unbounded:
        score += 15
    if left_value.kind == "UNKNOWN" or right_value.kind == "UNKNOWN":
        score -= 5
    if state.input_params or state.tainted_vars:
        score += 5
    return max(0, min(100, score))


def _confidence_score(
    template,
    node: c_ast.Node,
    state: FlowState,
    origin: str | None = None,
) -> int:
    if template.certainty_type == "DEFINITE":
        return 100

    score = template.base_confidence
    ids = _collect_ids(node)
    external_inputs = ids & (state.input_params | state.tainted_vars)

    if not ids:
        score -= 20
    elif not external_inputs:
        score -= 10

    if ids & state.input_params:
        score += 10
    if ids & state.tainted_vars:
        score += 15
    if origin == "allocation_function":
        score += 5

    return max(0, min(100, score))


def _finding_rank(finding: Finding) -> tuple[int, int, int, str, str]:
    return (
        RISK_PRIORITY.get(finding.risk, -1),
        _CERTAINTY_PRIORITY.get(finding.certainty_type, -1),
        finding.confidence,
        finding.category,
        finding.type,
    )


def _extract_guard_signatures(node: c_ast.Node | None) -> set[GuardSignature]:
    if node is None:
        return set()

    if isinstance(node, c_ast.BinaryOp):
        if node.op in _LOGICAL_OPS:
            return _extract_guard_signatures(node.left) | _extract_guard_signatures(node.right)

        if node.op in _COMPARISON_OPS:
            return _guard_signature_from_comparison(node)

    return set()


def _guard_signature_from_comparison(node: c_ast.BinaryOp) -> set[GuardSignature]:
    signatures: set[GuardSignature] = set()

    left_name = _simple_name(node.left)
    right_name = _simple_name(node.right)

    # Multiplication guard:
    # if (n > SIZE_MAX / elem_size) return NULL;
    if node.op in {">", ">="} and left_name:
        if isinstance(node.right, c_ast.BinaryOp) and node.right.op == "/":
            limit_name = _simple_name(node.right.left)
            divisor_name = _simple_name(node.right.right)
            if limit_name in {"SIZE_MAX", "INT_MAX"} and divisor_name:
                signatures.add(GuardSignature("mul", _sorted_pair(left_name, divisor_name)))

    # Addition guard:
    # if (a > INT_MAX - b) return 0;
    if node.op in {">", ">="} and left_name:
        if isinstance(node.right, c_ast.BinaryOp) and node.right.op == "-":
            limit_name = _simple_name(node.right.left)
            rhs_name = _simple_name(node.right.right)
            if limit_name in {"INT_MAX", "INT_MIN"} and rhs_name:
                signatures.add(GuardSignature("add", _sorted_pair(left_name, rhs_name)))

    # Subtraction guard:
    # if (b > a) return;
    if node.op in {">", ">="} and left_name and right_name:
        signatures.add(GuardSignature("sub", (right_name, left_name)))
    elif node.op in {"<", "<="} and left_name and right_name:
        signatures.add(GuardSignature("sub", (left_name, right_name)))

    return signatures


def _has_guarded_operation(expr: c_ast.BinaryOp, active_guards: set[GuardSignature]) -> bool:
    left_name = _simple_name(expr.left)
    right_name = _simple_name(expr.right)
    if not left_name or not right_name:
        return False

    pair = _sorted_pair(left_name, right_name)
    if expr.op == "+":
        return GuardSignature("add", pair) in active_guards
    if expr.op == "*":
        return GuardSignature("mul", pair) in active_guards
    if expr.op == "-":
        return GuardSignature("sub", (left_name, right_name)) in active_guards
    return False


def _contains_binary_op(node: c_ast.Node | None, op: str) -> bool:
    if node is None:
        return False
    if isinstance(node, c_ast.BinaryOp):
        if node.op == op:
            return True
        return _contains_binary_op(node.left, op) or _contains_binary_op(node.right, op)
    if isinstance(node, c_ast.UnaryOp):
        return _contains_binary_op(node.expr, op)
    if isinstance(node, c_ast.Cast):
        return _contains_binary_op(node.expr, op)
    if isinstance(node, c_ast.FuncCall):
        if _contains_binary_op(node.args, op):
            return True
        return False
    if isinstance(node, c_ast.ExprList):
        return any(_contains_binary_op(expr, op) for expr in node.exprs or [])
    if isinstance(node, c_ast.TernaryOp):
        return (
            _contains_binary_op(node.cond, op)
            or _contains_binary_op(node.iftrue, op)
            or _contains_binary_op(node.iffalse, op)
        )
    return any(_contains_binary_op(child, op) for _, child in node.children() if isinstance(child, c_ast.Node))


def _collect_return_nodes(node: c_ast.Node | None) -> list[c_ast.Return]:
    returns: list[c_ast.Return] = []
    if node is None:
        return returns
    if isinstance(node, c_ast.Return):
        returns.append(node)
        return returns
    for _, child in node.children():
        if isinstance(child, c_ast.Node):
            returns.extend(_collect_return_nodes(child))
    return returns


class OverflowAnalyzer:
    def __init__(self, source: str):
        self.source = source
        self.lines = source.splitlines()
        self.findings: dict[int, Finding] = {}
        self.function_summaries: dict[str, FunctionSummary] = {}
        self.function_defs: dict[str, c_ast.FuncDef] = {}
        self.call_stack: list[str] = []
        self.parser = c_parser.CParser()

    def analyze(self) -> list[Finding]:
        try:
            ast = self.parser.parse(_prepare_source(self.source), filename="<input>")
        except ParseError:
            return []

        for external in ast.ext:
            if isinstance(external, c_ast.FuncDef):
                func_name = _function_def_name(external)
                if func_name:
                    self.function_defs[func_name] = external
                    self.function_summaries[func_name] = _summarize_function(external)

        has_main = "main" in self.function_defs
        for external in ast.ext:
            if isinstance(external, c_ast.FuncDef):
                func_name = _function_def_name(external)
                if func_name == "main" or (not has_main and func_name):
                    self._analyze_function_def(external)
                elif not func_name:
                    continue
            else:
                self._walk_children(external, FlowState(frozenset(), set(), set(), {}, None))

        return sorted(self.findings.values(), key=lambda f: f.line_number)

    def _analyze_function_def(self, node: c_ast.FuncDef) -> None:
        func_name = _function_def_name(node)
        if func_name:
            self.function_summaries[func_name] = _summarize_function(node)
        state = FlowState(
            active_guards=frozenset(),
            tainted_vars=set(),
            input_params=_function_param_names(node),
            value_env={name: _UNBOUNDED for name in _function_param_names(node)},
            function_name=func_name,
        )
        self._analyze_statement(node.body, state)

    def _analyze_statement(self, node: c_ast.Node | None, state: FlowState) -> FlowState:
        if node is None:
            return state

        if isinstance(node, c_ast.Compound):
            current_guards = state.active_guards
            for item in node.block_items or []:
                state.active_guards = current_guards
                state = self._analyze_statement(item, state)
                current_guards = state.active_guards
            return state

        if isinstance(node, c_ast.If):
            self._scan_expr(node.cond, state, in_comparison=False)
            guard_signatures = _extract_guard_signatures(node.cond)
            if self._branch_exits(node.iftrue):
                state.active_guards = state.active_guards | guard_signatures
            self._analyze_statement(node.iftrue, state)
            self._analyze_statement(node.iffalse, state)
            return state

        if isinstance(node, c_ast.Assignment):
            self._scan_expr(node.rvalue, state, in_comparison=False)
            self._update_target_state(node.lvalue, node.rvalue, state)
            return state

        if isinstance(node, c_ast.Decl):
            self._scan_expr(node.init, state, in_comparison=False)
            self._update_decl_state(node.name, node.init, state)
            return state

        if isinstance(node, c_ast.Return):
            self._scan_expr(node.expr, state, in_comparison=False)
            return state

        if isinstance(node, c_ast.FuncCall):
            self._handle_funccall(node, state)
            return state

        if isinstance(node, c_ast.For):
            if isinstance(node.init, c_ast.Node):
                self._analyze_statement(node.init, state)
            self._scan_expr(node.cond, state, in_comparison=False)
            self._scan_expr(node.next, state, in_comparison=False)
            self._analyze_statement(node.stmt, state)
            return state

        if isinstance(node, c_ast.While):
            self._scan_expr(node.cond, state, in_comparison=False)
            self._analyze_statement(node.stmt, state)
            return state

        if isinstance(node, c_ast.DoWhile):
            self._analyze_statement(node.stmt, state)
            self._scan_expr(node.cond, state, in_comparison=False)
            return state

        if isinstance(node, c_ast.Switch):
            self._scan_expr(node.cond, state, in_comparison=False)
            self._analyze_statement(node.stmt, state)
            return state

        self._walk_children(node, state)
        return state

    def _walk_children(self, node: c_ast.Node, state: FlowState) -> None:
        for _, child in node.children():
            if isinstance(child, c_ast.Node):
                self._analyze_statement(child, state)

    def _scan_expr(self, node: c_ast.Node | None, state: FlowState, in_comparison: bool) -> None:
        if node is None:
            return

        if isinstance(node, c_ast.BinaryOp):
            if node.op in _LOGICAL_OPS:
                self._scan_expr(node.left, state, in_comparison=True)
                self._scan_expr(node.right, state, in_comparison=True)
                return

            if node.op in _COMPARISON_OPS:
                self._scan_expr(node.left, state, in_comparison=True)
                self._scan_expr(node.right, state, in_comparison=True)
                return

            if not in_comparison:
                if not _has_guarded_operation(node, set(state.active_guards)):
                    self._record_binaryop(node, state)

            self._scan_expr(node.left, state, in_comparison)
            self._scan_expr(node.right, state, in_comparison)
            return

        if isinstance(node, c_ast.UnaryOp):
            self._scan_expr(node.expr, state, in_comparison)
            return

        if isinstance(node, c_ast.Cast):
            self._scan_expr(node.expr, state, in_comparison)
            return

        if isinstance(node, c_ast.TernaryOp):
            self._scan_expr(node.cond, state, in_comparison=True)
            self._scan_expr(node.iftrue, state, in_comparison)
            self._scan_expr(node.iffalse, state, in_comparison)
            return

        if isinstance(node, c_ast.ExprList):
            for expr in node.exprs or []:
                self._scan_expr(expr, state, in_comparison)
            return

        if isinstance(node, c_ast.FuncCall):
            self._handle_funccall(node, state)
            return

        for _, child in node.children():
            if isinstance(child, c_ast.Node):
                self._scan_expr(child, state, in_comparison)

    def _handle_funccall(self, node: c_ast.FuncCall, state: FlowState) -> None:
        function_name = _simple_name(node.name)
        args = node.args

        if function_name == "scanf":
            state.tainted_vars.update(_scan_target_names(args))
            for target in _scan_target_names(args):
                state.value_env[target] = _UNBOUNDED

        if function_name in self.function_defs and function_name not in self.call_stack:
            self._analyze_function_call(function_name, node, state)

        allocation_decision = _allocation_decision(node, state)
        if allocation_decision is not None:
            self._record_decision(node, allocation_decision)
            for expr in _function_call_args(node):
                self._scan_expr(expr, state, in_comparison=False)
            return

        if args is not None:
            for expr in _function_call_args(node):
                self._scan_expr(expr, state, in_comparison=False)

    def _analyze_function_call(self, function_name: str, call_node: c_ast.FuncCall, caller_state: FlowState) -> None:
        func_def = self.function_defs.get(function_name)
        if func_def is None or function_name in self.call_stack:
            return

        child_state = FlowState(
            active_guards=frozenset(),
            tainted_vars=set(),
            input_params=set(),
            value_env={},
            function_name=function_name,
        )

        param_names = _ordered_function_param_names(func_def)
        arg_nodes = _function_call_args(call_node)
        for index, param_name in enumerate(param_names):
            arg_node = arg_nodes[index] if index < len(arg_nodes) else None
            value, overflow = _eval_expression(arg_node, caller_state)
            if isinstance(arg_node, c_ast.FuncCall):
                called_name = _simple_name(arg_node.name) or ""
                summary = self.function_summaries.get(called_name)
                if called_name == "scanf" or (summary and summary.returns_user_input):
                    value = _UNBOUNDED
            if overflow:
                value = _UNBOUNDED
            child_state.value_env[param_name] = value
            child_state.input_params.add(param_name)
            if value.is_unbounded:
                child_state.tainted_vars.add(param_name)

        self.call_stack.append(function_name)
        try:
            self._analyze_statement(func_def.body, child_state)
        finally:
            self.call_stack.pop()

        return_value = self._evaluate_function_return(func_def, call_node, caller_state)
        if return_value.is_unbounded:
            for target_name in _assign_target_names(call_node):
                caller_state.value_env[target_name] = _UNBOUNDED
                caller_state.tainted_vars.add(target_name)
        elif return_value.is_constant:
            for target_name in _assign_target_names(call_node):
                caller_state.value_env[target_name] = return_value

    def _update_target_state(self, target: c_ast.Node, value_node: c_ast.Node | None, state: FlowState) -> None:
        targets = _assign_target_names(target)
        value, overflow = _eval_expression(value_node, state)
        if isinstance(value_node, c_ast.FuncCall):
            function_name = _simple_name(value_node.name) or ""
            summary = self.function_summaries.get(function_name)
            if function_name == "scanf" or (summary and summary.returns_user_input):
                value = _UNBOUNDED
            elif function_name in self.function_defs:
                return_value = self._evaluate_function_return(self.function_defs[function_name], value_node, state)
                if return_value.is_unbounded:
                    value = _UNBOUNDED
                elif return_value.is_constant:
                    value = return_value
        if overflow:
            value = _UNBOUNDED
        for target_name in targets:
            state.value_env[target_name] = value
            if value.is_unbounded:
                state.tainted_vars.add(target_name)

    def _update_decl_state(self, target_name: str | None, value_node: c_ast.Node | None, state: FlowState) -> None:
        if target_name is None:
            return
        value, overflow = _eval_expression(value_node, state)
        if isinstance(value_node, c_ast.FuncCall):
            function_name = _simple_name(value_node.name) or ""
            summary = self.function_summaries.get(function_name)
            if function_name == "scanf" or (summary and summary.returns_user_input):
                value = _UNBOUNDED
            elif function_name in self.function_defs:
                return_value = self._evaluate_function_return(self.function_defs[function_name], value_node, state)
                if return_value.is_unbounded:
                    value = _UNBOUNDED
                elif return_value.is_constant:
                    value = return_value
        if overflow:
            value = _UNBOUNDED
        state.value_env[target_name] = value
        if value.is_unbounded:
            state.tainted_vars.add(target_name)

    def _branch_exits(self, node: c_ast.Node | None) -> bool:
        if node is None:
            return False
        if isinstance(node, c_ast.Return):
            return True
        if isinstance(node, c_ast.Compound):
            return any(self._branch_exits(item) for item in node.block_items or [])
        if isinstance(node, c_ast.If):
            return self._branch_exits(node.iftrue) and self._branch_exits(node.iffalse)
        return False

    def _record_binaryop(self, node: c_ast.BinaryOp, state: FlowState) -> None:
        decision = _binary_decision(node, state)
        if decision is None:
            return
        self._record_decision(node, decision)

    def _record_decision(self, node: c_ast.Node, decision: AnalysisDecision) -> None:
        coord = getattr(node, "coord", None)
        if coord is None or coord.line is None:
            return

        line_number = coord.line - _PROLOG_LINE_OFFSET
        if line_number <= 0:
            return

        finding = Finding(
            line_number=line_number,
            line_content=_line_content(self.lines, line_number),
            function_name=decision.function_name or self._current_function_name(),
            expression=decision.expression,
            cwe=decision.cwe,
            category=decision.category,
            type=decision.type,
            risk_type=decision.risk_type,
            risk=decision.severity,
            severity=decision.severity,
            certainty_type=decision.certainty_type,
            confidence=decision.confidence,
            reason=decision.reason,
            suggestion=decision.suggestion,
        )
        self._store_finding(finding)

    def _record_specific(self, node: c_ast.Node, cwe: str, category: str, type_name: str, risk: str, certainty_type: str, confidence: int, reason: str, suggestion: str) -> None:
        coord = getattr(node, "coord", None)
        if coord is None or coord.line is None:
            return

        line_number = coord.line - _PROLOG_LINE_OFFSET
        if line_number <= 0:
            return

        line_content = _line_content(self.lines, line_number)
        finding = Finding(
            line_number=line_number,
            line_content=line_content,
            function_name=self._current_function_name(),
            expression=_expr_to_source(node),
            cwe=cwe,
            category=category,
            type=type_name,
            risk_type="REAL_OVERFLOW_RISK",
            risk=risk,
            severity=risk,
            certainty_type=certainty_type,
            confidence=confidence,
            reason=reason,
            suggestion=suggestion,
        )
        self._store_finding(finding)

    def _current_function_name(self) -> str:
        return ""

    def _evaluate_function_return(self, func_def: c_ast.FuncDef, call_node: c_ast.Node | None, caller_state: FlowState) -> SymbolicValue:
        param_names = _ordered_function_param_names(func_def)
        child_state = FlowState(
            active_guards=frozenset(),
            tainted_vars=set(),
            input_params=set(param_names),
            value_env={},
            function_name=_function_def_name(func_def),
        )

        arg_nodes = _function_call_args(call_node) if isinstance(call_node, c_ast.FuncCall) else []
        for index, param_name in enumerate(param_names):
            arg_node = arg_nodes[index] if index < len(arg_nodes) else None
            value, overflow = _eval_expression(arg_node, caller_state)
            if overflow:
                value = _UNBOUNDED
            if isinstance(arg_node, c_ast.FuncCall):
                called_name = _simple_name(arg_node.name) or ""
                summary = self.function_summaries.get(called_name)
                if called_name == "scanf" or (summary and summary.returns_user_input):
                    value = _UNBOUNDED
            child_state.value_env[param_name] = value

        returns = _collect_return_nodes(func_def.body)
        if not returns:
            return _UNBOUNDED

        resolved: list[SymbolicValue] = []
        for ret in returns:
            value, overflow = _eval_expression(ret.expr, child_state)
            if overflow:
                return _UNBOUNDED
            resolved.append(value)

        if not resolved:
            return _UNBOUNDED
        first = resolved[0]
        if all(item == first for item in resolved):
            return first
        if any(item.is_unbounded for item in resolved):
            return _UNBOUNDED
        return _UNKNOWN

    def _store_finding(self, finding: Finding) -> None:
        existing = self.findings.get(finding.line_number)
        if existing is None:
            self.findings[finding.line_number] = finding
            return

        if _finding_rank(finding) > _finding_rank(existing):
            self.findings[finding.line_number] = finding


def analyze(source: str) -> list[Finding]:
    return OverflowAnalyzer(source).analyze()


def analyze_file(path: str) -> list[Finding]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return analyze(f.read())
