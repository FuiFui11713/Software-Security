"""Static analysis configuration for OverflowGuard."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FindingTemplate:
    cwe: str
    type: str
    risk: str
    certainty_type: str
    base_confidence: int
    category: str
    reason: str
    suggestion: str


RISK_PRIORITY = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

BOUNDARY_TEMPLATES = {
    "INT_MAX_PLUS": FindingTemplate(
        cwe="CWE-190",
        type="INTEGER_OVERFLOW",
        risk="CRITICAL",
        certainty_type="DEFINITE",
        base_confidence=100,
        category="INTEGER_BOUNDARY_OVERFLOW",
        reason="Integer addition involving INT_MAX may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
        suggestion="Check bounds before adding: if (x == INT_MAX) handle_error();",
    ),
    "INT_MIN_MINUS": FindingTemplate(
        cwe="CWE-190",
        type="INTEGER_UNDERFLOW",
        risk="CRITICAL",
        certainty_type="DEFINITE",
        base_confidence=100,
        category="INTEGER_BOUNDARY_OVERFLOW",
        reason="Integer subtraction from INT_MIN may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
        suggestion="Check bounds before subtracting: if (x == INT_MIN) handle_error();",
    ),
}

ARITHMETIC_TEMPLATES = {
    "+": FindingTemplate(
        cwe="CWE-190",
        type="INTEGER_OVERFLOW",
        risk="MEDIUM",
        certainty_type="POTENTIAL",
        base_confidence=50,
        category="INTEGER_ARITHMETIC_OVERFLOW",
        reason="Integer addition may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
        suggestion="Guard: if (a > INT_MAX - b) handle_error(); before a + b",
    ),
    "*": FindingTemplate(
        cwe="CWE-190",
        type="INTEGER_OVERFLOW",
        risk="HIGH",
        certainty_type="POTENTIAL",
        base_confidence=70,
        category="INTEGER_ARITHMETIC_OVERFLOW",
        reason="Integer multiplication may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
        suggestion="Guard: if (a != 0 && b > INT_MAX / a) handle_error(); before a * b",
    ),
    "-": FindingTemplate(
        cwe="CWE-190",
        type="INTEGER_UNDERFLOW",
        risk="MEDIUM",
        certainty_type="POTENTIAL",
        base_confidence=50,
        category="INTEGER_ARITHMETIC_OVERFLOW",
        reason="Integer subtraction may exceed the representable range of signed int, resulting in undefined behavior (CWE-190).",
        suggestion="Guard: if (b > a) handle_error(); for unsigned; check INT_MIN for signed",
    ),
}

FUNCTION_TEMPLATES = {
    "malloc": FindingTemplate(
        cwe="CWE-190",
        type="ALLOCATION_OVERFLOW",
        risk="CRITICAL",
        certainty_type="POTENTIAL",
        base_confidence=95,
        category="MEMORY_ALLOCATION_OVERFLOW",
        reason="Multiplication in allocation size may wrap size_t, potentially causing an undersized heap allocation (CWE-190).",
        suggestion="Guard: if (n > SIZE_MAX / sizeof(T)) return NULL; before malloc(n * sizeof(T));",
    ),
    "realloc": FindingTemplate(
        cwe="CWE-190",
        type="ALLOCATION_OVERFLOW",
        risk="CRITICAL",
        certainty_type="POTENTIAL",
        base_confidence=95,
        category="MEMORY_ALLOCATION_OVERFLOW",
        reason="Multiplication in allocation size may wrap size_t, potentially causing an undersized heap allocation (CWE-190).",
        suggestion="Guard: if (n > SIZE_MAX / sizeof(T)) return NULL; before realloc(n * sizeof(T));",
    ),
    "calloc": FindingTemplate(
        cwe="CWE-190",
        type="ALLOCATION_OVERFLOW",
        risk="CRITICAL",
        certainty_type="POTENTIAL",
        base_confidence=95,
        category="MEMORY_ALLOCATION_OVERFLOW",
        reason="Multiplication in allocation size may wrap size_t, potentially causing an undersized heap allocation (CWE-190).",
        suggestion="Validate inputs before calloc: if (n > SIZE_MAX / elem_size) return NULL;",
    ),
}


def classify_binary(op: str, left_name: str | None, right_name: str | None, left_is_constant: bool = False, right_is_constant: bool = False) -> FindingTemplate | None:
    if op == "+":
        if left_name == "INT_MAX" or right_name == "INT_MAX":
            return BOUNDARY_TEMPLATES["INT_MAX_PLUS"]
        return ARITHMETIC_TEMPLATES["+"]

    if op == "-":
        if left_name == "INT_MIN":
            return BOUNDARY_TEMPLATES["INT_MIN_MINUS"]
        return ARITHMETIC_TEMPLATES["-"]

    if op == "*":
        return ARITHMETIC_TEMPLATES["*"]

    return None


def classify_function(name: str) -> FindingTemplate | None:
    return FUNCTION_TEMPLATES.get(name)
