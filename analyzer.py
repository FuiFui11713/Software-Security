"""
OverflowGuard - Integer Overflow Detection Engine
Stub implementation — Mustafa replaces the internals, interface stays the same.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass
class Finding:
    line_number: int
    line_content: str
    risk: str          # LOW / MEDIUM / HIGH / CRITICAL
    reason: str
    suggestion: str

# --- Detection rules ---

_RULES = [
    {
        # INT_MAX ± something in an assignment, not a guard condition
        "pattern": re.compile(r'=\s*INT_MAX\s*[\+\-]|INT_MAX\s*[\+\-]\s*\d'),
        "risk": "CRITICAL",
        "reason": "Adding to / subtracting from INT_MAX causes signed integer overflow",
        "suggestion": "Check value before adding: if (x == INT_MAX) handle_error();",
    },
    {
        # malloc/realloc whose argument contains a * between two identifiers/numbers
        "pattern": re.compile(r'\b(?:malloc|realloc)\s*\(\s*[^)]*\b\w+\s*\*\s*\w+'),
        "risk": "CRITICAL",
        "reason": "malloc argument uses multiplication — result may overflow size_t",
        "suggestion": "Guard: if (n > SIZE_MAX / sizeof(T)) return NULL; before malloc(n * sizeof(T));",
    },
    {
        "pattern": re.compile(r'\bcalloc\s*\(\s*[^)]*\b\w+\s*\*\s*\w+'),
        "risk": "HIGH",
        "reason": "calloc argument uses multiplication — may overflow",
        "suggestion": "Validate: if (n > SIZE_MAX / sizeof(T)) return NULL;",
    },
    {
        # Multiplication in an assignment (=), NOT in a guard (>/<) and NOT pointer decl
        # Matches:  var = a * b   or   type var = a * b
        # Avoids:   int *p  (pointer decl — no = before *)
        "pattern": re.compile(r'=\s*[^;]*\b(\w+)\s*\*\s*(\w+)'),
        "risk": "HIGH",
        "reason": "Multiplication of two integers may exceed INT_MAX",
        "suggestion": "Guard: if (a != 0 && b > INT_MAX / a) handle_error(); before a * b",
    },
    {
        # Addition in an assignment, NOT in a guard condition
        "pattern": re.compile(r'=\s*[^;]*\b(\w+)\s*\+\s*(\w+)'),
        "risk": "MEDIUM",
        "reason": "Addition may overflow if operands are near INT_MAX",
        "suggestion": "Guard: if (a > INT_MAX - b) handle_error(); before a + b",
    },
    {
        # Subtraction in an assignment
        "pattern": re.compile(r'=\s*[^;]*\b(\w+)\s*-\s*(\w+)'),
        "risk": "LOW",
        "reason": "Subtraction may underflow if result goes below INT_MIN",
        "suggestion": "Guard: if (b > a) handle_error(); for unsigned; check INT_MIN for signed",
    },
]

# Skip comment lines, preprocessor, and lines that are clearly guard / output calls
_SKIP = re.compile(
    r'^\s*('
    r'//|/\*|\*'           # comments
    r'|#'                  # preprocessor
    r'|printf|fprintf|scanf|perror'  # I/O
    r'|if\s*\('            # guard conditions (if-statements)
    r'|return\s'           # return statements
    r'|free\s*\('          # memory free
    r'|assert\s*\('        # assertions
    r')'
)


def analyze(source: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or _SKIP.match(stripped):
            continue
        for rule in _RULES:
            if rule["pattern"].search(stripped):
                findings.append(Finding(
                    line_number=i,
                    line_content=stripped,
                    risk=rule["risk"],
                    reason=rule["reason"],
                    suggestion=rule["suggestion"],
                ))
                break  # one finding per line (highest-priority rule wins)
    return findings


def analyze_file(path: str) -> list[Finding]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return analyze(f.read())
