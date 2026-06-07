# OverflowGuard

OverflowGuard is an AST-based static analysis tool for C source files. It focuses on integer overflow, integer underflow, and allocation-size overflow patterns using `pycparser`.

## What it does

- Parses `.c` files into an AST
- Tracks integer values with a lightweight symbolic/range model
- Detects realistic overflow risks in:
  - arithmetic expressions
  - boundary cases such as `INT_MAX + x` and `INT_MIN - x`
  - allocation expressions such as `malloc(n * sizeof(T))`
- Stores previously analyzed files in a local history menu
- Generates an HTML report for each analysis

## Requirements

- Python 3.8+
- `pip`
- `streamlit`
- `pycparser`

## Setup

```bash
pip install -r requirements.txt
```

## Run

```bash
python -m streamlit run app.py
```

Open the local URL shown by Streamlit, usually:

```bash
http://localhost:8501
```

## Demo Flow

1. Open **Yeni Analiz**
2. Upload a `.c` file
3. Click **Analyze**
4. Review findings in the results table
5. Open **Daha Önce İncelenenler** to inspect saved analyses
6. Use the detail page to review source, findings, and download HTML reports

## Analysis Model

- Constant expressions are folded first.
- Fully deterministic safe expressions are not reported.
- Function parameters and user-input driven values are treated as unbounded.
- Guarded expressions are skipped when a matching safety check is detected.
- Allocation risks are reported only when the allocation size can realistically overflow.

## Project Structure

```text
app.py               Streamlit UI
analyzer.py          AST-based detection engine
analysis_config.py   Risk templates, severity mapping, and messages
history_store.py     Local persistence for previous analyses
report.py            HTML report generator
test_files/          Manual demo cases
requirements.txt     Python dependencies
```

## Test Files

```text
test_files/
  boundary/
    risky_intmax.c
    risky_intmin.c
  allocation/
    risky_malloc.c
    risky_realloc.c
    risky_calloc.c
    risky_malloc_rows_cols.c
    risky_realloc_rows_cols.c
    safe_malloc_constant.c
  arithmetic/
    risky_add.c
    risky_add_scanf.c
    risky_mul.c
    risky_sub.c
    safe_add_guarded.c
    safe_mul_guarded.c
  safe.c
```

## Output Schema

Each finding includes:

- `line_number`
- `line_content`
- `function_name`
- `expression`
- `cwe`
- `category`
- `type`
- `risk_type`
- `risk`
- `severity`
- `certainty_type`
- `confidence`
- `reason`
- `suggestion`

## Notes for Submission

- The tool is fully usable as a demo project.
- Previously analyzed files are stored locally in `.overflowguard_history.json`.
- Safe examples are included so reviewers can compare false-positive behavior against risky cases.
- The project is intentionally rule-based and explainable, which fits a software security term project presentation.
