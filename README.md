# Software-Security — Term Project

Software Security Term Project

---

## OverflowGuard

Static integer overflow vulnerability detector for C source files. (CWE-190)

## Requirements

- Python 3.8+
- pip

## Setup (first time)

```bash
pip install -r requirements.txt
```

## Run

```bash
python -m streamlit run app.py
```

Then open **http://localhost:8501** in your browser.

## Usage

1. Upload a `.c` file using the file picker
2. Click **Analyze**
3. View findings by severity (CRITICAL / HIGH / MEDIUM / LOW)
4. Download the HTML report

## Project structure

```
app.py          — Streamlit UI (Ata)
analyzer.py     — Detection engine (Mustafa)
report.py       — HTML report generator (Ata)
test_files/
  risky.c       — Example with vulnerabilities
  safe.c        — Example with no vulnerabilities
requirements.txt
```

## Interface contract (for integration)

`analyzer.py` exposes two functions:

```python
def analyze(source: str) -> list[Finding]: ...
def analyze_file(path: str)  -> list[Finding]: ...
```

`Finding` has these fields: `line_number`, `line_content`, `risk`, `reason`, `suggestion`.  
`risk` is one of: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`.

The UI (`app.py`) only calls `analyze(source)` — Mustafa can replace the internals of `analyzer.py` without touching anything else.
