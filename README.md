# tlsping

Small Python project organized with a `src/` layout and a dedicated virtual environment.

## Setup

1. Create the virtual environment:
   ```bash
   /usr/bin/python3 -m venv .venv
   ```
2. Activate it:
   ```bash
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -e .
   ```

## Run

```bash
python -m tlsping.main --port NTS-KE nts.netnod.se
```

## Test

```bash
python -m unittest discover -s tests -v
```
