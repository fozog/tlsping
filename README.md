# tlsping

Small Python project organized with a `src/` layout and a dedicated virtual environment.

## Develop

1. Create the virtual environment:
   ```bash
   /usr/bin/python3 -m venv .venv
   ```
2. Activate it:
   ```bash
   source .venv/bin/activate
   ```

## Install

```
sudo pip install git+https://github.com/fozog/tlsping.git
```

## Run

```bash
tlsping impots.gouv.fr
tlsping --full play.itunes.apple.com
tlsping --port NTS-KE nts.netnod.se
```

