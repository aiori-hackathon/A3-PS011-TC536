# PS-011 External Asset Monitoring Tool

PS-011 is an external-asset monitoring and change-detection tool built in Python.

## Quickstart

### Installation
```bash
pip install -e .
# or with dev dependencies
pip install -e .[dev]
```

### Running Tests
```bash
pytest
```

### Usage
Inspect the scope hash of a configuration file:
```bash
python -m ps011.scope scope.yaml
```
