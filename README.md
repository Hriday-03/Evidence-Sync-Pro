# EvidenceSync Pro

Windows-native forensic cross-device event correlation engine with explainable confidence scoring.

## Features

- **Multi-device correlation**: Link evidence across Windows, mobile, and cloud sources
- **Explainable confidence**: Every correlation shows why it matched and how reliable it is
- **Artifact manipulability assessment**: Understand which evidence is easy to fake vs. hard to tamper with
- **Court-ready reporting**: PDF/HTML/JSON exports with full audit trails

## Status

**v0.1.0 - Early Development**

Phase 0/9 complete. Parsers in progress.

## Installation

```bash
git clone https://github.com/Hriday-03/Evidence-Sync-Pro
cd evidence-sync-pro
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Development

```bash
# Run tests
pytest tests/ -v --cov=evidence_sync_pro

# Format code
black .

# Type checking
mypy evidence_sync_pro

# Linting
flake8 evidence_sync_pro
```

## License

Apache 2.0