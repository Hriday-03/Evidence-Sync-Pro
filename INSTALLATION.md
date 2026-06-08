# Installation Guide (Windows)

## System Requirements

- Windows 10 or later
- Python 3.9 or later
- 2GB RAM (8GB+ recommended)
- 500MB disk space

## Steps

1. Download and install Python 3.9+ from python.org (make sure to tick "Add Python to PATH")

2. Clone the repository:
```bash
git clone https://github.com/yourusername/evidence-sync-pro
cd evidence-sync-pro
```

3. Create virtual environment:
```bash
python -m venv venv
venv\Scripts\activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Verify installation:
```bash
pytest tests/ -v
```

If all tests pass, you're ready!

## Troubleshooting

### "python-evtx installation failed"
Make sure you have Visual C++ Build Tools installed. Download from:
https://visualstudio.microsoft.com/visual-cpp-build-tools/

### "pyqt6 not found"
Run: `pip install PyQt6==6.4.2 --upgrade`

### Tests fail on first run
Run: `pip install -r requirements.txt --upgrade`