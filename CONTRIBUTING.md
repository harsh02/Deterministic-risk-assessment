# Contributing to DetRisk

Thank you for your interest in contributing to DetRisk! 🎉

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or suggest features
- Include detailed information: OS, Python version, steps to reproduce
- For security issues, please email directly (do not create public issues)

### Pull Requests

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/YourFeature`
3. **Make changes** with clear, descriptive commits
4. **Test thoroughly**: Run all tests and add new ones if needed
5. **Update documentation** if you change functionality
6. **Submit PR** with a clear description of changes

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/detrisk.git
cd detrisk

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Download NLP model
python -m spacy download en_core_web_md

# Populate intelligence feeds
python scripts/sync_intel_feeds.py

# Run tests
python -m pytest tests/unit/test_engine.py -v
```

### Code Style

- Follow PEP 8 guidelines
- Use type hints for function parameters and returns
- Add docstrings to all functions/classes
- Use descriptive variable names
- Keep functions focused and concise

### Testing

- Add tests for all new features
- Ensure all existing tests pass
- Aim for high test coverage
- Test edge cases and error conditions

### Security

- Never use `eval()` or `exec()`
- Validate all user inputs
- Use safe file operations
- Follow secure coding practices

## Questions?

Feel free to open a GitHub Discussion or contact the maintainers.

Thank you for contributing! 🚀
