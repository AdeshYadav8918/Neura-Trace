# Contributing to Neura Trace

Thank you for your interest in contributing to Neura Trace!

## How to Contribute

### Reporting Issues
1. Check if the issue already exists
2. Create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)

### Feature Requests
1. Check existing feature requests
2. Describe the feature and its benefits
3. Provide examples of use cases

### Pull Requests
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Development Setup

1. Clone your fork:

    git clone https://github.com/YOUR_USERNAME/neura-trace.git
    cd neura-trace

2. Create virtual environment:

    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:

    pip install -r requirements.txt

4. Install development tools:

    pip install black flake8 pytest

# Code Style
    Follow PEP 8 guidelines
    Use descriptive variable names
    Add docstrings to functions
    Include type hints where possible

# Testing
    Write tests for new features
    Ensure existing tests pass
    Test on multiple platforms if possible

# Documentation
    Update README.md for significant changes
    Add comments for complex logic
    Update inline documentation
    