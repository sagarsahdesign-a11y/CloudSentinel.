# Contributing to CloudSentinel

First off, thank you for checking out CloudSentinel! We welcome contributions from the cybersecurity, DevSecOps, and cloud engineering communities.

---

## Code of Conduct

We are committed to providing a welcoming, diverse, and harassment-free environment for everyone. Please treat all contributors with respect.

---

## How to Contribute

### 1. Reporting Bugs & Requesting Features
- Search the issue tracker to make sure the bug/feature hasn't been reported yet.
- If not, open a new issue using the provided templates, including steps to reproduce or clear descriptions of the desired feature.

### 2. Local Development Setup
To set up CloudSentinel locally:

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/CloudSentinel.git
   cd CloudSentinel
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix/macOS:
   source venv/bin/activate
   ```
3. Install the package in editable mode with development dependencies:
   ```bash
   pip install -e .[dev]
   ```

### 3. Coding Guidelines
- **Formatting**: We use `black` for formatting. Run `black .` before committing.
- **Linting & Styling**: We use `ruff`. Run `ruff check .` to catch style issues and potential bugs.
- **Type Hints**: Please write clear type hints for all parameters and return values.
- **No Mock Placeholders**: Avoid writing mock-only code paths in production checks. Keep mocks isolated to the test suite.

### 4. Running Tests
We use `pytest` and `moto` to test our AWS security checks. Run the tests using:
```bash
pytest -v --cov=cloudsentinel tests/
```

### 5. Submitting a Pull Request
- Create a new branch: `git checkout -b feature/your-feature-name`.
- Commit your changes with descriptive commit messages.
- Ensure all tests, lints, and format checks pass.
- Open a Pull Request referencing the issue you are fixing.
