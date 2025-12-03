# Secure Scanner

Static code analyzer for Python that detects:
- SQL injection via f-strings
- Dangerous functions (`eval`, `exec`)
- Unsafe deserialization (`pickle`, `yaml.load`)
- More...

Outputs results in text or [SARIF](https://sarif.io) format for CI/CD integration.

## Usage

```bash
python -m scanner --path ./my_project
python -m scanner --path . --format sarif