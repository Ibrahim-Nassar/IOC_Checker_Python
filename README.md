
# Python_IOC_Checker

## Configuration

### Environment Variables

#### Rate Limiting Configuration
The following environment variables can be used to customize API rate limits for different providers:

- `VIRUSTOTAL_RPM` - VirusTotal requests per minute (default: 4)
- `GREYNOISE_RPM` - GreyNoise requests per week (default: 50)

Example `.env` file:
```
VIRUSTOTAL_RPM=10
GREYNOISE_RPM=100
```

## CLI Usage

The command-line interface automatically loads saved API keys from the GUI configuration, so you can set up your keys once in the GUI and use them immediately with the CLI.

## Installation

### Requirements
```bash
poetry install
```

### Development Setup
To set up the development environment with pre-commit hooks:

```bash
pip install pre-commit
pre-commit install
```

This will install pre-commit hooks that run:
- Ruff (linting and auto-fixing)
- Black (code formatting)
- Mypy (static type checking)

## Building an EXE

Run `build_windows\build.bat` to produce `dist\IOC_Checker.exe`.
