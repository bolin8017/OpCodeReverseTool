# OpCodeReverseTool

[English](README.md) | [繁體中文](docs/README.zh-TW.md)

A unified binary opcode extraction framework for security researchers and reverse engineers. Extract operation codes (opcodes) from binary files using a single CLI, regardless of which reverse engineering backend you use.

## Supported Backends

- **[Ghidra](https://ghidra-sre.org/)** - NSA's open-source reverse engineering framework with powerful disassembly capabilities
- **[Radare2](https://www.radare.org/n/)** - Free and open-source reverse engineering framework supporting many architectures
- **[IDA Pro](https://www.hex-rays.com/products/ida/)** - *(Planned)* Industry-standard disassembler and debugger

## Installation

### Prerequisites

- Python 3.8+
- At least one supported backend installed:
  - **Ghidra**: Download from [ghidra-sre.org](https://ghidra-sre.org/), requires Java 17+
  - **Radare2**: Build from source or install via package manager

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Docker Deployment (Optional)

Pre-configured Docker environments are available in `deployment-scripts/`. See [deployment-scripts/README.md](deployment-scripts/README.md) for details.

## Usage

### Basic Syntax

```bash
python get_opcode.py -b <backend> -d <binary_directory> [options]
```

### Command-Line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-b, --backend` | Yes | Backend to use: `ghidra` or `radare2` |
| `-d, --directory` | Yes | Path to directory containing binary files |
| `-o, --output` | No | Output directory (default: `<input_dir>_disassemble`) |
| `-t, --timeout` | No | Timeout per file in seconds (default: 600) |
| `--pattern` | No | Glob pattern to filter files (default: files without extensions) |
| `-g, --ghidra` | Ghidra only | Path to Ghidra `analyzeHeadless` script |

### Usage Examples

#### Ghidra Backend

```bash
# Basic usage
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless

# Custom output directory
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless -o /path/to/output

# Custom timeout (1200 seconds)
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless -t 1200

# Process only .exe files
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless --pattern "*.exe"

# All options combined
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless -o /path/to/output -t 1200 --pattern "*.exe"
```

#### Radare2 Backend

```bash
# Basic usage
python get_opcode.py -b radare2 -d /path/to/binaries

# Custom output directory
python get_opcode.py -b radare2 -d /path/to/binaries -o /path/to/output

# Custom timeout (600 seconds)
python get_opcode.py -b radare2 -d /path/to/binaries -t 600

# Process all files (including those with extensions)
python get_opcode.py -b radare2 -d /path/to/binaries --pattern "*"

# All options combined
python get_opcode.py -b radare2 -d /path/to/binaries -o /path/to/output -t 600 --pattern "*"
```

## Output Format

### Directory Structure

All backends produce the same output structure:

```
output_dir/
├── results/
│   ├── 00/
│   │   └── 00046252fa98...csv
│   └── a0/
│       └── a0f3bc71de...csv
├── extraction.log
└── timing.log
```

Results are organized into subdirectories based on the first two characters of the filename, preventing any single directory from accumulating too many files.

### CSV Format

Each CSV file contains three columns:

```csv
addr,opcode,section_name
4194356,nop,segment_1.1
4194360,mov,.text
4194368,push,.text
```

| Column | Type | Description |
|--------|------|-------------|
| `addr` | int | Instruction address |
| `opcode` | str | Instruction mnemonic (first token only) |
| `section_name` | str | Binary section/segment name |

### Log Files

- **extraction.log** - Records extraction success/failure for each file
- **timing.log** - Records processing time per file (`filename,seconds`)

## Project Structure

```
OpCodeReverseTool/
├── get_opcode.py              # Unified CLI entry point
├── requirements.txt           # Python dependencies
├── opcode_tool/
│   ├── __init__.py
│   ├── common.py              # Shared logic (logging, parallel processing, CSV)
│   └── backends/
│       ├── __init__.py        # Backend registry
│       ├── base.py            # BaseBackend ABC
│       ├── ghidra.py          # Ghidra backend
│       └── radare2.py         # Radare2 backend
├── scripts/
│   ├── ghidra_opcode_script.py  # Ghidra internal extraction script
│   └── r2_timeout_check.sh     # Radare2 timeout check
├── deployment-scripts/        # Docker deployment configurations
├── output/                    # Sample output
└── test_data/                 # Sample test binaries
```

## Features

- **Unified CLI** - Single command interface for all backends
- **Parallel Processing** - Multi-core CPU utilization for batch extraction
- **Timeout Protection** - Configurable per-file timeout to handle problematic binaries
- **Flexible File Filtering** - Glob pattern support for selecting specific file types
- **Consistent Output** - Identical CSV format and directory structure across all backends
- **Extensible Architecture** - ABC-based backend system for easy addition of new tools
- **Comprehensive Logging** - Separate extraction and timing logs for debugging and analysis
- **Resource Cleanup** - Automatic cleanup of temporary files after processing

## Adding a New Backend

Implement the `BaseBackend` abstract class:

```python
from opcode_tool.backends.base import BaseBackend

class MyBackend(BaseBackend):
    @classmethod
    def add_arguments(cls, parser):
        # Add backend-specific CLI arguments
        pass

    def validate_environment(self):
        # Check tool availability
        pass

    def extract_features(self, input_file, timeout, extraction_logger):
        # Return [{'addr': int, 'opcode': str, 'section_name': str}, ...]
        pass
```

Then register it in `opcode_tool/backends/__init__.py`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
