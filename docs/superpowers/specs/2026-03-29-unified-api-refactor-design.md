# OpCodeReverseTool Unified API Refactor Design

## Overview

Refactor OpCodeReverseTool from separate, duplicated Ghidra/Radare2 modules into a unified framework with a single CLI entry point, shared common logic, and a consistent backend abstraction layer (ABC). All backends produce identical output format.

## Project Structure

```
OpCodeReverseTool/
├── get_opcode.py                      # Unified CLI entry point
├── requirements.txt                   # Unified Python dependencies
├── opcode_tool/
│   ├── __init__.py
│   ├── common.py                      # Shared logic: logging, parallel processing,
│   │                                  #   output dir management, CSV writing, file filtering
│   └── backends/
│       ├── __init__.py                # BACKEND_REGISTRY + get_backend()
│       ├── base.py                    # BaseBackend ABC
│       ├── ghidra.py                  # GhidraBackend implementation
│       └── radare2.py                 # Radare2Backend implementation
├── scripts/
│   ├── ghidra_opcode_script.py        # Ghidra internal Python script (runs inside Ghidra JVM)
│   └── r2_timeout_check.sh            # Radare2 timeout check script
├── deployment-scripts/                # Docker deployment (bug fixes applied)
│   ├── README.md
│   ├── ghidra_deploy/
│   │   ├── Dockerfile
│   │   └── ghidra_deploy.sh
│   └── radare2_deploy/
│       ├── Dockerfile
│       └── radare2_deploy.sh
├── docs/
├── output/                            # Sample output
├── test_data/                         # Test binaries
├── LICENSE
├── .gitignore
└── README.md
```

## Unified CLI Interface

```bash
# Basic usage
python get_opcode.py -b ghidra -d /path/to/bins -g /path/to/analyzeHeadless
python get_opcode.py -b radare2 -d /path/to/bins

# Full parameters
python get_opcode.py \
  -b <backend>          # Required: ghidra | radare2
  -d <directory>        # Required: binary file directory
  -o <output>           # Optional: output directory (default: <input_dir>_disassemble)
  -t <timeout>          # Optional: timeout in seconds (default: 600)
  --pattern <glob>      # Optional: file filter pattern (default: no-extension files)

# Backend-specific parameters
  -g <ghidra_path>      # ghidra only: path to analyzeHeadless
```

- Shared arguments defined in `get_opcode.py` argparse
- Each backend injects its own arguments via `add_arguments(parser)` classmethod
- argparse merges them into a single `--help` output

## Unified Output Structure

All backends produce identical output:

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

- Subdirectories based on first 2 characters of filename
- Consistent across all backends

## Unified CSV Format

```csv
addr,opcode,section_name
4194356,nop,segment_1.1
4194360,mov,.text
```

- `addr`: instruction address as integer
- `opcode`: instruction mnemonic (first token only)
- `section_name`: binary section/segment name

## Backend Abstraction (ABC)

```python
class BaseBackend(ABC):
    def __init__(self, args: argparse.Namespace):
        self.args = args

    @classmethod
    @abstractmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Inject backend-specific CLI arguments."""
        ...

    @abstractmethod
    def validate_environment(self) -> None:
        """Check backend tool availability. Raise RuntimeError if unavailable."""
        ...

    @abstractmethod
    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> list[dict]:
        """
        Core extraction method. Returns unified format:
        [{'addr': int, 'opcode': str, 'section_name': str}, ...]
        Empty list means extraction failed.
        """
        ...
```

## Shared Main Flow (`common.run()`)

```
1. setup_output_directory()         -> Create output/results/ directory
2. configure_logging()              -> Create extraction_logger + timing_logger
3. backend.validate_environment()   -> Verify tool availability
4. collect_files()                  -> Scan binary files based on --pattern
5. parallel_process()               -> ProcessPoolExecutor parallel extraction
   └─ extraction()                  -> Per-file processing:
      ├─ Check if CSV already exists (skip)
      ├─ backend.extract_features() -> Get opcode list
      ├─ Write CSV (common handles this, not backend)
      └─ Record timing
6. cleanup()                        -> Clean up temp files (e.g. Ghidra projects)
```

Key design decisions:
- CSV writing moved from backends to `common.py` for format consistency
- Timing recorded uniformly by `common.py`, not by each backend
- `time.perf_counter()` replaces `time.process_time()` for wall-clock time
- Loggers not passed across processes; workers rebuild logger from name + output_dir

## Bug Fixes Included

| # | Issue | Fix |
|---|-------|-----|
| 1 | Radare2 Dockerfile filename mismatch (`install_radare2.sh` vs `radare2_deploy.sh`) | Unify to `radare2_deploy.sh` |
| 2 | `time.process_time()` measures only CPU time, useless for subprocess work | Use `time.perf_counter()` |
| 3 | `os.cpu_count()` can return `None` | Fallback: `os.cpu_count() or 1` |
| 4 | Logger objects passed across process boundaries (unsafe serialization) | Rebuild logger in worker from name + output_dir |
| 5 | `timing.log` concurrent write race condition in Ghidra script | Timing handled by `common.py` only; Ghidra script no longer writes timing.log |

## Code Cleanup Included

| # | Issue | Fix |
|---|-------|-----|
| 6 | Unused imports (`pandas` in Ghidra, `Dict`/`Any`) | Remove |
| 7 | Ghidra missing `requirements.txt` | Single unified `requirements.txt` at root |
| 8 | `r2_timeout_check.sh` unquoted variables | Add double quotes |
| 9 | Extra blank line in Radare2 `extraction()` | Remove |
| 10 | No input directory validation | Validate in `common.run()` |

## Documentation Updates

| # | Issue | Fix |
|---|-------|-----|
| 11 | Root README too short | Rewrite with full project intro, install, unified CLI usage, all parameter examples, output format |
| 12 | Sub-module READMEs don't match new architecture | Update to reflect new structure |
| 13 | IDA Pro references | Keep, mark as planned/future |

## What Does NOT Change

- `ghidra_opcode_script.py` core logic (runs inside Ghidra JVM with its own constraints)
  - But: remove its direct `timing.log` writing; timing handled externally
- All IDA Pro placeholder descriptions retained for future implementation
- MIT License unchanged
