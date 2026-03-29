# Unified API Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor OpCodeReverseTool into a unified framework with single CLI entry, ABC-based backend abstraction, and consistent output format.

**Architecture:** Single `get_opcode.py` entry point selects a backend (ghidra/radare2) via `-b` flag. Shared logic (logging, parallel processing, CSV writing, file filtering) lives in `opcode_tool/common.py`. Each backend implements `BaseBackend` ABC with `extract_features()`, `validate_environment()`, and `add_arguments()`.

**Tech Stack:** Python 3.x, argparse, ProcessPoolExecutor, csv, logging, r2pipe (radare2), subprocess (ghidra)

**Spec:** `docs/superpowers/specs/2026-03-29-unified-api-refactor-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `get_opcode.py` | Create | Unified CLI entry point |
| `requirements.txt` | Create (root) | Unified Python dependencies |
| `opcode_tool/__init__.py` | Create | Package marker |
| `opcode_tool/common.py` | Create | Shared logic: logging, parallel, CSV, file filtering |
| `opcode_tool/backends/__init__.py` | Create | Backend registry + `get_backend()` |
| `opcode_tool/backends/base.py` | Create | `BaseBackend` ABC |
| `opcode_tool/backends/ghidra.py` | Create | `GhidraBackend` implementation |
| `opcode_tool/backends/radare2.py` | Create | `Radare2Backend` implementation |
| `scripts/ghidra_opcode_script.py` | Create (moved + simplified from `Ghidra/`) | Ghidra internal script |
| `scripts/r2_timeout_check.sh` | Create (moved + fixed from `Radare2/`) | Radare2 timeout check |
| `deployment-scripts/radare2_deploy/Dockerfile` | Modify | Fix filename mismatch bug |
| `.gitignore` | Modify | Add new paths |
| `README.md` | Rewrite | Comprehensive unified docs |
| `README.zh-TW.md` | Create | Traditional Chinese docs |
| `Ghidra/` | Delete | Replaced by `opcode_tool/backends/ghidra.py` |
| `Radare2/` | Delete | Replaced by `opcode_tool/backends/radare2.py` |

---

### Task 1: Package Scaffolding + BaseBackend ABC + Registry

**Files:**
- Create: `opcode_tool/__init__.py`
- Create: `opcode_tool/backends/__init__.py`
- Create: `opcode_tool/backends/base.py`

- [ ] **Step 1: Create package directory structure**

```bash
mkdir -p opcode_tool/backends
```

- [ ] **Step 2: Create `opcode_tool/__init__.py`**

```python
"""OpCodeReverseTool - Unified opcode extraction framework."""
```

- [ ] **Step 3: Create `opcode_tool/backends/base.py`**

```python
import argparse
import logging
from abc import ABC, abstractmethod


class BaseBackend(ABC):
    """Abstract base class for opcode extraction backends."""

    worker_multiplier = 2

    def __init__(self, args: argparse.Namespace, output_dir: str):
        self.args = args
        self.output_dir = output_dir

    @classmethod
    @abstractmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Inject backend-specific CLI arguments into the parser."""
        ...

    @abstractmethod
    def validate_environment(self) -> None:
        """Check that the backend tool is available.

        Raises:
            RuntimeError: If the backend tool is not found or not usable.
        """
        ...

    @abstractmethod
    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> list[dict]:
        """Extract opcodes from a binary file.

        Args:
            input_file: Path to the binary file.
            timeout: Maximum seconds to allow for extraction.
            extraction_logger: Logger for recording errors.

        Returns:
            List of dicts with keys: 'addr' (int), 'opcode' (str),
            'section_name' (str). Empty list if extraction failed.
        """
        ...

    def cleanup(self) -> None:
        """Clean up backend-specific temporary resources. Default: no-op."""
        pass
```

- [ ] **Step 4: Create `opcode_tool/backends/__init__.py`**

This is a placeholder that will be completed after the backends are created. For now, create it with a forward-looking structure:

```python
"""Backend registry for OpCodeReverseTool."""

BACKEND_REGISTRY = {}


def get_backend(name: str):
    """Get a backend class by name.

    Args:
        name: Backend name (e.g., 'ghidra', 'radare2').

    Returns:
        Backend class.

    Raises:
        ValueError: If backend name is not registered.
    """
    if name not in BACKEND_REGISTRY:
        available = ', '.join(BACKEND_REGISTRY.keys())
        raise ValueError(f"Unknown backend '{name}'. Available: {available}")
    return BACKEND_REGISTRY[name]
```

- [ ] **Step 5: Commit**

```bash
git add opcode_tool/
git commit -m "feat: create package scaffolding with BaseBackend ABC and registry"
```

---

### Task 2: Shared Logic (`common.py`)

**Files:**
- Create: `opcode_tool/common.py`

- [ ] **Step 1: Create `opcode_tool/common.py`**

```python
import os
import csv
import time
import logging
import fnmatch
from typing import List, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

from tqdm import tqdm

from opcode_tool.backends import get_backend

RESULTS_SUBDIR = "results"


def setup_output_directory(input_dir: str, custom_output_dir: str = None) -> str:
    """Set up the output directory structure.

    Args:
        input_dir: Path to the input binary directory.
        custom_output_dir: Optional custom output directory path.

    Returns:
        Path to the output directory.
    """
    if custom_output_dir:
        output_dir = custom_output_dir
    else:
        output_dir = os.path.join(
            os.path.dirname(input_dir),
            f"{os.path.basename(input_dir)}_disassemble"
        )
    print(f"Output directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, RESULTS_SUBDIR), exist_ok=True)
    return output_dir


def configure_logging(output_dir: str) -> None:
    """Configure logging for the main process.

    Sets up extraction and timing loggers. Worker processes create
    their own loggers via _get_extraction_logger/_get_timing_logger.

    Args:
        output_dir: Path to the output directory.
    """
    extraction_log_file = os.path.join(output_dir, 'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    extraction_logger = logging.getLogger('extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    extraction_logger.handlers.clear()
    handler = logging.FileHandler(extraction_log_file)
    handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    )
    extraction_logger.addHandler(handler)

    timing_log_file = os.path.join(output_dir, 'timing.log')
    print(f"Timing log: {timing_log_file}")
    timing_logger = logging.getLogger('timing_logger')
    timing_logger.setLevel(logging.INFO)
    timing_logger.handlers.clear()
    timing_handler = logging.FileHandler(timing_log_file)
    timing_handler.setFormatter(logging.Formatter('%(message)s'))
    timing_logger.addHandler(timing_handler)


def _get_extraction_logger(output_dir: str) -> logging.Logger:
    """Get or create extraction logger for a worker process."""
    logger = logging.getLogger(f'extraction_{os.getpid()}')
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(
            os.path.join(output_dir, 'extraction.log')
        )
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        logger.addHandler(handler)
    return logger


def _get_timing_logger(output_dir: str) -> logging.Logger:
    """Get or create timing logger for a worker process."""
    logger = logging.getLogger(f'timing_{os.getpid()}')
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(
            os.path.join(output_dir, 'timing.log')
        )
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
    return logger


def collect_files(binary_path: str, output_path: str,
                  pattern: str = None) -> List[Tuple[str, str, str]]:
    """Collect binary files to process.

    Args:
        binary_path: Root directory containing binary files.
        output_path: Output directory for CSV results.
        pattern: Optional glob pattern for filtering files.
                 Default (None) matches files without extensions.

    Returns:
        List of (input_file_path, output_csv_path, filename) tuples.
    """
    files = []
    for root, _, filenames in os.walk(binary_path):
        for filename in filenames:
            if pattern:
                if not fnmatch.fnmatch(filename, pattern):
                    continue
            else:
                # Default: only files without extensions (e.g. hash-named binaries)
                if '.' in filename:
                    continue

            input_file = os.path.join(root, filename)
            subdir = filename[:2]
            output_csv = os.path.join(
                output_path, RESULTS_SUBDIR, subdir, f"{filename}.csv"
            )
            files.append((input_file, output_csv, filename))
    return files


def write_csv(opcodes: List[dict], output_path: str) -> None:
    """Write extracted opcodes to a CSV file.

    Args:
        opcodes: List of dicts with keys 'addr', 'opcode', 'section_name'.
        output_path: Path to the output CSV file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(
            f, fieldnames=['addr', 'opcode', 'section_name']
        )
        writer.writeheader()
        writer.writerows(opcodes)


def _extraction_worker(backend_name: str, args, input_file: str,
                       output_csv: str, filename: str,
                       output_dir: str, timeout: int) -> float:
    """Worker function for parallel extraction. Runs in a separate process.

    Returns:
        Execution time in seconds, or 0.0 if failed/skipped.
    """
    extraction_logger = _get_extraction_logger(output_dir)

    if os.path.exists(output_csv):
        extraction_logger.info(f"File already exists: {output_csv}")
        return 0.0

    start_time = time.perf_counter()

    try:
        backend_cls = get_backend(backend_name)
        backend = backend_cls(args, output_dir)
        opcodes = backend.extract_features(input_file, timeout,
                                           extraction_logger)
        execution_time = time.perf_counter() - start_time

        if not opcodes:
            return 0.0

        write_csv(opcodes, output_csv)

        timing_logger = _get_timing_logger(output_dir)
        timing_logger.info(f"{filename},{execution_time:.2f}")

        extraction_logger.info(
            f"{filename}: Successfully extracted opcode information"
        )
        return execution_time

    except FileNotFoundError:
        extraction_logger.error(
            f"{filename}: File not found - {input_file}"
        )
    except Exception as e:
        extraction_logger.exception(
            f"{filename}: Unexpected error - {e}"
        )

    return 0.0


def parallel_process(files: List[Tuple[str, str, str]], backend_name: str,
                     args, output_dir: str, timeout: int) -> None:
    """Process extraction tasks in parallel.

    Args:
        files: List of (input_file, output_csv, filename) tuples.
        backend_name: Name of the backend to use.
        args: Parsed CLI arguments.
        output_dir: Output directory path.
        timeout: Timeout in seconds per file.
    """
    if not files:
        print("No files to process.")
        return

    backend_cls = get_backend(backend_name)
    cpu_count = os.cpu_count() or 1
    max_workers = min(cpu_count * backend_cls.worker_multiplier, len(files))

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                _extraction_worker, backend_name, args,
                input_file, output_csv, filename,
                output_dir, timeout
            )
            for input_file, output_csv, filename in files
        ]
        with tqdm(total=len(futures), desc="Processing files",
                  unit="file") as pbar:
            for _ in as_completed(futures):
                pbar.update(1)


def run(backend_name: str, args) -> None:
    """Main orchestration function.

    Args:
        backend_name: Name of the backend to use.
        args: Parsed CLI arguments (must have .directory, .output,
              .timeout, .pattern attributes).
    """
    output_dir = setup_output_directory(args.directory, args.output)
    configure_logging(output_dir)

    backend_cls = get_backend(backend_name)
    backend = backend_cls(args, output_dir)
    backend.validate_environment()

    files = collect_files(args.directory, output_dir, args.pattern)
    if not files:
        print(f"No matching files found in {args.directory}")
        return

    print(f"Found {len(files)} files to process")
    parallel_process(files, backend_name, args, output_dir, args.timeout)

    backend.cleanup()
    print("Extraction complete.")
```

- [ ] **Step 2: Commit**

```bash
git add opcode_tool/common.py
git commit -m "feat: add shared logic module (logging, parallel, CSV, file filtering)"
```

---

### Task 3: GhidraBackend + Ghidra Script

**Files:**
- Create: `opcode_tool/backends/ghidra.py`
- Create: `scripts/ghidra_opcode_script.py` (simplified from `Ghidra/ghidra_opcode_script.py`)

- [ ] **Step 1: Create `scripts/` directory**

```bash
mkdir -p scripts
```

- [ ] **Step 2: Create `scripts/ghidra_opcode_script.py`**

Simplified from original: accepts only a temp CSV path argument, no timing.log writing, no logging (errors communicated via exceptions and missing CSV).

```python
"""Ghidra postScript for opcode extraction.

Runs inside Ghidra's headless analyzer environment.
Receives one argument: the path where the temp CSV should be written.

Uses .format() instead of f-strings for Jython/Ghidrathon compatibility.
"""
import os
import csv
from ghidra.program.model.address import AddressSet
from ghidra.app.cmd.disassemble import DisassembleCommand

argv = getScriptArgs()

if len(argv) < 1:
    raise ValueError("Missing argument: CSV output path")

csv_output_path = argv[0]
file_name = currentProgram().getName()

memory_blocks = currentProgram().getMemory().getBlocks()

if not memory_blocks:
    raise Exception("{}: No memory blocks found - file may be packed, damaged, or incomplete".format(file_name))

all_opcodes = []
for block in memory_blocks:
    section_name = block.getName()
    address_set = AddressSet(block.getStart(), block.getEnd())

    # Manually disassemble since we use -noanalysis
    disassemble_cmd = DisassembleCommand(address_set, address_set, True)
    disassemble_cmd.applyTo(currentProgram())

    instructions = currentProgram().getListing().getInstructions(address_set, True)
    for instr in instructions:
        addr = int(instr.getAddress().getOffset())
        opcode = str(instr).split(' ')[0]
        all_opcodes.append([addr, opcode, section_name])

if not all_opcodes:
    raise Exception("{}: No instructions found in any memory block".format(file_name))

# Create output directory if needed
output_dir = os.path.dirname(csv_output_path)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

with open(csv_output_path, 'w', newline='', encoding='utf-8') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['addr', 'opcode', 'section_name'])
    csvwriter.writerows(all_opcodes)
```

- [ ] **Step 3: Create `opcode_tool/backends/ghidra.py`**

```python
import os
import csv
import shutil
import logging
import argparse
import subprocess

from opcode_tool.backends.base import BaseBackend

SCRIPTS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'scripts')
)
GHIDRA_SCRIPT_NAME = 'ghidra_opcode_script.py'
GHIDRA_PROJECTS_SUBDIR = 'ghidra_projects'


class GhidraBackend(BaseBackend):
    """Ghidra-based opcode extraction backend."""

    # Ghidra spends most time waiting for I/O
    worker_multiplier = 2

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '-g', '--ghidra', type=str,
            help='Path to Ghidra headless analyzer (analyzeHeadless)'
        )

    def validate_environment(self) -> None:
        if not self.args.ghidra:
            raise RuntimeError(
                "Ghidra backend requires -g/--ghidra argument"
            )
        ghidra_path = os.path.normpath(
            os.path.expanduser(self.args.ghidra)
        )
        if not os.path.exists(ghidra_path):
            raise RuntimeError(
                f"Ghidra headless analyzer not found at {ghidra_path}"
            )
        self.args.ghidra = ghidra_path

        script_path = os.path.join(SCRIPTS_DIR, GHIDRA_SCRIPT_NAME)
        if not os.path.exists(script_path):
            raise RuntimeError(
                f"Ghidra script not found at {script_path}"
            )

    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> list[dict]:
        file_name = os.path.basename(input_file)
        project_name = f"{file_name}_project"
        project_folder = os.path.join(
            self.output_dir, GHIDRA_PROJECTS_SUBDIR, project_name
        )
        temp_csv = os.path.join(project_folder, f"{file_name}.csv")

        os.makedirs(project_folder, exist_ok=True)

        script_path = os.path.join(SCRIPTS_DIR, GHIDRA_SCRIPT_NAME)

        try:
            result = subprocess.run([
                'timeout', '--kill-after=10', str(timeout),
                self.args.ghidra, project_folder, project_name,
                '-import', input_file,
                '-noanalysis',
                '-scriptPath', SCRIPTS_DIR,
                '-postScript', script_path,
                temp_csv
            ], capture_output=True, text=True)

            if result.returncode == 124:
                extraction_logger.error(
                    f"{file_name}: File analysis timed out "
                    f"after {timeout} seconds"
                )
                return []

            if result.returncode != 0:
                extraction_logger.error(
                    f"{file_name}: Ghidra analysis failed "
                    f"with exit code {result.returncode}"
                )
                return []

            if not os.path.exists(temp_csv):
                stderr_tail = (result.stderr[-500:]
                               if result.stderr else "no output")
                extraction_logger.error(
                    f"{file_name}: Output CSV not found. "
                    f"Ghidra output: {stderr_tail}"
                )
                return []

            # Read temp CSV into list of dicts
            opcodes = []
            with open(temp_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    opcodes.append({
                        'addr': int(row['addr']),
                        'opcode': row['opcode'],
                        'section_name': row['section_name']
                    })

            return opcodes

        except Exception as e:
            extraction_logger.error(
                f"{file_name}: Unexpected error - {e}"
            )
            return []
        finally:
            if os.path.exists(project_folder):
                shutil.rmtree(project_folder, ignore_errors=True)

    def cleanup(self) -> None:
        """Remove the ghidra_projects temporary directory."""
        ghidra_projects = os.path.join(
            self.output_dir, GHIDRA_PROJECTS_SUBDIR
        )
        if os.path.exists(ghidra_projects):
            shutil.rmtree(ghidra_projects, ignore_errors=True)
```

- [ ] **Step 4: Commit**

```bash
git add scripts/ghidra_opcode_script.py opcode_tool/backends/ghidra.py
git commit -m "feat: add GhidraBackend and simplified Ghidra extraction script"
```

---

### Task 4: Radare2Backend + Fix Timeout Script

**Files:**
- Create: `opcode_tool/backends/radare2.py`
- Create: `scripts/r2_timeout_check.sh` (moved + fixed from `Radare2/`)

- [ ] **Step 1: Create `scripts/r2_timeout_check.sh`**

Fixed: all variables properly quoted.

```bash
#!/bin/bash

input_file="$1"
timeout_seconds="$2"

timeout --kill-after=10 "$timeout_seconds" r2 -qc "aaa" "$input_file" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "true"
else
    echo "false"
fi
```

- [ ] **Step 2: Make the script executable**

```bash
chmod +x scripts/r2_timeout_check.sh
```

- [ ] **Step 3: Create `opcode_tool/backends/radare2.py`**

```python
import os
import logging
import argparse
import subprocess
from contextlib import contextmanager

import r2pipe

from opcode_tool.backends.base import BaseBackend

SCRIPTS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'scripts')
)
R2_TIMEOUT_SCRIPT = 'r2_timeout_check.sh'


class Radare2Backend(BaseBackend):
    """Radare2-based opcode extraction backend."""

    # r2pipe spawns r2 processes; keep worker count conservative
    worker_multiplier = 1

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        # Radare2 has no additional required arguments
        pass

    def validate_environment(self) -> None:
        script_path = os.path.join(SCRIPTS_DIR, R2_TIMEOUT_SCRIPT)
        if not os.path.exists(script_path):
            raise RuntimeError(
                f"{R2_TIMEOUT_SCRIPT} not found in {SCRIPTS_DIR}"
            )
        if not os.access(script_path, os.X_OK):
            raise RuntimeError(
                f"{R2_TIMEOUT_SCRIPT} in {SCRIPTS_DIR} is not executable"
            )

    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> list[dict]:
        file_name = os.path.basename(input_file)

        # Pre-flight timeout check
        if not self._check_timeout(input_file, timeout):
            extraction_logger.error(
                f"{file_name}: File analysis timed out "
                f"after {timeout} seconds"
            )
            return []

        try:
            with self._open_r2pipe(input_file) as r2:
                r2.cmd("e asm.flags.middle=0")
                sections = r2.cmdj('iSj')

                if not sections:
                    extraction_logger.error(
                        f"{file_name}: No sections found - "
                        f"file may be packed, damaged, or incomplete"
                    )
                    return []

                all_opcodes = [
                    {
                        'addr': instr['offset'],
                        'opcode': (instr['opcode'].split()[0]
                                   if 'opcode' in instr else ''),
                        'section_name': section['name']
                    }
                    for section in sections
                    if section['size'] > 0
                    for instr in (
                        r2.cmdj(
                            f"pDj {section['size']} @{section['vaddr']}"
                        ) or []
                    )
                ]

                return all_opcodes

        except Exception as e:
            extraction_logger.error(
                f"{file_name}: Unexpected error - {e}"
            )
            return []

    @staticmethod
    def _check_timeout(input_file: str, timeout: int) -> bool:
        """Run pre-flight timeout check using r2_timeout_check.sh."""
        script_path = os.path.join(SCRIPTS_DIR, R2_TIMEOUT_SCRIPT)
        try:
            result = subprocess.run(
                [script_path, input_file, str(timeout)],
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip() == "true"
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    @contextmanager
    def _open_r2pipe(file_path: str):
        """Context manager for r2pipe to ensure proper cleanup."""
        r2 = None
        try:
            r2 = r2pipe.open(file_path, flags=['-2'])
            yield r2
        finally:
            if r2:
                r2.quit()
```

- [ ] **Step 4: Commit**

```bash
git add scripts/r2_timeout_check.sh opcode_tool/backends/radare2.py
git commit -m "feat: add Radare2Backend and fix timeout script variable quoting"
```

---

### Task 5: Finalize Backend Registry + Unified CLI Entry Point

**Files:**
- Modify: `opcode_tool/backends/__init__.py`
- Create: `get_opcode.py` (root)

- [ ] **Step 1: Update `opcode_tool/backends/__init__.py` with real imports**

Replace the placeholder registry with actual backend imports:

```python
"""Backend registry for OpCodeReverseTool."""

from opcode_tool.backends.ghidra import GhidraBackend
from opcode_tool.backends.radare2 import Radare2Backend

BACKEND_REGISTRY = {
    'ghidra': GhidraBackend,
    'radare2': Radare2Backend,
}


def get_backend(name: str):
    """Get a backend class by name.

    Args:
        name: Backend name (e.g., 'ghidra', 'radare2').

    Returns:
        Backend class.

    Raises:
        ValueError: If backend name is not registered.
    """
    if name not in BACKEND_REGISTRY:
        available = ', '.join(BACKEND_REGISTRY.keys())
        raise ValueError(
            f"Unknown backend '{name}'. Available: {available}"
        )
    return BACKEND_REGISTRY[name]
```

- [ ] **Step 2: Create `get_opcode.py` at project root**

```python
#!/usr/bin/env python3
"""OpCodeReverseTool - Unified opcode extraction from binary files.

Supports multiple reverse engineering backends through a single CLI.
"""

import os
import sys
import argparse

from opcode_tool.backends import get_backend, BACKEND_REGISTRY
from opcode_tool.common import run


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description='Extract address and opcode information '
                    'from binary files.'
    )
    parser.add_argument(
        '-b', '--backend', type=str, required=True,
        choices=BACKEND_REGISTRY.keys(),
        help='Reverse engineering backend to use'
    )
    parser.add_argument(
        '-d', '--directory', type=str, required=True,
        help='Path to the binary directory'
    )
    parser.add_argument(
        '-o', '--output', type=str,
        help='Path to the output directory '
             '(default: <input_dir>_disassemble)'
    )
    parser.add_argument(
        '-t', '--timeout', type=int, default=600,
        help='Timeout duration in seconds (default: 600)'
    )
    parser.add_argument(
        '--pattern', type=str, default=None,
        help='Glob pattern to filter files '
             '(default: files without extensions)'
    )

    # Let each backend inject its own arguments
    for backend_cls in BACKEND_REGISTRY.values():
        backend_cls.add_arguments(parser)

    args = parser.parse_args()
    args.directory = os.path.normpath(os.path.expanduser(args.directory))
    if args.output:
        args.output = os.path.normpath(os.path.expanduser(args.output))
    return args


def main() -> None:
    """Main entry point."""
    args = parse_arguments()

    if not os.path.isdir(args.directory):
        print(f"Error: Directory not found: {args.directory}")
        sys.exit(1)

    run(args.backend, args)


if __name__ == '__main__':
    main()
```

- [ ] **Step 3: Verify CLI help output**

```bash
python get_opcode.py --help
```

Expected: shows all shared arguments (`-b`, `-d`, `-o`, `-t`, `--pattern`) plus backend-specific ones (`-g`).

- [ ] **Step 4: Commit**

```bash
git add opcode_tool/backends/__init__.py get_opcode.py
git commit -m "feat: add unified CLI entry point with backend selection"
```

---

### Task 6: Config Fixes (requirements.txt, Dockerfile, .gitignore)

**Files:**
- Create: `requirements.txt` (root)
- Modify: `deployment-scripts/radare2_deploy/Dockerfile`
- Modify: `.gitignore`

- [ ] **Step 1: Create unified `requirements.txt` at project root**

```
r2pipe>=1.8.8
pandas>=2.2.2
tqdm>=4.66.1
```

Note: `pandas` is kept because it may be useful for downstream analysis. `r2pipe` is only needed for the radare2 backend but is listed here for simplicity.

- [ ] **Step 2: Fix Radare2 Dockerfile filename mismatch**

In `deployment-scripts/radare2_deploy/Dockerfile`, change:

```dockerfile
# Use an official base image
FROM ubuntu:latest

# Install base utilities
RUN apt-get update && apt-get install -y git make sudo

# Create a new user and add to sudo group
RUN useradd -m radare2user \
    && echo "radare2user:radare2user" | chpasswd \
    && adduser radare2user sudo

# Switch to the new user
USER radare2user

# Set working directory
WORKDIR /home/radare2user

# Copy the installation script into the container
COPY --chown=radare2user:radare2user radare2_deploy.sh /home/radare2user/radare2_deploy.sh

# Grant execution permissions to the script
RUN chmod +x /home/radare2user/radare2_deploy.sh

# Run the script when the container starts
CMD ["/home/radare2user/radare2_deploy.sh"]
```

- [ ] **Step 3: Update `.gitignore`**

Add new paths for the refactored structure:

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Jupyter Notebook
.ipynb_checkpoints

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Project specific - Output directories
*_disassemble/
results/
ghidra_projects/

# Project specific - Log files
*.log
extraction.log
timing.log

# Project specific - Test data and binaries
test_data/
test_binaries/
sample_binaries/

# Temporary files
*.tmp
*.temp
*.bak

# CSV output files (uncomment if you want to ignore CSV results)
# *.csv

# Ghidra project files
*.gpr
*.rep/
*.lock

# Docs build artifacts
docs/superpowers/
```

- [ ] **Step 4: Commit**

```bash
git add requirements.txt deployment-scripts/radare2_deploy/Dockerfile .gitignore
git commit -m "fix: unified requirements.txt, Radare2 Dockerfile filename, .gitignore"
```

---

### Task 7: Documentation (README.md + README.zh-TW.md)

**Files:**
- Rewrite: `README.md`
- Create: `README.zh-TW.md`

- [ ] **Step 1: Rewrite `README.md`**

```markdown
# OpCodeReverseTool

[English](README.md) | [繁體中文](README.zh-TW.md)

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
```

- [ ] **Step 2: Create `README.zh-TW.md`**

```markdown
# OpCodeReverseTool

[English](README.md) | [繁體中文](README.zh-TW.md)

統一的二進位檔案 opcode 提取框架，專為安全研究人員和逆向工程師設計。無論使用哪種逆向工程後端，都能透過單一 CLI 介面從二進位檔案中提取操作碼（opcodes）。

## 支援的後端

- **[Ghidra](https://ghidra-sre.org/)** - 美國國家安全局開源的逆向工程框架，具備強大的反組譯能力
- **[Radare2](https://www.radare.org/n/)** - 免費開源的逆向工程框架，支援多種架構
- **[IDA Pro](https://www.hex-rays.com/products/ida/)** - *（計劃中）* 業界標準的反組譯器和除錯器

## 安裝

### 前置需求

- Python 3.8+
- 至少安裝一個支援的後端：
  - **Ghidra**：從 [ghidra-sre.org](https://ghidra-sre.org/) 下載，需要 Java 17+
  - **Radare2**：從原始碼編譯或透過套件管理器安裝

### 安裝 Python 依賴

```bash
pip install -r requirements.txt
```

### Docker 部署（可選）

預設的 Docker 環境配置在 `deployment-scripts/` 中。詳見 [deployment-scripts/README.md](deployment-scripts/README.md)。

## 使用方法

### 基本語法

```bash
python get_opcode.py -b <後端> -d <二進位檔案目錄> [選項]
```

### 命令列參數

| 參數 | 必需 | 說明 |
|------|------|------|
| `-b, --backend` | 是 | 使用的後端：`ghidra` 或 `radare2` |
| `-d, --directory` | 是 | 包含二進位檔案的目錄路徑 |
| `-o, --output` | 否 | 輸出目錄（預設：`<input_dir>_disassemble`） |
| `-t, --timeout` | 否 | 每個檔案的超時時間（秒）（預設：600） |
| `--pattern` | 否 | 檔案過濾的 glob 模式（預設：無副檔名的檔案） |
| `-g, --ghidra` | 僅 Ghidra | Ghidra `analyzeHeadless` 腳本的路徑 |

### 使用範例

#### Ghidra 後端

```bash
# 基本使用
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless

# 自訂輸出目錄
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless -o /path/to/output

# 自訂超時時間（1200 秒）
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless -t 1200

# 僅處理 .exe 檔案
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless --pattern "*.exe"

# 組合所有選項
python get_opcode.py -b ghidra -d /path/to/binaries -g ~/ghidra/support/analyzeHeadless -o /path/to/output -t 1200 --pattern "*.exe"
```

#### Radare2 後端

```bash
# 基本使用
python get_opcode.py -b radare2 -d /path/to/binaries

# 自訂輸出目錄
python get_opcode.py -b radare2 -d /path/to/binaries -o /path/to/output

# 自訂超時時間（600 秒）
python get_opcode.py -b radare2 -d /path/to/binaries -t 600

# 處理所有檔案（包括有副檔名的）
python get_opcode.py -b radare2 -d /path/to/binaries --pattern "*"

# 組合所有選項
python get_opcode.py -b radare2 -d /path/to/binaries -o /path/to/output -t 600 --pattern "*"
```

## 輸出格式

### 目錄結構

所有後端產生相同的輸出結構：

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

結果按檔案名稱的前兩個字元組織到子目錄中，避免單一目錄累積過多檔案。

### CSV 格式

每個 CSV 檔案包含三個欄位：

```csv
addr,opcode,section_name
4194356,nop,segment_1.1
4194360,mov,.text
4194368,push,.text
```

| 欄位 | 型態 | 說明 |
|------|------|------|
| `addr` | int | 指令地址 |
| `opcode` | str | 指令助記符（僅第一個 token） |
| `section_name` | str | 二進位檔案的節區/段落名稱 |

### 日誌檔案

- **extraction.log** - 記錄每個檔案的提取成功/失敗
- **timing.log** - 記錄每個檔案的處理時間（`filename,seconds`）

## 專案結構

```
OpCodeReverseTool/
├── get_opcode.py              # 統一 CLI 入口
├── requirements.txt           # Python 依賴
├── opcode_tool/
│   ├── __init__.py
│   ├── common.py              # 共用邏輯（日誌、並行處理、CSV）
│   └── backends/
│       ├── __init__.py        # 後端註冊表
│       ├── base.py            # BaseBackend ABC
│       ├── ghidra.py          # Ghidra 後端
│       └── radare2.py         # Radare2 後端
├── scripts/
│   ├── ghidra_opcode_script.py  # Ghidra 內部提取腳本
│   └── r2_timeout_check.sh     # Radare2 超時檢查
├── deployment-scripts/        # Docker 部署配置
├── output/                    # 範例輸出
└── test_data/                 # 範例測試二進位檔案
```

## 功能特性

- **統一 CLI** - 所有後端使用單一命令介面
- **並行處理** - 利用多核心 CPU 進行批次提取
- **超時保護** - 可設定每個檔案的超時時間，處理有問題的二進位檔案
- **彈性檔案過濾** - 支援 glob 模式選擇特定檔案類型
- **一致的輸出** - 所有後端產生相同的 CSV 格式和目錄結構
- **可擴展架構** - 基於 ABC 的後端系統，輕鬆新增工具支援
- **完整日誌** - 分別記錄提取和計時日誌，便於除錯和分析
- **資源清理** - 處理完成後自動清理臨時檔案

## 新增後端

實作 `BaseBackend` 抽象類別：

```python
from opcode_tool.backends.base import BaseBackend

class MyBackend(BaseBackend):
    @classmethod
    def add_arguments(cls, parser):
        # 新增後端專屬的 CLI 參數
        pass

    def validate_environment(self):
        # 檢查工具可用性
        pass

    def extract_features(self, input_file, timeout, extraction_logger):
        # 回傳 [{'addr': int, 'opcode': str, 'section_name': str}, ...]
        pass
```

然後在 `opcode_tool/backends/__init__.py` 中註冊。

## 授權

本專案採用 MIT 授權條款 - 詳見 [LICENSE](LICENSE) 檔案。
```

- [ ] **Step 3: Commit**

```bash
git add README.md README.zh-TW.md
git commit -m "docs: rewrite README with unified CLI docs in English and Traditional Chinese"
```

---

### Task 8: Remove Old Directories + Final Verification

**Files:**
- Delete: `Ghidra/` directory
- Delete: `Radare2/` directory

- [ ] **Step 1: Remove old module directories**

```bash
rm -rf Ghidra/ Radare2/
```

- [ ] **Step 2: Verify project structure**

```bash
find . -not -path './.git/*' -not -path './test_data/*' -not -path './output/*' -type f | sort
```

Expected structure:

```
./get_opcode.py
./requirements.txt
./LICENSE
./README.md
./README.zh-TW.md
./.gitignore
./opcode_tool/__init__.py
./opcode_tool/common.py
./opcode_tool/backends/__init__.py
./opcode_tool/backends/base.py
./opcode_tool/backends/ghidra.py
./opcode_tool/backends/radare2.py
./scripts/ghidra_opcode_script.py
./scripts/r2_timeout_check.sh
./deployment-scripts/README.md
./deployment-scripts/ghidra_deploy/Dockerfile
./deployment-scripts/ghidra_deploy/ghidra_deploy.sh
./deployment-scripts/radare2_deploy/Dockerfile
./deployment-scripts/radare2_deploy/radare2_deploy.sh
./docs/superpowers/specs/2026-03-29-unified-api-refactor-design.md
./docs/superpowers/plans/2026-03-29-unified-api-refactor.md
```

- [ ] **Step 3: Verify CLI help output works**

```bash
python get_opcode.py --help
```

Expected: shows unified help with all arguments including `-b`, `-d`, `-o`, `-t`, `--pattern`, `-g`.

- [ ] **Step 4: Verify Python imports work**

```bash
python -c "from opcode_tool.backends import BACKEND_REGISTRY; print(list(BACKEND_REGISTRY.keys()))"
```

Expected: `['ghidra', 'radare2']`

- [ ] **Step 5: Commit removal of old directories**

```bash
git add -A
git commit -m "refactor: remove old Ghidra/ and Radare2/ directories, replaced by unified opcode_tool package"
```

---

## Self-Review Checklist

- [x] **Spec coverage**: All spec sections mapped to tasks (ABC in T1, common in T2, backends in T3-T4, CLI in T5, bug fixes in T6, docs in T7, cleanup in T8)
- [x] **Placeholder scan**: No TBD/TODO, all code complete
- [x] **Type consistency**: `BaseBackend` signature matches all implementations; `extract_features` returns `list[dict]` everywhere; `get_backend()` returns class, not instance
- [x] **Bug fixes covered**: Dockerfile (T6), `time.perf_counter` (T2), `os.cpu_count() or 1` (T2), logger rebuild in workers (T2), timing.log race condition removed (T3 ghidra script simplified), unused imports eliminated (all new code), variable quoting (T4)
