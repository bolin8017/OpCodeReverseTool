import os
import csv
import shutil
import logging
import argparse
import subprocess
from typing import Dict, List

from opcode_tool.backends.base import BaseBackend, SCRIPTS_DIR

GHIDRA_SCRIPT_NAME = 'ghidra_opcode_script.py'
GHIDRA_PROJECTS_SUBDIR = 'ghidra_projects'
_TIMEOUT_EXIT_CODE = 124


class GhidraBackend(BaseBackend):
    """Ghidra-based opcode extraction backend."""

    # Ghidra spends most time waiting for I/O
    worker_multiplier = 2

    def __init__(self, args: argparse.Namespace, output_dir: str):
        super().__init__(args, output_dir)
        self._ghidra_path = os.path.normpath(
            os.path.expanduser(self.args.ghidra)
        ) if self.args.ghidra else ''
        self._script_path = os.path.join(SCRIPTS_DIR, GHIDRA_SCRIPT_NAME)

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '-g', '--ghidra', type=str,
            help='Path to Ghidra headless analyzer (analyzeHeadless)'
        )

    def validate_environment(self) -> None:
        if not self._ghidra_path:
            raise RuntimeError(
                "Ghidra backend requires -g/--ghidra argument"
            )
        if not os.path.exists(self._ghidra_path):
            raise RuntimeError(
                f"Ghidra headless analyzer not found at {self._ghidra_path}"
            )
        if not os.path.exists(self._script_path):
            raise RuntimeError(
                f"Ghidra script not found at {self._script_path}"
            )

    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> List[Dict]:
        file_name = os.path.basename(input_file)
        project_name = f"{file_name}_project"
        project_folder = os.path.join(
            self.output_dir, GHIDRA_PROJECTS_SUBDIR, project_name
        )
        temp_csv = os.path.join(project_folder, f"{file_name}.csv")

        os.makedirs(project_folder, exist_ok=True)

        try:
            result = subprocess.run([
                'timeout', '--kill-after=10', str(timeout),
                self._ghidra_path, project_folder, project_name,
                '-import', input_file,
                '-noanalysis',
                '-scriptPath', SCRIPTS_DIR,
                '-postScript', self._script_path,
                temp_csv
            ], capture_output=True, text=True)

            if result.returncode == _TIMEOUT_EXIT_CODE:
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
            shutil.rmtree(project_folder, ignore_errors=True)

    def cleanup(self) -> None:
        """Remove the ghidra_projects temporary directory."""
        ghidra_projects = os.path.join(
            self.output_dir, GHIDRA_PROJECTS_SUBDIR
        )
        shutil.rmtree(ghidra_projects, ignore_errors=True)
