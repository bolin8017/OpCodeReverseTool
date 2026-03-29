import os
import csv
import shutil
import logging
import argparse
import subprocess
from typing import Dict, List

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
                         extraction_logger: logging.Logger) -> List[Dict]:
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
