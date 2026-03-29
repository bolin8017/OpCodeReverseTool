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
