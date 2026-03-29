import os
import argparse
import logging
from abc import ABC, abstractmethod
from typing import Dict, List

SCRIPTS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'scripts')
)


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
                         extraction_logger: logging.Logger) -> List[Dict]:
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
