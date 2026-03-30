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
_EXTRACTION_LOG_FMT = '%(asctime)s - %(levelname)s - %(message)s'
_TIMING_LOG_FMT = '%(message)s'


def setup_output_directory(input_dir: str, custom_output_dir: str = None) -> str:
    """Set up the output directory structure."""
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


def _make_logger(name: str, log_file: str, fmt: str,
                 clear_handlers: bool = False) -> logging.Logger:
    """Create or get a logger with a file handler."""
    logger = logging.getLogger(name)
    if clear_handlers:
        logger.handlers.clear()
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
    return logger


def configure_logging(output_dir: str) -> None:
    """Configure logging for the main process.
    Sets up extraction and timing loggers. Worker processes create
    their own loggers via _get_extraction_logger/_get_timing_logger."""
    extraction_log_file = os.path.join(output_dir, 'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    _make_logger('extraction_logger', extraction_log_file,
                 _EXTRACTION_LOG_FMT, clear_handlers=True)

    timing_log_file = os.path.join(output_dir, 'timing.log')
    print(f"Timing log: {timing_log_file}")
    _make_logger('timing_logger', timing_log_file,
                 _TIMING_LOG_FMT, clear_handlers=True)


def _get_extraction_logger(output_dir: str) -> logging.Logger:
    """Get or create extraction logger for a worker process."""
    return _make_logger(
        f'extraction_{os.getpid()}',
        os.path.join(output_dir, 'extraction.log'),
        _EXTRACTION_LOG_FMT,
    )


def _get_timing_logger(output_dir: str) -> logging.Logger:
    """Get or create timing logger for a worker process."""
    return _make_logger(
        f'timing_{os.getpid()}',
        os.path.join(output_dir, 'timing.log'),
        _TIMING_LOG_FMT,
    )


def collect_files(binary_path: str, output_path: str,
                  pattern: str = None) -> List[Tuple[str, str, str]]:
    """Collect binary files to process.
    Default (pattern=None) matches files without extensions (e.g. hash-named binaries).
    Returns list of (input_file_path, output_csv_path, filename) tuples."""
    files = []
    for root, _, filenames in os.walk(binary_path):
        for filename in filenames:
            if pattern:
                if not fnmatch.fnmatch(filename, pattern):
                    continue
            else:
                # Default: only files without extensions
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
    """Write extracted opcodes to a CSV file."""
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
    Returns execution time in seconds, or 0.0 if failed/skipped."""
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
            extraction_logger.warning(
                f"{filename}: Backend returned no features, skipping"
            )
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
                     args, output_dir: str, timeout: int,
                     worker_multiplier: int) -> None:
    """Process extraction tasks in parallel.

    Args:
        worker_multiplier: Factor multiplied by CPU count to determine
            max worker processes (e.g. 2 for Ghidra, 1 for Radare2).
    """
    if not files:
        print("No files to process.")
        return

    cpu_count = os.cpu_count() or 1
    max_workers = min(cpu_count * worker_multiplier, len(files))
    succeeded = 0

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
            for future in as_completed(futures):
                try:
                    if future.result() > 0.0:
                        succeeded += 1
                except Exception:
                    pass
                pbar.update(1)

    failed = len(files) - succeeded
    print(f"Results: {succeeded} succeeded, {failed} failed/skipped")


def run(backend_name: str, args) -> None:
    """Main orchestration function."""
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
    try:
        parallel_process(files, backend_name, args, output_dir, args.timeout,
                         backend_cls.worker_multiplier)
    finally:
        backend.cleanup()
    print("Extraction complete.")
