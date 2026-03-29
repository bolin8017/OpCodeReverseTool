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


def configure_logging(output_dir: str) -> None:
    """Configure logging for the main process.
    Sets up extraction and timing loggers. Worker processes create
    their own loggers via _get_extraction_logger/_get_timing_logger."""
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
    """Process extraction tasks in parallel."""
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
    parallel_process(files, backend_name, args, output_dir, args.timeout)

    backend.cleanup()
    print("Extraction complete.")
