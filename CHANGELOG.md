# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-31

### Added

- Unified CLI framework with `BaseBackend` abstract base class
- Radare2 backend for opcode extraction
- Ghidra backend for opcode extraction
- Parallel processing support for batch binary analysis
- `--pattern` glob support for selecting input binaries
- CSV output format for extracted opcode data

### Fixed

- Replaced `time.process_time` with `time.perf_counter` for accurate wall-clock timing
- Default CPU count to `os.cpu_count() or 1` to avoid `None` on unsupported platforms
- Logger rebuild in worker processes to prevent logging issues in multiprocessing
- Corrected Radare2 Dockerfile filename
- Fixed variable quoting in `r2_timeout_check.sh`
