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
