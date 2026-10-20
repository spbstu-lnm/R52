#!/usr/bin/env python3
import sys
import argparse

import angr


def main():
    # Parse CLI arguments
    args = parse_args()

    # Load binary
    project = angr.Project(
        args.binary,
        ld_path=['/usr/lib/wine/i386-windows/'],
        #auto_load_libs=False,
    )

    # Check that angr identified it correctly
    print(project.arch)      # architecture (e.g. <Arch AMD64 (LE)>)
    print(project.simos)     # OS (<SimOS Windows>)

    # Establish initial state and exploration manager
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    # Explore the binary symbolically
    simulation.explore(find=lambda s: b"Success" in s.posix.dumps(1))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Symbolic execution of a binary using angr."
    )

    parser.add_argument("binary", help="Path to the binary to analyze.")
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())
