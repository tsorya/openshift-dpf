#!/usr/bin/env python3
"""Hold an anonymous executable mapping for Argus to observe."""

import argparse
import mmap
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hold-seconds", type=int, default=45)
    args = parser.parse_args()
    if not 0 <= args.hold_seconds <= 45:
        parser.error("hold time must be between 0 and 45 seconds")

    with mmap.mmap(
        -1,
        mmap.PAGESIZE,
        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
    ) as mapping:
        mapping.write(b"Argus demo: inert bytes; never executed.\n")
        print(f"anonymous executable mapping held for {args.hold_seconds}s", flush=True)
        time.sleep(args.hold_seconds)


if __name__ == "__main__":
    main()
