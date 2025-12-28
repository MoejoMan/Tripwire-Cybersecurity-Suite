"""
Minimal utility helpers placeholder.

We'll add small, reusable functions here over time (e.g., formatting,
color helpers, CSV export), keeping this module lightweight.
"""

import os
import time
from typing import Iterator


def follow_file(path: str, start_from_end: bool = True, poll_seconds: float = 0.5) -> Iterator[str]:
    """
    Yield new lines appended to `path` in a loop, similar to `tail -f`.
    Handles simple truncation/rotation by reopening when file size shrinks
    or the path temporarily disappears.
    """
    while True:
        try:
            with open(path, 'r', errors='ignore') as f:
                if start_from_end:
                    f.seek(0, os.SEEK_END)
                else:
                    f.seek(0)
                last_size = os.path.getsize(path)
                while True:
                    line = f.readline()
                    if line:
                        yield line
                    else:
                        time.sleep(poll_seconds)
                        try:
                            current_size = os.path.getsize(path)
                            if current_size < last_size:
                                # truncated or rotated; reopen
                                break
                            last_size = current_size
                        except Exception:
                            # path missing or inaccessible; retry outer loop
                            time.sleep(poll_seconds)
                            break
        except FileNotFoundError:
            time.sleep(poll_seconds)
            continue

