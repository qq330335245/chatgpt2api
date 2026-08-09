"""Best-effort process heap reclamation for memory-constrained Linux hosts."""

from __future__ import annotations

import ctypes
import gc
import sys


def release_process_memory() -> bool:
    """Collect Python objects and ask glibc to return free heap pages to the OS.

    malloc_trim is unavailable on non-Linux platforms and cannot reclaim allocated
    or fragmented pages, so callers must treat a False result as non-fatal.
    """
    gc.collect()
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim.argtypes = [ctypes.c_size_t]
        libc.malloc_trim.restype = ctypes.c_int
        return bool(libc.malloc_trim(0))
    except (AttributeError, OSError):
        return False
