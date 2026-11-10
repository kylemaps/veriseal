"""Are erased epoch keys still in the recorder's memory?

    python bench/memory_dump.py --runs 10 --out memory.json

A child process plays the recorder: it builds a key chain and closes 20 epochs, signing each
head and then erasing its key. This script, its parent, then reads every readable page of the
child's memory and counts how many of the erased seeds and private keys it can still find.

    bare     the child only signs and erases, which leaves the allocator little else to reuse
    sealer   the child feeds messages through the real sealer, as a recorder would

Each run must find the newest seed, which the recorder still needs; if it doesn't, the scan is
broken and the script stops. Python can't promise that erased bytes are gone, so this measures
what is left on the computer that runs it. Linux reads /proc/PID/mem, which needs no sudo for
your own child process; Windows uses ReadProcessMemory. Nothing from any log is involved.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

EPOCHS = 20
SECOND = 1_000_000_000


def child(seed_hex: str, mode: str) -> None:
    """The recorder: close EPOCHS epochs, say which process to read, then wait."""
    from veriseal.stream import EpochKeys, StreamSealer

    keys = EpochKeys(600, bytes.fromhex(seed_hex))
    if mode == "bare":
        for epoch in range(EPOCHS):
            keys.sign(epoch, b"head %d" % epoch)
    else:
        sealer = StreamSealer(
            "task", SECOND, keys.sign_only, persist=lambda head: None, erase=keys.erase
        )
        for index in range(EPOCHS * 50):
            sealer.add(f"/t{index % 5}", index * SECOND // 50, os.urandom(200))
        sealer.tick(EPOCHS * SECOND)
    assert keys._epoch == EPOCHS, keys._epoch
    print(f"ready {os.getpid()}", flush=True)
    sys.stdin.readline()


def _read_linux(pid: int) -> list[bytes]:
    chunks = []
    with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for line in maps:
            fields = line.split()
            start, end = (int(value, 16) for value in fields[0].split("-"))
            special = len(fields) > 5 and fields[5] in ("[vvar]", "[vsyscall]")
            if not fields[1].startswith("r") or special:
                continue
            try:
                mem.seek(start)
                chunks.append(mem.read(end - start))
            except (OSError, ValueError, OverflowError):
                continue
    return chunks


def _read_windows(pid: int) -> list[bytes]:
    import ctypes
    import ctypes.wintypes as wt

    class Region(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wt.DWORD),
            ("PartitionId", wt.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wt.DWORD),
            ("Protect", wt.DWORD),
            ("Type", wt.DWORD),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = wt.HANDLE
    kernel.VirtualQueryEx.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(Region),
        ctypes.c_size_t,
    ]
    kernel.VirtualQueryEx.restype = ctypes.c_size_t
    kernel.ReadProcessMemory.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)  # query information, read memory
    readable = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
    chunks, address, region = [], 0, Region()
    while kernel.VirtualQueryEx(handle, address, ctypes.byref(region), ctypes.sizeof(region)):
        base, size = region.BaseAddress or 0, region.RegionSize
        guarded = region.Protect & 0x100
        if region.State == 0x1000 and (region.Protect & 0xFF) in readable and not guarded:
            buffer = ctypes.create_string_buffer(size)
            got = ctypes.c_size_t()
            if kernel.ReadProcessMemory(handle, base, buffer, size, ctypes.byref(got)):
                chunks.append(buffer.raw[: got.value])
        address = base + size
    kernel.CloseHandle(handle)
    return chunks


def read_memory(pid: int) -> list[bytes]:
    """Every readable page of process *pid*."""
    if sys.platform.startswith("linux"):
        return _read_linux(pid)
    if sys.platform == "win32":
        return _read_windows(pid)
    raise OSError("reading another process's memory is only done on Linux and Windows here")


def run(mode: str) -> dict:
    """One recorder, one scan. Returns how many erased secrets the scan still found."""
    from veriseal.stream import _KEY_DOMAIN, _hash, _next_seed

    seeds = [os.urandom(32)]
    for _ in range(EPOCHS):
        seeds.append(_next_seed(seeds[-1]))
    private = [_hash(_KEY_DOMAIN, seed) for seed in seeds]
    recorder = subprocess.Popen(
        [sys.executable, __file__, "child", seeds[0].hex(), mode],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert recorder.stdin is not None and recorder.stdout is not None
    try:
        word, pid = recorder.stdout.readline().split()
        assert word == "ready"
        chunks = read_memory(int(pid))
    finally:
        recorder.stdin.write("\n")
        recorder.stdin.flush()
        recorder.wait()

    def found(value: bytes) -> bool:
        return any(value in chunk for chunk in chunks)

    if not found(seeds[EPOCHS]):
        raise RuntimeError("the scan missed the live seed, so it can't be trusted")
    return {
        "mode": mode,
        "old_seeds_found": sum(found(seed) for seed in seeds[:EPOCHS]),
        "old_private_keys_found": sum(found(key) for key in private[:EPOCHS]),
        "first_seed_found": found(seeds[0]),
        "epochs_found": [index for index, seed in enumerate(seeds[:EPOCHS]) if found(seed)],
        "scanned_mb": round(sum(len(chunk) for chunk in chunks) / 1e6, 1),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--runs", type=int, default=10, help="runs of each mode")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    report: dict = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "epochs": EPOCHS,
        "runs": [],
    }
    for mode in ("bare", "sealer"):
        for index in range(args.runs):
            row = run(mode)
            report["runs"].append(row)
            print(
                f"{mode:6} run {index + 1:2}: old seeds {row['old_seeds_found']:2}/{EPOCHS}, "
                f"old private keys {row['old_private_keys_found']:2}/{EPOCHS}, first seed "
                f"{'found' if row['first_seed_found'] else 'gone'}, "
                f"scanned {row['scanned_mb']:.0f} MB",
                flush=True,
            )
    if args.out:
        args.out.write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    if sys.argv[1:2] == ["child"]:
        child(sys.argv[2], sys.argv[3])
    else:
        main()
