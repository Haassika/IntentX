"""Bounded, benign lab workload; standard library only, no shell commands."""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkloadConfig:
    duration_seconds: float = 3600
    interval_seconds: float = 10
    seed: int = 42
    max_children: int = 3
    file_bytes: int = 65536
    cpu_iterations: int = 20000

    def __post_init__(self) -> None:
        for name, upper in (("duration_seconds", 86400), ("interval_seconds", 60)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0.1 <= value <= upper:
                raise ValueError(f"{name} must be finite and between 0.1 and {upper}")
        for name, lower, upper in (("seed", 0, 2**32 - 1), ("max_children", 1, 3), ("file_bytes", 1, 1048576), ("cpu_iterations", 0, 100000)):
            value = getattr(self, name)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"{name} must be an integer between {lower} and {upper}")


def run_workload(config: WorkloadConfig, stop: threading.Event | None = None) -> dict[str, int]:
    """Run a seeded activity sequence. Timing and OS scheduling are not deterministic.

    All files live in a private directory under /tmp. Only IPv4 loopback is
    used. Children execute a fixed Python sleep program with isolated imports.
    """
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        raise RuntimeError("The benign workload requires a non-root POSIX user")
    stop = stop if stop is not None else threading.Event()
    rng = random.Random(config.seed)
    counts = {"cycles": 0, "children": 0, "connections": 0, "bytes_written": 0}
    deadline = time.monotonic() + config.duration_seconds
    with tempfile.TemporaryDirectory(prefix="intentx-benign-", dir="/tmp") as directory:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(config.max_children)
            listener.settimeout(1)
            while not stop.is_set() and time.monotonic() < deadline:
                cycle_end = min(deadline, time.monotonic() + config.interval_seconds)
                children: list[subprocess.Popen] = []
                try:
                    with ExitStack() as stack:
                        activity_count = rng.randint(1, config.max_children)
                        for _ in range(activity_count):
                            if stop.is_set() or time.monotonic() >= cycle_end:
                                break
                            child = subprocess.Popen(
                                [sys.executable, "-I", "-c", "import time; time.sleep(60)"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, close_fds=True,
                                cwd=directory,
                            )
                            children.append(child)
                            counts["children"] += 1
                            client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                            client.settimeout(1)
                            client.connect(listener.getsockname())
                            server, _ = listener.accept()
                            stack.enter_context(server)
                            server.settimeout(1)
                            expected = b"intentx-benign\n"
                            client.sendall(expected)
                            message = b""
                            while len(message) < len(expected):
                                block = server.recv(len(expected) - len(message))
                                if not block:
                                    raise RuntimeError("Incomplete loopback message")
                                message += block
                            if message != expected:
                                raise RuntimeError("Unexpected loopback message")
                            counts["connections"] += 1
                        payload = bytes([rng.randrange(256)]) * rng.randint(1, config.file_bytes)
                        path = Path(directory) / "activity.bin"
                        path.write_bytes(payload)
                        if path.read_bytes() != payload:
                            raise RuntimeError("Temporary file verification failed")
                        path.unlink()
                        counts["bytes_written"] += len(payload)
                        value = 1
                        for index in range(rng.randint(0, config.cpu_iterations)):
                            if index % 1024 == 0 and (stop.is_set() or time.monotonic() >= cycle_end):
                                break
                            value = (value * 1664525 + 1013904223) & 0xffffffff
                        counts["cycles"] += 1
                        stop.wait(max(0, cycle_end - time.monotonic()))
                finally:
                    for child in children:
                        if child.poll() is None:
                            child.terminate()
                    for child in children:
                        try:
                            child.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            child.kill()
                            child.wait()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Controlled lab normal-behavior workload (non-root, loopback only)")
    for name, kind, default in (("duration-seconds", float, 3600), ("interval-seconds", float, 10), ("seed", int, 42), ("max-children", int, 3), ("file-bytes", int, 65536), ("cpu-iterations", int, 20000)):
        parser.add_argument(f"--{name}", type=kind, default=default)
    parser.add_argument("--record-profile", action="store_true")
    args = parser.parse_args()
    record_profile = vars(args).pop("record_profile")
    try:
        config = WorkloadConfig(**vars(args))
    except ValueError as exc:
        parser.error(str(exc))
    if record_profile:
        from intentx.behavior.provenance import write_workload_profile
        write_workload_profile(config)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    print(json.dumps({"profile": "controlled_lab_normal_behavior", "config": asdict(config)}), flush=True)
    print(json.dumps(run_workload(config, stop)), flush=True)


if __name__ == "__main__":
    main()
