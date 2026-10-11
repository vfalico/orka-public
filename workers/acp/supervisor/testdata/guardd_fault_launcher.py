#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading

from ig_kmx_guardd.guardian_integration import FailSafeGuardService
from ig_kmx_guardd.launcher import build_server, load


class _FaultSentinel:
    def __init__(self, write_fd: int):
        self._write_fd = write_fd
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            if self._write_fd >= 0:
                os.close(self._write_fd)
                self._write_fd = -1


_fault_sentinels: dict[int, _FaultSentinel] = {}

_GUARDIAN_CAPTURE = """
import os
import select
import socket
import sys

control = socket.socket(fileno=int(sys.argv[1]))
poller = select.poll()
poller.register(control.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
if not poller.poll(5000):
    raise SystemExit("guardian notice timed out")
payload = control.recv(4096)
temporary = sys.argv[2] + ".tmp"
with open(temporary, "wb") as output:
    output.write(payload)
    output.write(b"\\n")
os.replace(temporary, sys.argv[2])
"""


def _faultable_event_consumer_sentinel(worker):
    if worker.events is None or not worker.events.thread.is_alive():
        raise RuntimeError("event consumer is not alive")
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    sentinel = _FaultSentinel(write_fd)
    _fault_sentinels[worker.process.pid] = sentinel

    def watch() -> None:
        try:
            worker.events.thread.join()
        finally:
            sentinel.close()

    watcher = threading.Thread(
        target=watch, name=f"ig-event-liveness-{worker.process.pid}", daemon=True
    )
    watcher.start()
    return read_fd, watcher


def _capture_terminal_guardian_notice(guardian, path: str) -> None:
    control_fd = os.dup(guardian.control.fileno())
    try:
        subprocess.Popen(
            [sys.executable, "-c", _GUARDIAN_CAPTURE, str(control_fd), path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(control_fd,),
            close_fds=True,
        )
    finally:
        os.close(control_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--control", required=True)
    args = parser.parse_args()
    FailSafeGuardService._event_consumer_sentinel = staticmethod(
        _faultable_event_consumer_sentinel
    )
    server, store = build_server(load(args.config))
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    if os.path.exists(args.control):
        os.unlink(args.control)
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.bind(args.control)
    control.listen(1)
    try:
        while True:
            connection, _ = control.accept()
            with connection:
                command = connection.recv(64).decode().strip()
                if len(server.service.workers) != 1:
                    raise RuntimeError("fault injection requires exactly one worker")
                key, worker = next(iter(server.service.workers.items()))
                guardian = server.service.guardians[key]
                if command == "status":
                    connection.sendall(
                        (json.dumps(guardian.refresh(), sort_keys=True) + "\n").encode()
                    )
                    continue
                if command == "terminal":
                    connection.sendall(
                        (
                            json.dumps(
                                {
                                    "guardian_returncode": guardian.process.poll(),
                                    "worker_returncode": worker.process.poll(),
                                },
                                sort_keys=True,
                            )
                            + "\n"
                        ).encode()
                    )
                    continue
                operation, separator, fault = command.partition(":")
                if separator != ":" or operation not in {"prepare", "fire"}:
                    raise ValueError(f"unknown command: {command}")
                evidence = {
                    "fault": fault,
                    "guardd_pid": os.getpid(),
                    "worker_pid": worker.process.pid,
                    "guardian_pid": guardian.process.pid,
                }
                if operation == "prepare":
                    connection.sendall((json.dumps(evidence, sort_keys=True) + "\n").encode())
                    continue
                if fault == "worker":
                    os.kill(worker.process.pid, signal.SIGKILL)
                elif fault == "event_consumer":
                    _fault_sentinels[worker.process.pid].close()
                elif fault == "control":
                    guardian.control.close()
                elif fault == "guardd":
                    _capture_terminal_guardian_notice(
                        guardian, args.control + ".guardian-status"
                    )
                    connection.sendall((json.dumps(evidence, sort_keys=True) + "\n").encode())
                    os._exit(70)
                else:
                    raise ValueError(f"unknown fault: {fault}")
                connection.sendall((json.dumps(evidence, sort_keys=True) + "\n").encode())
    finally:
        control.close()
        server.close()
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
