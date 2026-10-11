#!/usr/bin/env python3
import argparse
import errno
import json
import os
import socket


def _capabilities() -> dict[str, int]:
    fields = {"CapInh", "CapPrm", "CapEff", "CapAmb"}
    result: dict[str, int] = {}
    with open("/proc/self/status", encoding="utf-8") as status:
        for line in status:
            name = line.partition(":")[0]
            if name in fields:
                result[name] = int(line.split()[1], 16)
    if set(result) != fields:
        raise RuntimeError(f"process status capability fields are incomplete: {result}")
    return result


def _start_ticks(pid: int) -> int:
    raw = open(f"/proc/{pid}/stat", encoding="utf-8").read()
    close = raw.rfind(")")
    fields = raw[close + 2 :].split()
    if close < 0 or len(fields) <= 19:
        raise RuntimeError(f"invalid process stat for {pid}")
    return int(fields[19])


def _cgroup_fds() -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for name in os.listdir("/proc/self/fd"):
        try:
            fd = int(name)
            target = os.readlink(f"/proc/self/fd/{name}")
        except (FileNotFoundError, ValueError):
            continue
        if target.startswith("/sys/fs/cgroup/"):
            found.append({"fd": fd, "target": target})
    return sorted(found, key=lambda item: int(item["fd"]))


def _prove_freezer_denied(path: str) -> tuple[str, int]:
    fd = -1
    try:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise RuntimeError(
                    f"exact freezer open failed with unexpected errno {exc.errno}"
                ) from exc
            return "open", exc.errno
        try:
            os.write(fd, b"1\n")
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EPERM}:
                raise RuntimeError(
                    f"exact freezer write failed with unexpected errno {exc.errno}"
                ) from exc
            return "write", exc.errno
    except OSError as exc:
        raise RuntimeError(f"exact freezer attempt failed unexpectedly: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    raise RuntimeError("unprivileged exact freezer attempt unexpectedly succeeded")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", required=True)
    parser.add_argument("--freezer", required=True)
    parser.add_argument("--fault", required=True)
    args = parser.parse_args()

    groups = os.getgroups()
    capabilities = _capabilities()
    cgroup_fds = _cgroup_fds()
    if groups:
        raise RuntimeError(f"supplementary groups were not cleared: {groups}")
    if any(capabilities.values()):
        raise RuntimeError(f"capabilities were not cleared: {capabilities}")
    if cgroup_fds:
        raise RuntimeError(f"coordinator inherited cgroup descriptors: {cgroup_fds}")

    freezer_stage, freezer_errno = _prove_freezer_denied(args.freezer)
    if _cgroup_fds():
        raise RuntimeError("coordinator retained a cgroup descriptor after denied write")

    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.connect(args.control)
    control.sendall(f"fire:{args.fault}\n".encode())
    response = b""
    while not response.endswith(b"\n"):
        chunk = control.recv(4096)
        if not chunk:
            raise RuntimeError("fault control closed before returning evidence")
        response += chunk
    control.close()

    print(
        json.dumps(
            {
                "coordinator_pid": os.getpid(),
                "coordinator_start_ticks": _start_ticks(os.getpid()),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "groups": groups,
                "capabilities": capabilities,
                "freezer_path": args.freezer,
                "freezer_denial_stage": freezer_stage,
                "freezer_errno": freezer_errno,
                "cgroup_fds": cgroup_fds,
                "fault_evidence": json.loads(response),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
