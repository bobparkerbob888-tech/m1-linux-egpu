#!/usr/bin/python3
"""One-boot SSH acknowledgement watchdog. Does not select or modify boot entries."""
import json
import os
import pwd
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TRIAL_ID = "oldm1-r4-20261003"
KERNEL = "7.3.0-rc1-j293-overlay-r4"
DEADLINE = 180.0  # Absolute CLOCK_BOOTTIME seconds, including suspend.
RUN_DIR = Path("/run/bob-kernel-overlay-trial")
STATE_DIR = Path("/var/lib/bob-kernel-overlay-trial")
MAX_JSON = 65536
TERMINAL = {"acknowledged", "reboot-requested", "reboot-request-failed"}


def condition_matches(cmdline, kernel):
    tokens = [s for s in cmdline.split() if s.startswith("bob_kernel_trial=")]
    return kernel == KERNEL and tokens == ["bob_kernel_trial=" + TRIAL_ID]


def identity(boot_id):
    return {"trial_id": TRIAL_ID, "boot_id": boot_id, "kernel": KERNEL}


def valid_ack(value, expected):
    return isinstance(value, dict) and value == expected


def read_json_file(path, owner):
    """Never follow links, block on a FIFO, or read an unbounded user file."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner:
            return None
        if owner == 0 and info.st_mode & 0o022:
            return None
        if info.st_size > MAX_JSON:
            return None
        data = os.read(fd, MAX_JSON + 1)
        if len(data) > MAX_JSON:
            return None
        value = json.loads(data)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def prepare_directory(path, owner, group, mode, allowed_owners):
    path.mkdir(mode=mode, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in allowed_owners:
        raise RuntimeError("Unexpected directory ownership or type: " + str(path))
    os.chown(path, owner, group)
    os.chmod(path, mode)


def atomic_receipt(value):
    fd, temporary = tempfile.mkstemp(prefix=".result-", dir=STATE_DIR)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o644)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE_DIR / "result.json")
        directory_fd = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def normal_reboot():
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "--no-block", "reboot"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True, timeout=10, check=False,
        )
        return result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return -1


def run_guard(expected, clock, read_ack, sleep, write_receipt, reboot,
              previous=None, deadline=DEADLINE):
    """Dependency injection permits tests with no system reboot calls."""
    if (isinstance(previous, dict)
            and all(previous.get(k) == v for k, v in expected.items())
            and previous.get("outcome") in TERMINAL):
        return "already-complete"

    while True:
        now = clock()
        if now >= deadline:
            result = dict(expected, outcome="reboot-requested",
                          observed_boottime=now, deadline_boottime=deadline)
            # Persist intent BEFORE making the only reboot request.
            try:
                write_receipt(result)
            except Exception as error:
                print("Could not persist reboot intent: " + str(error), file=sys.stderr)
            returncode = reboot()
            result["reboot_returncode"] = returncode
            if returncode:
                result["outcome"] = "reboot-request-failed"
            try:
                write_receipt(result)
            except Exception as error:
                print("Could not persist reboot result: " + str(error), file=sys.stderr)
            return result["outcome"]

        if valid_ack(read_ack(), expected):
            # Sampling the deadline again prevents an IO-delayed late ack.
            observed = clock()
            if observed >= deadline:
                continue
            try:
                write_receipt(dict(expected, outcome="acknowledged",
                                   observed_boottime=observed,
                                   deadline_boottime=deadline))
            except Exception as error:
                print("Could not persist acknowledgement: " + str(error), file=sys.stderr)
                sleep(min(0.25, deadline - observed))
                continue
            return "acknowledged"
        sleep(min(0.25, deadline - now))


def main():
    cmdline = Path("/proc/cmdline").read_text()
    if not condition_matches(cmdline, os.uname().release):
        return 0  # No directory, receipt or reboot on any other boot.
    if os.geteuid() != 0:
        raise RuntimeError("The trial guard must run as root")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    expected = identity(boot_id)
    previous = None
    read_ack = lambda: None
    def receipt_unavailable(_):
        raise RuntimeError("Root receipt directory was not validated")
    receipt_writer = receipt_unavailable
    try:
        account = pwd.getpwnam("bob")
        prepare_directory(STATE_DIR, 0, 0, 0o755, {0})
        receipt_writer = atomic_receipt
        previous = read_json_file(STATE_DIR / "result.json", 0)
        prepare_directory(RUN_DIR, account.pw_uid, account.pw_gid, 0o700,
                          {0, account.pw_uid})
        read_ack = lambda: read_json_file(RUN_DIR / "ack.json", account.pw_uid)
    except Exception as error:
        # A broken acknowledgement path must not silently cancel rollback.
        print("Trial setup failed; keeping rollback deadline: " + str(error),
              file=sys.stderr)
    outcome = run_guard(
        expected, lambda: time.clock_gettime(time.CLOCK_BOOTTIME), read_ack,
        time.sleep, receipt_writer, normal_reboot, previous,
    )
    print("Kernel trial guard: " + outcome, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
