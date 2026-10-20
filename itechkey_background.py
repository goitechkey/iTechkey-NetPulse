"""Run the NetPulse monitor with console output persisted to a log file.

Windows Task Scheduler starts this entry point in the background. Keep this
process in the foreground of the scheduled task so it can track its lifetime
and start a fresh monitor process after an in-app restart request.
"""
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MONITOR_SCRIPT = BASE_DIR / "itechkey_monitor.py"
CONSOLE_LOG = BASE_DIR / "itechkey_console.log"
RESTART_EXIT_CODE = 75


def run_supervised_monitor(log):
    """Keep the scheduled task alive while restarting its monitor child on demand."""
    environment = os.environ.copy()
    environment["ITECHKEY_SUPERVISED"] = "1"
    command = [sys.executable, "-u", str(MONITOR_SCRIPT)]
    while True:
        print("\n[%s] NetPulse monitor process starting" %
              datetime.now().isoformat(timespec="seconds"), file=log)
        process = subprocess.Popen(
            command, cwd=str(BASE_DIR), stdout=log, stderr=subprocess.STDOUT,
            env=environment,
        )
        exit_code = process.wait()
        if exit_code == RESTART_EXIT_CODE:
            print("[%s] NetPulse restart requested; starting updated process" %
                  datetime.now().isoformat(timespec="seconds"), file=log)
            time.sleep(1)
            continue
        if exit_code:
            print("[%s] NetPulse monitor process stopped with exit code %s" % (
                datetime.now().isoformat(timespec="seconds"), exit_code,
            ), file=log)
        else:
            print("[%s] NetPulse monitor exited" %
                  datetime.now().isoformat(timespec="seconds"), file=log)
        return exit_code


def main():
    if not MONITOR_SCRIPT.is_file():
        raise FileNotFoundError("Monitor script not found: %s" % MONITOR_SCRIPT)

    with CONSOLE_LOG.open("a", encoding="utf-8", buffering=1) as log:
        return run_supervised_monitor(log)


if __name__ == "__main__":
    sys.exit(main())
