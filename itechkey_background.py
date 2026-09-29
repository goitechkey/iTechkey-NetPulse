"""Run the NetPulse monitor with console output persisted to a log file.

Windows Task Scheduler starts this entry point in the background. Keep this
process in the foreground of the scheduled task so it can track its lifetime.
"""
import runpy
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MONITOR_SCRIPT = BASE_DIR / "itechkey_monitor.py"
CONSOLE_LOG = BASE_DIR / "itechkey_console.log"


def main():
    if not MONITOR_SCRIPT.is_file():
        raise FileNotFoundError("Monitor script not found: %s" % MONITOR_SCRIPT)

    with CONSOLE_LOG.open("a", encoding="utf-8", buffering=1) as log:
        print("\n[%s] NetPulse background process starting" %
              datetime.now().isoformat(timespec="seconds"), file=log)
        try:
            with redirect_stdout(log), redirect_stderr(log):
                runpy.run_path(str(MONITOR_SCRIPT), run_name="__main__")
        except BaseException as exc:
            print("[%s] NetPulse background process stopped: %s: %s" % (
                datetime.now().isoformat(timespec="seconds"),
                type(exc).__name__, exc,
            ), file=log)
            raise
        else:
            print("[%s] NetPulse monitor exited" %
                  datetime.now().isoformat(timespec="seconds"), file=log)


if __name__ == "__main__":
    sys.exit(main())
