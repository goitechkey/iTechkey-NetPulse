"""Run the NetPulse sensor collector as a single dedicated process.

Use this alongside a WSGI web server such as Gunicorn. Do not run multiple
collector instances against the same sensors/database.
"""
import logging
import signal
import threading

import itechkey_monitor as monitor


def main():
    try:
        monitor.init_db()
    except Exception:
        logging.exception("Collector database initialization failed")
        raise

    stopped = threading.Event()

    def request_stop(_signum, _frame):
        stopped.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    monitor.start_monitor()
    logging.info("NetPulse collector process started")

    try:
        while not stopped.wait(1):
            pass
    finally:
        monitor._monitor_stop.set()
        monitor._flush_batch()
        logging.info("NetPulse collector process stopped")


if __name__ == "__main__":
    main()
