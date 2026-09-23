from datetime import datetime
import time


class Timer:
    def __init__(self):
        self.elapsed: float | None = None
        self._start_counter: float | None = None
        self.start_time: datetime | None = None

    def start(self):
        self.start_time = datetime.now().astimezone()
        self._start_counter = time.perf_counter()
        self.elapsed = None

    def stop(self):
        if self._start_counter is None:
            raise RuntimeError("Timer has not been started")
        self.elapsed = time.perf_counter() - self._start_counter

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
