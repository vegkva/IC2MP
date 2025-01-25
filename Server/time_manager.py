import time

class TimerManager:
    def __init__(self):
        self.timers = {}

    def start_timer(self, name):
        """Start a timer with the given name."""
        self.timers[f"start_{name}"] = time.time()

    def stop_timer(self, name):
        """Stop the timer with the given name."""
        self.timers[f"end_{name}"] = time.time()

    def get_start_time(self, name):
        """Get the start time for the timer with the given name."""
        return self.timers.get(f"start_{name}")

    def get_end_time(self, name):
        """Get the end time for the timer with the given name."""
        return self.timers.get(f"end_{name}")

    def get_elapsed_time(self, name):
        """Get the elapsed time for the timer with the given name without stopping it."""
        start_time = self.get_start_time(name)
        if start_time is None:
            return None
        current_time = time.time()
        return round(current_time - start_time)