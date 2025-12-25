import time

class ReplayAttackScenario:
    def __init__(self, window_seconds=30):
        self.window = window_seconds
        self.seen = {}

    def observe(self, msg_id: str):
        self.seen[msg_id] = time.time()

    def is_replay(self, msg_id: str) -> bool:
        now = time.time()

        # cleanup old entries
        self.seen = {
            mid: ts for mid, ts in self.seen.items()
            if now - ts < self.window
        }

        return msg_id in self.seen