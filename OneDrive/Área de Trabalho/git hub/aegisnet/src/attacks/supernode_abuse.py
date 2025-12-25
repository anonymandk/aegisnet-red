import random

class SuperNodeAbuseScenario:
    def __init__(self, drop_rate=0.2, delay_ms=300):
        self.drop_rate = drop_rate
        self.delay_ms = delay_ms

    def forward(self, message):
        if random.random() < self.drop_rate:
            return None  # dropped

        return {
            "message": message,
            "delay_ms": self.delay_ms
        }
