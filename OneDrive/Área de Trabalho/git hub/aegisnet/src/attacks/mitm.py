class MitMAttackScenario:
    def __init__(self):
        self.detected = False

    def substitute_key(self, advertised_key: bytes, malicious_key: bytes) -> dict:
        """
        Simulates key substitution and detects mismatch.
        """

        if advertised_key != malicious_key:
            self.detected = True

        return {
            "original_key": advertised_key,
            "received_key": malicious_key,
            "attack_detected": self.detected
        }
