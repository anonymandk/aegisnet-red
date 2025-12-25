class MitMAttackScenario:
     def __init__(self):
        self.detected = False

     def substitute_key(self, advertised_key, malicious_key):
        if advertised_key != malicious_key:
            self.detected = True

        return {
            "original_key": advertised_key,
            "received_key": malicious_key,
            "attack_detected": self.detected
        }

     def attempt_downgrade(self, advertised_cipher: str):
         allowed = ["AES-256-GCM"]

        if advertised_cipher not in allowed:
            self.detected = True

        return {
            "cipher": advertised_cipher,
            "allowed": advertised_cipher in allowed,
            "attack_detected": self.detected
        }
