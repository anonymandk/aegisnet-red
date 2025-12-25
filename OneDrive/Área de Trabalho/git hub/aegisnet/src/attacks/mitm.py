class MitMSimulator:
    def attempt_key_substitution(self, original_pub, fake_pub):
        return {
            "original": original_pub,
            "substituted": fake_pub,
            "detected": True
        }
