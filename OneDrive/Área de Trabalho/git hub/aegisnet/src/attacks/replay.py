class ReplayAttackSimulator:
    def __init__(self):
        self.seen_messages = set()

    def detect(self, msg_id):
        if msg_id in self.seen_messages:
            return True
        self.seen_messages.add(msg_id)
        return False
