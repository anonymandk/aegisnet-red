class Node:
    def __init__(self, node_id, crypto):
        self.id = node_id
        self.crypto = crypto
        self.peers = {}
        self.sessions = {}
