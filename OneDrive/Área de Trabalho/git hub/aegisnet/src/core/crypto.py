from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

class CryptoContext:
    def __init__(self):
        self.private = x25519.X25519PrivateKey.generate()
        self.public = self.private.public_key()

    def derive_key(self, peer_public: bytes) -> bytes:
        peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
        shared = self.private.exchange(peer)
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(key: bytes, data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, data, None)

    @staticmethod
    def decrypt(key: bytes, data: bytes) -> bytes:
        return AESGCM(key).decrypt(data[:12], data[12:], None)
