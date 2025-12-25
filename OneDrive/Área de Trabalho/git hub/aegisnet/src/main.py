
## AegisNet-Red
##Adversarial P2P Secure Messaging Framework
## Author: Paulo Meins
## Purpose: Offensive Security Research / Red Team


import asyncio
import socket
import time
import json
import secrets
import enum
import hashlib
from dataclasses import dataclass
from typing import Dict, Set

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ===================== CONFIG =====================
PORT = 61500
PEER_TTL = 60
CACHE_SIZE = 2048
# =================================================

# ===================== UTILS ======================
def now(): return int(time.time())
def rid(): return secrets.token_hex(8)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
# =================================================

# ===================== CRYPTO =====================
class Crypto:
    @staticmethod
    def gen_keypair():
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def derive(shared: bytes) -> dict:
        keymat = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b"aegisnet-session"
        ).derive(shared)

        return {
            "enc": keymat[:32],
            "auth": keymat[32:]
        }

    @staticmethod
    def encrypt(key: bytes, data: bytes, aad=b""):
        aes = AESGCM(key)
        nonce = secrets.token_bytes(12)
        return nonce + aes.encrypt(nonce, data, aad)

    @staticmethod
    def decrypt(key: bytes, data: bytes, aad=b""):
        aes = AESGCM(key)
        return aes.decrypt(data[:12], data[12:], aad)
# =================================================

# ===================== MESSAGE ====================
class MsgType(enum.IntEnum):
    HANDSHAKE = 1
    CHAT = 2
    PING = 3
    FORWARD = 4

@dataclass
class Message:
    mid: str
    src: str
    dst: str
    typ: MsgType
    ts: int
    payload: bytes

    def encode(self) -> bytes:
        header = json.dumps({
            "mid": self.mid,
            "src": self.src,
            "dst": self.dst,
            "typ": int(self.typ),
            "ts": self.ts
        }).encode()
        return header + b"\n" + self.payload

    @staticmethod
    def decode(raw: bytes):
        meta, payload = raw.split(b"\n", 1)
        h = json.loads(meta.decode())
        return Message(
            h["mid"], h["src"], h["dst"],
            MsgType(h["typ"]), h["ts"], payload
        )
# =================================================

# ===================== PEER =======================
@dataclass
class Peer:
    ip: str
    last_seen: int
    keys: dict = None
# =================================================

# ===================== OFFENSIVE MODULES ==========
class Offensive:
    """Ataques simulados"""

    @staticmethod
    def replay(original: Message) -> Message:
        """Reenvia mensagem válida"""
        return Message(
            original.mid,  # mesmo ID (replay)
            original.src,
            original.dst,
            original.typ,
            original.ts,
            original.payload
        )

    @staticmethod
    def fingerprint(peer_ip: str) -> dict:
        """Fingerprint simples de nó"""
        return {
            "ip": peer_ip,
            "latency_guess": "low",
            "stack": "asyncio/udp",
            "likely_python": True
        }

    @staticmethod
    def flood(node, target_ip: str, count=50):
        """Flood controlado (lab)"""
        async def _f():
            for _ in range(count):
                msg = Message(
                    rid(), node.name, "flood",
                    MsgType.PING, now(), b"x"
                )
                await node.send_raw(target_ip, msg)
        return _f()
# =================================================

# ===================== NODE =======================
class Node:
    def __init__(self, name):
        self.name = name
        self.priv, self.pub = Crypto.gen_keypair()
        self.peers: Dict[str, Peer] = {}
        self.cache: Set[str] = set()

    async def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", PORT))
        print(f"[+] {self.name} online on UDP/{PORT}")

        while True:
            data, addr = await asyncio.get_running_loop().sock_recvfrom(self.sock, 8192)
            asyncio.create_task(self.handle(data, addr))

    async def handle(self, data, addr):
        msg = Message.decode(data)

        # Anti-replay (observável)
        if msg.mid in self.cache:
            print("[!] Replay detected:", msg.mid)
            return

        self.cache.add(msg.mid)
        if len(self.cache) > CACHE_SIZE:
            self.cache.pop()

        self.register_peer(msg.src, addr[0])

        if msg.typ == MsgType.HANDSHAKE:
            await self.accept_handshake(msg)

        elif msg.typ == MsgType.CHAT:
            self.accept_chat(msg)

    def register_peer(self, pid, ip):
        if pid not in self.peers:
            self.peers[pid] = Peer(ip, now())
        else:
            self.peers[pid].last_seen = now()

    async def handshake(self, peer, ip):
        msg = Message(
            rid(), self.name, peer,
            MsgType.HANDSHAKE, now(),
            self.pub.public_bytes_raw()
        )
        await self.send_raw(ip, msg)

    async def accept_handshake(self, msg):
        peer_pub = x25519.X25519PublicKey.from_public_bytes(msg.payload)
        shared = self.priv.exchange(peer_pub)
        keys = Crypto.derive(shared)
        self.peers[msg.src].keys = keys
        print(f"[+] Secure session with {msg.src}")

    async def send_chat(self, peer, text):
        p = self.peers.get(peer)
        if not p or not p.keys:
            print("[-] No session")
            return

        ct = Crypto.encrypt(p.keys["enc"], text.encode(), self.name.encode())
        msg = Message(rid(), self.name, peer, MsgType.CHAT, now(), ct)
        await self.send_raw(p.ip, msg)

    def accept_chat(self, msg):
        p = self.peers.get(msg.src)
        if not p or not p.keys:
            return
        pt = Crypto.decrypt(p.keys["enc"], msg.payload, msg.src.encode())
        print(f"[{msg.src}] {pt.decode()}")

    async def send_raw(self, ip, msg):
        await asyncio.get_running_loop().sock_sendto(
            self.sock, msg.encode(), (ip, PORT)
        )
# =================================================

# ===================== CLI ========================
async def cli(node):
    while True:
        cmd = input("> ")

        if cmd.startswith("/send"):
            _, peer, msg = cmd.split(" ", 2)
            await node.send_chat(peer, msg)

        elif cmd.startswith("/replay"):
            print("[!] Replay attack is passive (auto-detect only)")

        elif cmd.startswith("/fingerprint"):
            _, ip = cmd.split(" ", 1)
            print(Offensive.fingerprint(ip))

        elif cmd.startswith("/flood"):
            _, ip = cmd.split(" ", 1)
            await Offensive.flood(node, ip)

# ===================== MAIN =======================
async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="node1")
    parser.add_argument("--connect")
    args = parser.parse_args()

    node = Node(args.name)

    if args.connect:
        pid, ip = args.connect.split("@")

if __name__ == "__main__":
    asyncio.run(main())


from core.crypto import CryptoContext
from core.node import Node

def main():
    crypto = CryptoContext()
    node = Node("node1", crypto)
    print("AegisNet-Red initialized")

if __name__ == "__main__":
    main()
