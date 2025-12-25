import asyncio, socket

class Transport:
    async def send_udp(self, ip, port, payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        await asyncio.get_running_loop().sock_sendto(sock, payload, (ip, port))
