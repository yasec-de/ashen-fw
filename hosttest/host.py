import socket
import sys
import time

from cobs import cobs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from noise.connection import Keypair, NoiseConnection


def hexdump(label, data):
    print(f"{label} ({len(data)} bytes)")
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hexs:<47}  {asc}")


class Link:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=5)
        self.sock.settimeout(10)
        self.buf = bytearray()

    def recv_byte(self):
        while not self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf.extend(chunk)
        return self.buf.pop(0)

    def send_reset(self):
        self.sock.sendall(b"\x00" * 8)
        seen = 0
        while seen < 32:
            seen = seen + 1 if self.recv_byte() == 0x00 else 0

    def send_frame(self, body):
        frame = cobs.encode(body) + b"\x00"
        hexdump("TX frame (encrypted, pre-transmit)", frame)
        self.sock.sendall(frame)

    def read_frame(self):
        raw = bytearray()
        while True:
            b = self.recv_byte()
            if b == 0x00:
                return cobs.decode(bytes(raw))
            raw.append(b)


def main():
    host, _, port = (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:7600").partition(":")
    link = Link(host, int(port or 7600))

    link.send_reset()

    noise = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
    noise.set_as_initiator()
    noise.set_keypair_from_private_bytes(
        Keypair.STATIC, X25519PrivateKey.generate().private_bytes_raw()
    )
    noise.start_handshake()

    link.send_frame(noise.write_message(b""))
    noise.read_message(link.read_frame())
    link.send_frame(noise.write_message(b""))
    assert noise.handshake_finished

    def send_msg(body):
        hexdump("TX message (plaintext, pre-encryption)", body)
        link.send_frame(noise.encrypt(body))

    def recv_msg():
        while True:
            body = noise.decrypt(link.read_frame())
            hexdump("RX message (plaintext, post-decryption)", body)
            if body[:1] != b"\x01":  # skip unsolicited Log messages
                return body

    send_msg(b"\x05")
    status = recv_msg()
    assert status[0] == 0x06
    print(f"status: peer_trusted={status[1]} is_keyed={status[2]}")

    latencies = []
    echo_start = time.perf_counter()
    for value in range(3):
        t0 = time.perf_counter()
        send_msg(b"\x08" + value.to_bytes(8, "big"))
        reply = recv_msg()
        latencies.append(time.perf_counter() - t0)
        assert reply[0] == 0x09
        print(f"echo: sent {value} -> got {int.from_bytes(reply[1:9], 'big')}")
        time.sleep(0.25)
    echo_total = time.perf_counter() - echo_start

    print(f"echo phase total: {echo_total * 1000:.1f} ms")
    for i, lat in enumerate(latencies):
        print(f"  echo {i} latency: {lat * 1000:.1f} ms")

if __name__ == "__main__":
    main()
