"""
GhostGateway - Modbus Recon Module
Discovers Modbus devices, reads coils, registers, device identity.
"""

import socket
import struct
import time
from utils.logger import get_logger

logger = get_logger("Modbus-Recon")

# Clinical IoT register profiles (common in medical gateways)
CLINICAL_REGISTER_MAP = {
    0:  "Patient Monitor Status",
    1:  "Alarm Threshold - Heart Rate",
    2:  "Alarm Threshold - SpO2",
    3:  "Alarm Threshold - Blood Pressure",
    4:  "Ventilator Mode",
    5:  "Infusion Pump Rate",
    6:  "Device Power State",
    7:  "Emergency Override Flag",
    8:  "Data Transmission State",
    9:  "Gateway Connection Status",
    10: "Sensor Calibration Value",
}


class ModbusRecon:
    def __init__(self, target, port=502, unit_id=1, verbose=False):
        self.target = target
        self.port = port
        self.unit_id = unit_id
        self.verbose = verbose
        self.findings = []

    def _build_request(self, function_code, start_addr, count):
        transaction_id = 0x0001
        protocol_id = 0x0000
        length = 0x0006
        header = struct.pack(">HHHBB", transaction_id, protocol_id, length,
                             self.unit_id, function_code)
        data = struct.pack(">HH", start_addr, count)
        return header + data

    def _send_request(self, request, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target, self.port))
            sock.send(request)
            response = sock.recv(1024)
            sock.close()
            return response
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if self.verbose:
                logger.warning(f"Connection error: {e}")
            return None

    def check_connectivity(self):
        logger.info(f"Checking Modbus connectivity: {self.target}:{self.port}")
        req = self._build_request(0x03, 0, 1)
        resp = self._send_request(req)
        if resp:
            logger.info(f"[RECON] Modbus device REACHABLE at {self.target}:{self.port}")
            self.findings.append({
                "check": "Connectivity",
                "severity": "INFO",
                "detail": f"Modbus TCP device reachable at {self.target}:{self.port}"
            })
            return True
        else:
            logger.warning(f"[RECON] Modbus device NOT reachable at {self.target}:{self.port}")
            self.findings.append({
                "check": "Connectivity",
                "severity": "INFO",
                "detail": f"Modbus TCP device not reachable at {self.target}:{self.port}"
            })
            return False

    def read_coils(self, start=0, count=16):
        logger.info(f"[RECON] Reading coils {start}-{start+count-1}")
        req = self._build_request(0x01, start, count)
        resp = self._send_request(req)
        if resp and len(resp) > 8:
            byte_count = resp[8]
            coil_bytes = resp[9:9 + byte_count]
            coils = []
            for i, b in enumerate(coil_bytes):
                for bit in range(8):
                    coils.append((b >> bit) & 1)
            logger.info(f"[RECON] Coils: {coils[:count]}")
            self.findings.append({
                "check": "Coil Read (FC01)",
                "severity": "HIGH",
                "detail": f"Unauthenticated coil read allowed. Coils: {coils[:count]}"
            })
            return coils[:count]
        return []

    def read_holding_registers(self, start=0, count=11):
        logger.info(f"[RECON] Reading holding registers {start}-{start+count-1}")
        req = self._build_request(0x03, start, count)
        resp = self._send_request(req)
        registers = {}
        if resp and len(resp) > 9:
            byte_count = resp[8]
            reg_data = resp[9:9 + byte_count]
            values = struct.unpack(f">{byte_count // 2}H", reg_data)
            for i, val in enumerate(values):
                addr = start + i
                label = CLINICAL_REGISTER_MAP.get(addr, f"Register_{addr}")
                registers[addr] = {"label": label, "value": val}
                logger.info(f"  Register {addr:04d} [{label}] = {val}")
            self.findings.append({
                "check": "Holding Register Read (FC03)",
                "severity": "CRITICAL",
                "detail": f"Unauthenticated register read exposes clinical parameters: {list(registers.values())}"
            })
        return registers

    def read_device_identification(self):
        logger.info("[RECON] Attempting Device Identification (FC43)")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target, self.port))
            # MEI Type 0x0E - Read Device Identification
            pdu = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
                         self.unit_id, 0x2B, 0x0E, 0x01, 0x00])
            sock.send(pdu)
            resp = sock.recv(256)
            sock.close()
            if resp:
                logger.info(f"[RECON] Device ID response received ({len(resp)} bytes)")
                self.findings.append({
                    "check": "Device Identification (FC43/MEI)",
                    "severity": "MEDIUM",
                    "detail": f"Device responded to identification request. Raw bytes: {resp.hex()}"
                })
                return resp
        except Exception as e:
            if self.verbose:
                logger.warning(f"Device ID failed: {e}")
        return None

    def scan_unit_ids(self, max_id=5):
        logger.info(f"[RECON] Scanning Unit IDs 1-{max_id}")
        live_units = []
        for uid in range(1, max_id + 1):
            self.unit_id = uid
            req = self._build_request(0x03, 0, 1)
            resp = self._send_request(req, timeout=1)
            if resp and len(resp) > 8 and resp[7] != 0x83:
                logger.info(f"  [+] Unit ID {uid} -> ACTIVE")
                live_units.append(uid)
            else:
                logger.info(f"  [-] Unit ID {uid} -> no response")
            time.sleep(0.1)

        if live_units:
            self.findings.append({
                "check": "Unit ID Scan",
                "severity": "HIGH",
                "detail": f"Active Modbus unit IDs found: {live_units}"
            })
        return live_units

    def run(self):
        logger.info("=" * 50)
        logger.info("  MODBUS RECON MODULE - GhostGateway")
        logger.info("=" * 50)
        self.check_connectivity()
        self.read_coils()
        self.read_holding_registers()
        self.read_device_identification()
        self.scan_unit_ids()
        logger.info(f"[RECON] Complete. {len(self.findings)} findings.")
        return self.findings
