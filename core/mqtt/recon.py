"""
GhostGateway - MQTT Recon Module
Broker discovery, topic enumeration via wildcard subscribe,
authentication bypass detection, clinical topic mapping.
"""

import time
import threading
import paho.mqtt.client as mqtt
from utils.logger import get_logger

logger = get_logger("MQTT-Recon")

# Clinical MQTT topic patterns seen in medical IoT gateways
CLINICAL_TOPIC_PATTERNS = [
    "ward/#",
    "patient/#",
    "device/#",
    "vitals/#",
    "alarm/#",
    "gateway/#",
    "infusion/#",
    "monitor/#",
    "icu/#",
    "sensor/#",
    "#",                          # Full wildcard - unauthenticated access
]


class MQTTRecon:
    def __init__(self, broker, port=1883, verbose=False):
        self.broker = broker
        self.port = port
        self.verbose = verbose
        self.findings = []
        self.discovered_topics = []
        self._connected = False
        self._messages = []

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            logger.info(f"[RECON] Connected to MQTT broker {self.broker}:{self.port} (No Auth)")
        else:
            logger.warning(f"[RECON] Connection failed: RC={rc}")

    def _on_message(self, client, userdata, msg):
        entry = {"topic": msg.topic, "payload": str(msg.payload[:100])}
        self._messages.append(entry)
        if self.verbose:
            logger.info(f"  MSG [{msg.topic}] -> {msg.payload[:80]}")

    def check_anonymous_access(self):
        """Test if broker allows unauthenticated connections"""
        logger.info(f"[RECON] Testing anonymous access on {self.broker}:{self.port}")
        client = mqtt.Client(client_id="ghostgateway_recon")
        client.on_connect = self._on_connect
        client.on_message = self._on_message

        try:
            client.connect(self.broker, self.port, keepalive=5)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()

            if self._connected:
                self.findings.append({
                    "check": "Anonymous Access",
                    "severity": "CRITICAL",
                    "detail": f"MQTT broker at {self.broker}:{self.port} allows unauthenticated connections."
                })
                return True
            else:
                self.findings.append({
                    "check": "Anonymous Access",
                    "severity": "INFO",
                    "detail": "Broker requires authentication."
                })
                return False
        except Exception as e:
            logger.warning(f"[RECON] Cannot reach broker: {e}")
            return False

    def enumerate_topics(self):
        """Subscribe to wildcard topics to enumerate active clinical topics"""
        logger.info("[RECON] Enumerating topics via wildcard subscription...")
        discovered = set()

        def on_msg(client, userdata, msg):
            discovered.add(msg.topic)
            logger.info(f"  [+] Topic: {msg.topic} | Payload: {msg.payload[:60]}")

        client = mqtt.Client(client_id="ghostgateway_enum")
        client.on_message = on_msg

        try:
            client.connect(self.broker, self.port, keepalive=5)
            client.subscribe("#", qos=0)
            client.loop_start()
            time.sleep(5)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            logger.warning(f"[RECON] Topic enum failed: {e}")

        self.discovered_topics = list(discovered)
        if self.discovered_topics:
            self.findings.append({
                "check": "Topic Enumeration (# Wildcard)",
                "severity": "HIGH",
                "detail": f"Topics discovered via unauthenticated wildcard: {self.discovered_topics}"
            })
        return self.discovered_topics

    def test_sensitive_subscriptions(self):
        """Try subscribing to known clinical topic patterns"""
        logger.info("[RECON] Testing sensitive clinical topic subscriptions...")
        accessible = []

        for pattern in CLINICAL_TOPIC_PATTERNS[:6]:
            found = []

            def on_msg(client, userdata, msg, p=pattern):
                found.append(msg.topic)

            client = mqtt.Client(client_id=f"ghostgateway_{pattern[:5].replace('/', '_')}")
            client.on_message = on_msg

            try:
                client.connect(self.broker, self.port, keepalive=3)
                client.subscribe(pattern, qos=0)
                client.loop_start()
                time.sleep(2)
                client.loop_stop()
                client.disconnect()
                if found:
                    accessible.append({"pattern": pattern, "topics": found})
                    logger.info(f"  [+] Pattern [{pattern}] -> {len(found)} messages")
            except Exception:
                pass

        if accessible:
            self.findings.append({
                "check": "Sensitive Topic Access",
                "severity": "CRITICAL",
                "detail": f"Accessible clinical topics: {accessible}"
            })
        return accessible

    def fingerprint_broker(self):
        """Fingerprint MQTT broker software"""
        logger.info("[RECON] Fingerprinting broker...")
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.broker, self.port))
            # Send MQTT CONNECT packet (minimal)
            connect_pkt = bytes([
                0x10,                          # CONNECT
                0x12,                          # Remaining length
                0x00, 0x04, 0x4D, 0x51, 0x54, 0x54,  # Protocol name: MQTT
                0x04,                          # Protocol level: 4 (3.1.1)
                0x00,                          # Connect flags
                0x00, 0x3C,                    # Keep alive: 60s
                0x00, 0x08,                    # Client ID length: 8
                0x47, 0x68, 0x6F, 0x73, 0x74, 0x47, 0x57, 0x31  # GhostGW1
            ])
            sock.send(connect_pkt)
            resp = sock.recv(64)
            sock.close()
            if resp:
                logger.info(f"  [+] Broker responded to CONNECT. RC byte: {resp[3] if len(resp) > 3 else 'N/A'}")
                self.findings.append({
                    "check": "Broker Fingerprint",
                    "severity": "INFO",
                    "detail": f"Broker responded to raw MQTT CONNECT. Response: {resp.hex()}"
                })
                return resp
        except Exception as e:
            if self.verbose:
                logger.warning(f"Fingerprint failed: {e}")
        return None

    def run(self):
        logger.info("=" * 50)
        logger.info("  MQTT RECON MODULE - GhostGateway")
        logger.info("=" * 50)
        self.fingerprint_broker()
        self.check_anonymous_access()
        self.enumerate_topics()
        self.test_sensitive_subscriptions()
        logger.info(f"[RECON] Complete. {len(self.findings)} findings.")
        return self.findings
