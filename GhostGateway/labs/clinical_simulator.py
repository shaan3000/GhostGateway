"""
GhostGateway Lab - Clinical IoT Gateway Simulator
Simulates a real clinical IoT gateway publishing patient vitals
and receiving commands via MQTT, with Modbus register backing.
"""

import time
import json
import random
import threading
import paho.mqtt.client as mqtt

BROKER = "mqtt-broker"
PORT = 1883

# Simulated patient data
patients = {
    "patient_001": {"heartrate": 72, "spo2": 98, "bp_sys": 120, "bp_dia": 80},
    "patient_002": {"heartrate": 65, "spo2": 97, "bp_sys": 115, "bp_dia": 75},
    "patient_003": {"heartrate": 88, "spo2": 96, "bp_sys": 130, "bp_dia": 85},
}

alarms_suppressed = False


def on_connect(client, userdata, flags, rc):
    print(f"[GATEWAY] Connected to broker (RC={rc})")
    client.subscribe("ward/icu/device/command")
    client.subscribe("alarm/suppress")
    client.subscribe("alarm/global/suppress")
    client.subscribe("patient/monitor/threshold")
    client.subscribe("device/infusion/pump/rate")
    client.subscribe("gateway/config/update")


def on_message(client, userdata, msg):
    global alarms_suppressed
    print(f"[GATEWAY] Command received on [{msg.topic}]: {msg.payload[:100]}")
    try:
        data = json.loads(msg.payload)
        if msg.topic == "alarm/suppress" or msg.topic == "alarm/global/suppress":
            alarms_suppressed = data.get("suppress_all", False) or data.get("suppressed", False)
            print(f"[GATEWAY] ⚠️  Alarms suppressed: {alarms_suppressed}")
        elif msg.topic == "ward/icu/device/command":
            cmd = data.get("command", "")
            print(f"[GATEWAY] ⚠️  Command executed: {cmd}")
        elif msg.topic == "patient/monitor/threshold":
            print(f"[GATEWAY] ⚠️  Thresholds changed: {data}")
        elif msg.topic == "device/infusion/pump/rate":
            rate = data.get("rate_ml_hr", 0)
            print(f"[GATEWAY] ⚠️  Infusion pump rate changed to: {rate} ml/hr")
    except Exception as e:
        print(f"[GATEWAY] Parse error: {e}")


def publish_vitals(client):
    """Continuously publish patient vitals every 2 seconds"""
    while True:
        for pid, vitals in patients.items():
            # Add slight variation
            vitals["heartrate"] += random.randint(-2, 2)
            vitals["spo2"] = max(90, min(100, vitals["spo2"] + random.randint(-1, 1)))
            vitals["bp_sys"] += random.randint(-3, 3)

            payload = json.dumps({
                "patient_id": pid,
                "heartrate": vitals["heartrate"],
                "spo2": vitals["spo2"],
                "bp_systolic": vitals["bp_sys"],
                "bp_diastolic": vitals["bp_dia"],
                "alarm_active": not alarms_suppressed and vitals["spo2"] < 95,
                "timestamp": time.time()
            })

            client.publish(f"vitals/{pid}", payload, qos=0)
            client.publish(f"ward/icu/{pid}/monitor", payload, qos=0)

            # Simulate alarm if SpO2 drops
            if vitals["spo2"] < 95 and not alarms_suppressed:
                alarm_payload = json.dumps({
                    "patient_id": pid,
                    "alarm": "LOW_SPO2",
                    "value": vitals["spo2"],
                    "severity": "CRITICAL"
                })
                client.publish(f"alarm/{pid}/spo2", alarm_payload, qos=1)
                print(f"[GATEWAY] 🚨 ALARM: {pid} SpO2={vitals['spo2']}%")

        time.sleep(2)


def main():
    print("[GATEWAY] Clinical IoT Gateway Simulator starting...")
    print("[GATEWAY] Simulating: 3 ICU patients, MQTT vitals + command channel")

    client = mqtt.Client(client_id="clinical_gateway_sim")
    client.on_connect = on_connect
    client.on_message = on_message

    while True:
        try:
            client.connect(BROKER, PORT, keepalive=60)
            break
        except Exception:
            print("[GATEWAY] Broker not ready, retrying in 3s...")
            time.sleep(3)

    vitals_thread = threading.Thread(target=publish_vitals, args=(client,))
    vitals_thread.daemon = True
    vitals_thread.start()

    print("[GATEWAY] Publishing vitals... Listening for commands...")
    client.loop_forever()


if __name__ == "__main__":
    main()
