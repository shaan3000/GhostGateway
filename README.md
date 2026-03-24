# 👻 GhostGateway

> **Clinical IoT Gateway Attack Simulator**
> Modbus/MQTT Security Research Tool for Medical Device Environments

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.0-red)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Domain](https://img.shields.io/badge/Domain-Medical%20Device%20Security-critical)

---

```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║   
██║   ██║██╔══██║██║   ██║╚════██║   ██║   
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  

    Clinical IoT Gateway Attack Simulator
    Modbus/MQTT Security Research Tool
```

---

## ⚠️ Responsible Disclosure & Legal Notice

> **GhostGateway is a security research tool intended exclusively for:**
> - Authorized penetration testing engagements
> - Academic and medical device security research
> - Controlled lab environments
> - Security awareness and training
>
> **Unauthorized use against real medical devices or healthcare infrastructure is illegal and could endanger patient lives.**
> The author is not responsible for any misuse of this tool.

---

## 🔍 What Makes GhostGateway Unique?

Most ICS/OT security tools focus on general industrial environments (SCADA, PLCs). GhostGateway is purpose-built for **clinical IoT gateways** found in healthcare environments — with:

- **Medical-context register mappings** (Heart Rate thresholds, SpO2 alarms, Infusion Pump rates, Emergency Override flags)
- **Clinical MQTT topic patterns** (`ward/#`, `patient/#`, `vitals/#`, `alarm/#`, `icu/#`)
- **Built-in Docker lab** simulating a real hospital gateway with live patient vitals
- **Full attack suite** covering Recon → Injection → Replay → DoS for both Modbus and MQTT simultaneously
- **Clinical-context HTML reports** suitable for healthcare security assessments

---

## 🏥 Why Clinical IoT Gateways?

Clinical IoT gateways sit at the intersection of hospital networks and medical devices — they bridge legacy Modbus-based equipment (patient monitors, ventilators, infusion pumps) with modern IP/MQTT-based hospital networks.

**Key risks in real environments:**
- Modbus has **no authentication** by default
- MQTT brokers in clinical settings are frequently **deployed without TLS or auth**
- A compromised gateway can **silently suppress alarms** or **manipulate device thresholds**
- Real patient safety impact — not just data breach

---

## ✨ Features

### Modbus Attack Modules
| Module | Description |
|---|---|
| **Recon** | Device discovery, unit ID scan, coil read, holding register dump, device identification (FC43) |
| **Injection** | FC05/FC06/FC16 — write coils, single/multiple registers, target critical clinical registers |
| **Replay** | Capture live Modbus TCP frames + replay clinical attack frames |
| **DoS** | Connection flood, request flood, malformed function code attack |

### MQTT Attack Modules
| Module | Description |
|---|---|
| **Recon** | Anonymous access test, wildcard topic enumeration (`#`), clinical topic subscription, broker fingerprinting |
| **Injection** | Unauthorized publish to clinical topics, retained message injection, topic traversal |
| **Replay** | Capture broker messages and replay them (replay attack simulation) |
| **DoS** | Connection flood, message flood, large payload (64KB) flood, retained message abuse |

### Additional Features
- 🐳 **Docker lab** — simulated Modbus server + MQTT broker + clinical gateway
- 📊 **HTML report generation** — professional output for pentest engagements
- 🎨 **Colored CLI output** — clear severity-coded terminal feedback
- 🔧 **Modular architecture** — easy to extend with new modules

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Docker + Docker Compose (for lab environment)

### Install

```bash
git clone https://github.com/yourusername/GhostGateway.git
cd GhostGateway
pip install -r requirements.txt
```

---

## 🧪 Quick Start — Lab Environment

```bash
# Start the clinical IoT lab
cd labs/
docker-compose up -d

# Verify lab is running
docker-compose ps
```

---

## 💻 Usage

### Basic Commands

```bash
# Modbus Recon
python ghostgateway.py --protocol modbus --mode recon --target 127.0.0.1

# MQTT Recon
python ghostgateway.py --protocol mqtt --mode recon --broker 127.0.0.1

# Modbus Injection (write value 9999 to register 5 — Infusion Pump Rate)
python ghostgateway.py --protocol modbus --mode inject --target 127.0.0.1 --register 5 --value 9999

# MQTT Injection (inject alarm suppression command)
python ghostgateway.py --protocol mqtt --mode inject --broker 127.0.0.1 \
  --topic "alarm/suppress" --payload '{"suppress_all": true}'

# Modbus Replay
python ghostgateway.py --protocol modbus --mode replay --target 127.0.0.1

# MQTT Replay
python ghostgateway.py --protocol mqtt --mode replay --broker 127.0.0.1

# Modbus DoS (10 seconds, 10 threads)
python ghostgateway.py --protocol modbus --mode dos --target 127.0.0.1 \
  --duration 10 --threads 10

# MQTT DoS
python ghostgateway.py --protocol mqtt --mode dos --broker 127.0.0.1 \
  --duration 10 --threads 10

# Full Attack Suite (both protocols, all modules)
python ghostgateway.py --protocol all --mode full \
  --target 127.0.0.1 --broker 127.0.0.1 \
  --report --output reports/assessment.html

# Verbose mode
python ghostgateway.py --protocol modbus --mode recon --target 127.0.0.1 -v
```

---

## 📋 Clinical Register Mapping (Modbus)

GhostGateway uses medically-relevant register labels when targeting Modbus devices:

| Register | Clinical Meaning | Attack Impact |
|---|---|---|
| 0 | Patient Monitor Status | Device state manipulation |
| 1 | Alarm Threshold — Heart Rate | Silent threshold override |
| 2 | Alarm Threshold — SpO2 | Disable low oxygen alert |
| 3 | Alarm Threshold — Blood Pressure | Silent BP alarm bypass |
| 5 | Infusion Pump Rate | Drug delivery manipulation |
| 7 | Emergency Override Flag | Force emergency state |
| 9 | Gateway Connection Status | Disconnect simulation |

---

## 📁 Project Structure

```
GhostGateway/
├── ghostgateway.py          # Main CLI entry point
├── core/
│   ├── modbus/
│   │   ├── recon.py         # Modbus reconnaissance
│   │   ├── injection.py     # Modbus command injection
│   │   ├── replay.py        # Modbus replay attacks
│   │   └── dos.py           # Modbus denial of service
│   └── mqtt/
│       ├── recon.py         # MQTT broker recon
│       ├── injection.py     # MQTT unauthorized publish
│       ├── replay.py        # MQTT message replay
│       └── dos.py           # MQTT denial of service
├── utils/
│   ├── banner.py            # ASCII banner
│   ├── logger.py            # Colored output logger
│   └── report.py            # HTML report generator
├── labs/
│   ├── docker-compose.yml   # Clinical lab environment
│   ├── mosquitto.conf       # MQTT broker config
│   ├── clinical_simulator.py # Clinical gateway simulator
│   └── README.md
├── reports/                 # Generated HTML reports
├── requirements.txt
└── README.md
```

---

## 🗺️ Roadmap (v2.0)

- [ ] BLE medical device attack modules (glucose monitors, insulin pumps)
- [ ] HL7/FHIR protocol fuzzing module
- [ ] DICOM exposure scanner
- [ ] CVE database integration for known medical device vulnerabilities
- [ ] MITRE ATT&CK for ICS mapping in reports
- [ ] TLS/certificate weakness detection for MQTT
- [ ] Shodan integration for exposed clinical gateways

---

## 🔗 References & Research

- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [FDA Cybersecurity Guidance for Medical Devices](https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity)
- [NIST SP 800-82 — Guide to ICS Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [IEC 62443 — Industrial Cybersecurity Standards](https://www.iec.ch/isa99)
- [OWASP IoT Attack Surface Areas](https://owasp.org/www-project-internet-of-things/)

---

## 👤 Author

**Security Researcher — Medical Device & IoT Security**

- IoT/Medical Device Security Lead @ Healthcare Industry
- 8+ years in offensive security & penetration testing
- Specialization: Clinical IoT, Embedded Security, Cloud Security

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

**Remember: With great power comes great responsibility.**
Always obtain written authorization before testing any system.
